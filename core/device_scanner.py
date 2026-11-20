"""
Device Scanner Module
Implements ARP scanning for network device discovery using scapy.
"""

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, wait
from typing import List, Dict, Optional
from scapy.all import ARP, Ether, srp, conf
from datetime import datetime

from core.oui import lookup_mac_vendor
from utils.timing import Stopwatch, timed

# Reverse DNS is the slowest part of a scan and it is almost entirely waiting,
# so resolve every responder concurrently with a short per-lookup timeout.
HOSTNAME_WORKERS = 32
# Overall deadline for the whole batch of lookups, in seconds.
HOSTNAME_BATCH_TIMEOUT = 2.5

# Configure logging
logger = logging.getLogger(__name__)

# Activity logger (imported here to avoid circular imports)
_activity_logger = None


def get_activity_logger():
    """Get the activity logger instance."""
    global _activity_logger
    if _activity_logger is None:
        from core.activity_logger import ActivityLogger
        _activity_logger = ActivityLogger.instance()
    return _activity_logger


# MAC OUI lookup lives in core/oui.py, backed by the IEEE registry when it has
# been fetched (see scripts/update_oui.py) and a curated table otherwise.
# Re-exported here so existing imports of lookup_mac_vendor keep working.


class DeviceScanner:
    """
    ARP-based network device scanner.
    
    Uses Address Resolution Protocol (ARP) to discover devices on the local network.
    ARP works by broadcasting a request asking "Who has this IP address?" and
    listening for responses from devices that recognize their IP.
    """
    
    def __init__(self, timeout: int = 3, interface: Optional[str] = None):
        """
        Initialize the device scanner.
        
        Args:
            timeout: How long to wait for responses (seconds)
            interface: Network interface to use (None = default)
        """
        self.timeout = timeout
        self.interface = interface
        self._is_scanning = False
        # ip -> hostname, so repeat scans skip resolution entirely
        self._hostname_cache: Dict[str, str] = {}

    @timed("DeviceScanner.scan_network")
    def scan_network(self, ip_range: str = "192.168.1.0/24") -> List[Dict]:
        """
        Perform ARP scan on the specified IP range.
        
        Args:
            ip_range: CIDR notation of network to scan (e.g., "192.168.1.0/24")
            
        Returns:
            List of dictionaries containing device information:
            [
                {
                    "ip": "192.168.1.1",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "hostname": "Router",
                    "status": "Online",
                    "timestamp": "2026-08-21 12:00:00"
                },
                ...
            ]
        """
        if self._is_scanning:
            logger.warning("Scan already in progress")
            return []
        
        self._is_scanning = True
        devices = []
        watch = Stopwatch("DeviceScanner.scan_network.phases")

        try:
            logger.info(f"Starting ARP scan on {ip_range}")
            
            # Create ARP request packet
            # ARP asks: "Who has IP X.X.X.X? Tell me (my MAC)"
            arp_request = ARP(pdst=ip_range)
            
            # Ethernet frame wraps the ARP request
            # dst="ff:ff:ff:ff:ff:ff" means broadcast to all devices
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            
            # Combine into complete packet
            packet = broadcast / arp_request
            
            # Send packet and receive responses
            # srp = Send and Receive at Layer 2 (Ethernet)
            # timeout = how long to listen for responses
            # verbose = False prevents printing to console
            answered, unanswered = srp(
                packet, 
                timeout=self.timeout, 
                verbose=False,
                iface=self.interface
            )
            
            watch.mark("arp")

            # Collect the responders first, then resolve every hostname at once.
            # Doing it inline made each unresolvable device cost a full DNS
            # timeout, serially.
            responders = [
                (received.psrc, received.hwsrc) for _sent, received in answered
            ]
            hostnames = self._resolve_hostnames([ip for ip, _mac in responders])
            watch.mark("dns")

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for ip, mac_addr in responders:
                device = {
                    "ip": ip,                                # Source IP (who responded)
                    "mac": mac_addr,                          # Source MAC address
                    "device": lookup_mac_vendor(mac_addr),    # Device model from MAC OUI
                    "hostname": hostnames.get(ip, "Unknown"),
                    "status": "Online",
                    "timestamp": timestamp
                }
                devices.append(device)
                logger.debug(f"Found device: {device['ip']} ({device['mac']}) - {device['device']}")

            # One transaction for the whole batch instead of one per device
            try:
                get_activity_logger().log_devices_discovered(devices)
            except Exception as e:
                logger.debug(f"Activity logging failed: {e}")

            logger.info(f"Scan complete. Found {len(devices)} devices")
            
        except PermissionError:
            logger.error("Permission denied. Run as administrator for ARP scanning.")
            raise
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
        finally:
            self._is_scanning = False
            watch.done()

        return devices

    def _get_hostname(self, ip: str) -> str:
        """
        Attempt to resolve hostname for an IP address.

        Args:
            ip: IP address to resolve

        Returns:
            Hostname string, or "Unknown" if resolution fails
        """
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = "Unknown"

        self._hostname_cache[ip] = hostname
        return hostname

    def _resolve_hostnames(self, ips: List[str]) -> Dict[str, str]:
        """
        Resolve many IPs to hostnames concurrently.

        Args:
            ips: IP addresses to resolve

        Returns:
            Mapping of ip -> hostname ("Unknown" when resolution fails)
        """
        if not ips:
            return {}

        results = {ip: "Unknown" for ip in ips}

        # gethostbyaddr ignores socket.setdefaulttimeout on Windows, so bound
        # the batch as a whole instead: whatever has not resolved by the
        # deadline stays "Unknown". Stragglers finish in the background and
        # populate the cache for the next scan.
        workers = min(HOSTNAME_WORKERS, len(ips))
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dns")
        try:
            futures = {pool.submit(self._get_hostname, ip): ip for ip in ips}
            done, not_done = wait(futures, timeout=HOSTNAME_BATCH_TIMEOUT)

            for future in done:
                try:
                    results[futures[future]] = future.result()
                except Exception as e:
                    logger.debug(f"Hostname lookup failed for {futures[future]}: {e}")

            if not_done:
                logger.debug(f"{len(not_done)} hostname lookup(s) exceeded the deadline")
        finally:
            pool.shutdown(wait=False)

        return results


    def get_local_ip_range(self) -> str:
        """
        Detect the local network IP range automatically.
        
        Returns:
            CIDR notation of local network (e.g., "192.168.1.0/24")
        """
        try:
            import psutil
            # Get network interfaces
            addrs = psutil.net_if_addrs()
            
            for iface_name, iface_addrs in addrs.items():
                for addr in iface_addrs:
                    if addr.family.name == 'AF_INET':  # IPv4
                        ip = addr.address
                        netmask = addr.netmask
                        
                        # Skip loopback and link-local
                        if ip.startswith('127.') or ip.startswith('169.254.'):
                            continue
                        
                        # Calculate network range
                        if netmask:
                            network = self._calculate_network(ip, netmask)
                            logger.info(f"Detected local network: {network}")
                            return network
            
            # Default fallback
            logger.warning("Could not detect local network, using default")
            return "192.168.1.0/24"
            
        except Exception as e:
            logger.warning(f"Failed to detect network: {e}")
            return "192.168.1.0/24"
    
    def _calculate_network(self, ip: str, netmask: str) -> str:
        """
        Calculate network address from IP and netmask.
        
        Args:
            ip: IP address
            netmask: Subnet mask
            
        Returns:
            Network address in CIDR notation
        """
        try:
            # strict=False lets us pass a host address rather than the network
            # address and get the containing network back.
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        except ValueError as e:
            logger.warning(f"Could not parse {ip}/{netmask}: {e}")
            return "192.168.1.0/24"

        # An ARP sweep of anything larger than a /16 is not practical.
        if network.prefixlen < 16:
            logger.warning(f"Network {network} is too large to sweep, narrowing to /24")
            return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))

        return str(network)
    
    @property
    def is_scanning(self) -> bool:
        """Check if a scan is currently in progress."""
        return self._is_scanning
