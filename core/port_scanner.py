"""
Port Scanner Module
Network port scanning using python-nmap for service discovery.
"""

import ipaddress
import logging
import os
import re
import sys
import time
import nmap
import psutil
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from utils.timing import timed

logger = logging.getLogger(__name__)

# Targets and port specs are typed by the user and end up on an nmap command
# line, so accept only the shapes nmap actually needs.
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                         r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
PORT_SPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

# nmap's top ~100 TCP ports. The previous "quick scan" list held 20 despite the
# docstring and README both claiming 100.
COMMON_PORTS = (
    "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,"
    "144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,"
    "646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,"
    "1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,"
    "5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,"
    "8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,"
    "49154,49155,49156,49157"
)


class InvalidScanTarget(ValueError):
    """Raised when a scan target or port specification is not acceptable."""


def validate_target(target: str) -> str:
    """
    Validate a scan target.

    Accepts an IPv4/IPv6 address, a CIDR network, or a hostname. Anything else
    is rejected rather than passed through to the nmap command line.

    Args:
        target: The user-supplied target

    Returns:
        The cleaned target

    Raises:
        InvalidScanTarget: If the target is not a valid host or network
    """
    cleaned = (target or "").strip()
    if not cleaned:
        raise InvalidScanTarget("Target is required")

    for parse in (ipaddress.ip_address, ipaddress.ip_network):
        try:
            parse(cleaned, *([] if parse is ipaddress.ip_address else [False]))
            return cleaned
        except ValueError:
            continue

    if HOSTNAME_RE.match(cleaned):
        return cleaned

    raise InvalidScanTarget(
        f"'{cleaned}' is not a valid IP address, network, or hostname"
    )


def validate_ports(ports: str) -> str:
    """
    Validate a port specification such as "80", "80,443" or "1-1024".

    Args:
        ports: The user-supplied port spec

    Returns:
        The cleaned port spec

    Raises:
        InvalidScanTarget: If the spec is malformed or out of range
    """
    cleaned = (ports or "").strip().replace(" ", "")
    if not cleaned:
        raise InvalidScanTarget("Port range is required")

    if not PORT_SPEC_RE.match(cleaned):
        raise InvalidScanTarget(
            f"'{ports}' is not a valid port specification "
            "(use forms like 80, 80,443 or 1-1024)"
        )

    for part in cleaned.split(","):
        bounds = [int(p) for p in part.split("-")]
        for value in bounds:
            if not 1 <= value <= 65535:
                raise InvalidScanTarget(f"Port {value} is outside 1-65535")
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise InvalidScanTarget(f"Port range '{part}' is backwards")

    return cleaned

# Activity logger (imported here to avoid circular imports)
_activity_logger = None


def get_activity_logger():
    """Get the activity logger instance."""
    global _activity_logger
    if _activity_logger is None:
        from core.activity_logger import ActivityLogger
        _activity_logger = ActivityLogger.instance()
    return _activity_logger


def ensure_nmap_in_path():
    """Ensure nmap is in the system PATH."""
    # Common nmap installation paths on Windows
    nmap_paths = [
        r"C:\Program Files (x86)\Nmap",
        r"C:\Program Files\Nmap",
        r"C:\Nmap",
    ]
    
    # Get current PATH
    current_path = os.environ.get('PATH', '')
    
    # Check if nmap is already in PATH
    for path in nmap_paths:
        if path.lower() in current_path.lower():
            return True
    
    # Try to add nmap to PATH
    for path in nmap_paths:
        if os.path.exists(path):
            os.environ['PATH'] = path + ";" + current_path
            logger.info(f"Added nmap to PATH: {path}")
            return True
    
    logger.warning("Nmap not found in common installation paths")
    return False


@dataclass
class PortInfo:
    """Information about a single port."""
    port: int
    state: str  # open, closed, filtered
    protocol: str  # tcp, udp
    service: str  # http, ssh, ftp, etc.
    version: str  # Service version if detected
    banner: str  # Service banner if captured
    process_name: str = ""  # Local process using this port (if known)
    pid: int = 0  # Process ID (if known)


@dataclass
class ScanResult:
    """Complete scan result for a host."""
    ip: str
    hostname: str
    state: str  # up, down
    ports: List[PortInfo]
    scan_time: datetime
    scan_duration: float  # seconds


class PortScanner:
    """
    Network port scanner using nmap.
    
    Scans target hosts for open ports and identifies running services.
    Uses nmap's service detection capabilities for accurate identification.
    """
    
    def __init__(self):
        """Initialize the port scanner."""
        # Ensure nmap is in PATH before initializing
        ensure_nmap_in_path()
        self._scanner = nmap.PortScanner()
        self._is_scanning = False
        self._callbacks: List[Callable] = []
    
    @staticmethod
    def _is_local_target(target: str) -> bool:
        """
        Whether the target refers to this machine.

        Process names come from our own process table, so attributing them to a
        remote host's ports would be misleading.
        """
        if target.lower() in ("localhost", "127.0.0.1", "::1"):
            return True
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            return False
        if address.is_loopback:
            return True

        try:
            local_addresses = {
                addr.address
                for addrs in psutil.net_if_addrs().values()
                for addr in addrs
            }
        except Exception as e:
            logger.debug(f"Could not enumerate local addresses: {e}")
            return False
        return target in local_addresses

    @staticmethod
    def get_local_process_map() -> Dict[tuple, tuple]:
        """
        Build a mapping of (port, protocol) -> (pid, process_name)
        for all local listening connections.
        
        Returns:
            Dictionary mapping (port, protocol_str) -> (pid, process_name)
        """
        process_map = {}
        # One psutil.Process lookup per PID, not per connection. A busy machine
        # has many connections sharing a handful of processes.
        name_by_pid = {}

        try:
            for conn in psutil.net_connections(kind="inet"):
                if not (conn.laddr and conn.pid and conn.pid > 0):
                    continue

                port = conn.laddr.port
                # SOCK_STREAM -> tcp, SOCK_DGRAM -> udp
                protocol = conn.type.name.lower()

                key = (port, protocol)
                if key in process_map:
                    continue  # First match wins

                if conn.pid not in name_by_pid:
                    try:
                        name_by_pid[conn.pid] = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name_by_pid[conn.pid] = f"PID:{conn.pid}"

                process_map[key] = (conn.pid, name_by_pid[conn.pid])

        except (psutil.AccessDenied, OSError) as e:
            logger.debug(f"Could not build process map: {e}")

        return process_map
    
    @timed("PortScanner.scan")
    def scan(
        self, 
        target: str, 
        ports: str = "1-1024",
        scan_type: str = "quick",
        service_detection: bool = True
    ) -> Optional[ScanResult]:
        """
        Scan a target for open ports.
        
        Args:
            target: IP address or hostname to scan
            ports: Port range to scan (e.g., "1-1024", "80,443", "22-1000")
            scan_type: Type of scan ("quick", "full", "stealth")
            service_detection: Enable service version detection
            
        Returns:
            ScanResult with discovered ports, or None if scan fails
        """
        if self._is_scanning:
            logger.warning("Scan already in progress")
            return None

        # Reject anything that is not a plain host/network and port spec before
        # it reaches the nmap command line.
        target = validate_target(target)
        ports = validate_ports(ports)

        self._is_scanning = True
        started_at = time.perf_counter()

        try:
            # Build nmap arguments based on scan type
            arguments = self._build_scan_arguments(scan_type, service_detection)

            logger.info(f"Starting {scan_type} scan on {target} (ports: {ports})")

            # Log scan start
            try:
                act_logger = get_activity_logger()
                act_logger.log_scan_started(target, scan_type)
            except Exception as e:
                logger.debug(f"Non-fatal error: {e}")
            
            # Perform the scan
            # Note: nmap requires keyword arguments, not positional
            self._scanner.scan(hosts=target, ports=ports, arguments=arguments)
            
            # Check if host was found
            if target not in self._scanner.all_hosts():
                logger.warning(f"Host {target} not found or down")
                return ScanResult(
                    ip=target,
                    hostname="",
                    state="down",
                    ports=[],
                    scan_time=datetime.now(),
                    scan_duration=0
                )
            
            # Parse scan results
            host = self._scanner[target]
            
            # Get hostname
            hostname = ""
            if 'hostnames' in host and host['hostnames']:
                hostname = host['hostnames'][0].get('name', '')
            
            # Get ports
            ports_list = []
            if 'tcp' in host:
                for port_num, port_data in host['tcp'].items():
                    port_info = PortInfo(
                        port=port_num,
                        state=port_data.get('state', 'unknown'),
                        protocol='tcp',
                        service=port_data.get('name', 'unknown'),
                        version=port_data.get('version', ''),
                        banner=port_data.get('product', '')
                    )
                    ports_list.append(port_info)
            
            if 'udp' in host:
                for port_num, port_data in host['udp'].items():
                    port_info = PortInfo(
                        port=port_num,
                        state=port_data.get('state', 'unknown'),
                        protocol='udp',
                        service=port_data.get('name', 'unknown'),
                        version=port_data.get('version', ''),
                        banner=port_data.get('product', '')
                    )
                    ports_list.append(port_info)
            
            # Sort by port number
            ports_list.sort(key=lambda p: p.port)
            
            # Enrich with local process information. Only meaningful when the
            # target is this machine -- a PID here belongs to our process table,
            # not the remote host's.
            if self._is_local_target(target):
                process_map = self.get_local_process_map()
                for port_info in ports_list:
                    key = (port_info.port, port_info.protocol)
                    if key in process_map:
                        port_info.pid, port_info.process_name = process_map[key]

            scan_time = datetime.now()
            scan_duration = time.perf_counter() - started_at

            result = ScanResult(
                ip=target,
                hostname=hostname,
                state="up",
                ports=ports_list,
                scan_time=scan_time,
                scan_duration=scan_duration
            )
            
            logger.info(f"Scan complete. Found {len(ports_list)} ports on {target}")
            
            # Log scan completion
            try:
                act_logger = get_activity_logger()
                act_logger.log_scan_completed(target, len(ports_list))
            except Exception as e:
                logger.debug(f"Non-fatal error: {e}")
            
            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
            
            return result
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap error: {e}")
            raise
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
        finally:
            self._is_scanning = False
    
    def quick_scan(self, target: str) -> Optional[ScanResult]:
        """
        Perform a quick scan of common ports.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            ScanResult with common open ports
        """
        return self.scan(target, COMMON_PORTS, scan_type="quick", service_detection=True)
    
    def full_scan(self, target: str) -> Optional[ScanResult]:
        """
        Perform a full scan of all 65535 ports.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            ScanResult with all open ports
        """
        return self.scan(target, "1-65535", scan_type="full", service_detection=True)
    
    def _build_scan_arguments(self, scan_type: str, service_detection: bool) -> str:
        """
        Build nmap command arguments.
        
        Args:
            scan_type: Type of scan
            service_detection: Enable service detection
            
        Returns:
            Nmap arguments string
        """
        args = []

        # Scan type
        if scan_type == "quick":
            args.append("-T4")  # Fast timing
        elif scan_type == "full":
            args.append("-T3")  # Normal timing
        elif scan_type == "stealth":
            args.append("-sS")  # SYN stealth scan
            args.append("-T2")  # Sneaky timing

        # Service detection. This is the slowest phase of a scan by a wide
        # margin, so it is opt-in from the UI rather than always on.
        if service_detection:
            args.append("-sV")
            args.append("--version-intensity=2")  # Probe less exhaustively

        # Don't resolve DNS (faster)
        args.append("-n")

        # NOTE: no -oN here. python-nmap already runs nmap with "-oX -" and
        # parses that XML; adding a second output-to-stdout flag interleaves
        # plain text into the XML stream.

        return " ".join(args)
    
    def scan_network_range(
        self, 
        network: str, 
        ports: str = "22,80,443",
        max_hosts: int = 10
    ) -> List[ScanResult]:
        """
        Scan a network range for hosts with specific ports open.
        
        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            ports: Ports to check
            max_hosts: Maximum hosts to scan
            
        Returns:
            List of ScanResult for hosts with open ports
        """
        results = []
        
        try:
            # Scan the network
            self._scanner.scan(network, ports, arguments="-n -T4")
            
            # Process results
            for host in self._scanner.all_hosts()[:max_hosts]:
                if self._scanner[host].state() == 'up':
                    # Quick scan this host
                    result = self.quick_scan(host)
                    if result and result.ports:
                        results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            return []
    
    def add_callback(self, callback: Callable):
        """Add a callback function to be called when scan completes."""
        self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable):
        """Remove a callback function."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    @property
    def is_scanning(self) -> bool:
        """Check if a scan is currently in progress."""
        return self._is_scanning
    
    @staticmethod
    def get_common_ports() -> Dict[str, int]:
        """
        Get dictionary of common ports and their services.
        
        Returns:
            Dictionary mapping service names to port numbers
        """
        return {
            "FTP": 21,
            "SSH": 22,
            "Telnet": 23,
            "SMTP": 25,
            "DNS": 53,
            "HTTP": 80,
            "POP3": 110,
            "RPC": 111,
            "NetBIOS": 139,
            "IMAP": 143,
            "HTTPS": 443,
            "SMB": 445,
            "IMAPS": 993,
            "POP3S": 995,
            "PPTP": 1723,
            "RDP": 3389,
            "VNC": 5900,
            "HTTP-Alt": 8080,
            "HTTPS-Alt": 8443
        }
