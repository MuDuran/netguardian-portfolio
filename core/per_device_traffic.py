"""
Per-Device Traffic Monitor Module
Tracks bandwidth usage per IP address using packet sniffing with scapy.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

# scapy only checks stop_filter when a packet arrives, so sniff in short
# bursts and re-check the stop flag between them.
SNIFF_BURST_SECONDS = 1.0

# Drop an IP from the table after this long with no traffic.
STALE_AFTER_SECONDS = 60

# Activity logger (imported here to avoid circular imports)
_activity_logger = None


def get_activity_logger():
    """Get the activity logger instance."""
    global _activity_logger
    if _activity_logger is None:
        from core.activity_logger import ActivityLogger
        _activity_logger = ActivityLogger.instance()
    return _activity_logger


@dataclass
class DeviceTraffic:
    """Traffic data for a single device."""
    ip: str
    hostname: str
    device_name: str
    bytes_sent: int  # Upload (from this device)
    bytes_recv: int  # Download (to this device)
    upload_speed: float  # bytes per second
    download_speed: float  # bytes per second
    last_seen: float  # timestamp


class PerDeviceTrafficMonitor:
    """
    Monitors traffic per IP address using packet sniffing.
    
    Captures packets on the network and aggregates bytes sent/received
    per IP address to show which devices are using bandwidth.
    """
    
    def __init__(self, interface: Optional[str] = None, sample_interval: float = 1.0):
        """
        Initialize the per-device traffic monitor.
        
        Args:
            interface: Network interface to sniff on (None = default)
            sample_interval: Seconds between speed calculations (default: 1.0)
        """
        self.interface = interface
        self.sample_interval = sample_interval
        self._is_monitoring = False
        self._sniffer_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Traffic tracking: ip -> {bytes_sent, bytes_recv, last_seen}
        self._current_period: Dict[str, Dict] = {}
        self._last_period: Dict[str, Dict] = {}
        
        # Device info cache: ip -> {hostname, device_name}
        self._device_info: Dict[str, Dict] = {}
        
        # Callbacks
        self._callbacks: List[Callable] = []
        
        # Local IP (to determine direction)
        self._local_ip: Optional[str] = None
    
    def _detect_local_ip(self) -> Optional[str]:
        """Detect the local machine's IP address."""
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for iface_name, iface_addrs in addrs.items():
                for addr in iface_addrs:
                    if addr.family.name == 'AF_INET':
                        ip = addr.address
                        if not ip.startswith('127.') and not ip.startswith('169.254.'):
                            return ip
        except Exception:
            pass
        return None
    
    def set_device_info(self, ip: str, hostname: str, device_name: str):
        """Set device information for an IP address."""
        self._device_info[ip] = {
            "hostname": hostname,
            "device_name": device_name
        }
    
    def set_device_info_batch(self, devices: List[Dict]):
        """Set device information for multiple devices."""
        for device in devices:
            ip = device.get("ip", "")
            if ip:
                self._device_info[ip] = {
                    "hostname": device.get("hostname", "Unknown"),
                    "device_name": device.get("device", "Unknown")
                }
    
    def start(self):
        """Start monitoring per-device traffic."""
        if self._is_monitoring:
            logger.warning("Per-device monitoring already started")
            return
        
        self._is_monitoring = True
        self._current_period = {}
        self._last_period = {}
        self._local_ip = self._detect_local_ip()
        
        # Start sniffer thread
        self._sniffer_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="PerDeviceTrafficSniffer"
        )
        self._sniffer_thread.start()
        
        logger.info(f"Per-device traffic monitoring started on {self.interface or 'default interface'}")
        
        # Log activity
        try:
            act_logger = get_activity_logger()
            act_logger.log_traffic_monitoring_started(f"per-device on {self.interface or 'default'}")
        except Exception as e:
            logger.debug(f"Non-fatal error: {e}")
    
    def stop(self):
        """Stop monitoring per-device traffic. A no-op if not running."""
        # cleanup() calls this unconditionally. Without the guard it logged a
        # "stopped" line for a monitor that was never started, which makes the
        # logs read as though sniffing had been active.
        if not self._is_monitoring:
            return

        self._is_monitoring = False

        # Wait for sniffer thread to finish
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=SNIFF_BURST_SECONDS * 3)

        logger.info("Per-device traffic monitoring stopped")

        # Log activity
        try:
            act_logger = get_activity_logger()
            act_logger.log_traffic_monitoring_stopped()
        except Exception as e:
            logger.debug(f"Non-fatal error: {e}")
    
    def _process_packet(self, packet):
        """
        Account for one captured packet.

        Returns None deliberately. scapy prints whatever the prn callback
        returns, so returning True made it write "True" to stdout for every
        packet -- thousands of blocking writes a minute, each holding the GIL.
        Stopping is handled by stop_filter, not by this return value.
        """
        if not self._is_monitoring:
            return

        from scapy.all import IP
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)

        with self._lock:
            # Direction is relative to this machine.
            if self._local_ip:
                if src_ip == self._local_ip:
                    self._track_bytes(src_ip, bytes_sent=packet_size, bytes_recv=0)
                elif dst_ip == self._local_ip:
                    self._track_bytes(dst_ip, bytes_sent=0, bytes_recv=packet_size)
                # Traffic between two other devices is not ours to attribute.
            else:
                # Local IP unknown: count both ends.
                self._track_bytes(src_ip, bytes_sent=packet_size, bytes_recv=0)
                self._track_bytes(dst_ip, bytes_sent=0, bytes_recv=packet_size)

    def _sniff_loop(self):
        """Sniff packets continuously until stopped."""
        try:
            from scapy.all import sniff

            # Sniff in short bursts rather than one unbounded call. scapy only
            # evaluates stop_filter when a packet arrives, so on a quiet
            # interface an unbounded sniff() would ignore stop() until the next
            # packet -- which is what made stop() hang for its full timeout.
            while self._is_monitoring:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda _: not self._is_monitoring,
                    timeout=SNIFF_BURST_SECONDS
                )

        except ImportError:
            logger.error("scapy is required for per-device traffic monitoring")
            self._is_monitoring = False
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            self._is_monitoring = False

    def _track_bytes(self, ip: str, bytes_sent: int, bytes_recv: int):
        """Track bytes for a specific IP address."""
        if ip not in self._current_period:
            self._current_period[ip] = {
                "bytes_sent": 0,
                "bytes_recv": 0,
                "last_seen": time.time()
            }
        
        self._current_period[ip]["bytes_sent"] += bytes_sent
        self._current_period[ip]["bytes_recv"] += bytes_recv
        self._current_period[ip]["last_seen"] = time.time()
    
    def update(self) -> List[DeviceTraffic]:
        """
        Update speed calculations and return current traffic data.
        Should be called periodically (e.g., every second) from the UI timer.
        
        Returns:
            List of DeviceTraffic objects sorted by total traffic (highest first)
        """
        current_time = time.time()
        
        with self._lock:
            # Calculate speeds by comparing current period to last period
            result = []
            
            for ip, current in self._current_period.items():
                # Get previous data for this IP
                prev = self._last_period.get(ip, {"bytes_sent": 0, "bytes_recv": 0})
                
                # Calculate speed (bytes per second)
                upload_speed = (current["bytes_sent"] - prev["bytes_sent"]) / self.sample_interval
                download_speed = (current["bytes_recv"] - prev["bytes_recv"]) / self.sample_interval
                
                # Get device info
                info = self._device_info.get(ip, {})
                
                traffic = DeviceTraffic(
                    ip=ip,
                    hostname=info.get("hostname", "Unknown"),
                    device_name=info.get("device_name", "Unknown"),
                    bytes_sent=current["bytes_sent"],
                    bytes_recv=current["bytes_recv"],
                    upload_speed=max(0, upload_speed),
                    download_speed=max(0, download_speed),
                    last_seen=current["last_seen"]
                )
                result.append(traffic)
            
            # Save current as last period
            self._last_period = {}
            for ip, data in self._current_period.items():
                self._last_period[ip] = {
                    "bytes_sent": data["bytes_sent"],
                    "bytes_recv": data["bytes_recv"]
                }
            
            # Drop IPs that have gone quiet. Both maps must be cleared: leaving
            # a stale _last_period entry behind meant a returning device was
            # diffed against an old, larger total and reported no traffic.
            stale_ips = [
                ip for ip, data in self._current_period.items()
                if current_time - data["last_seen"] > STALE_AFTER_SECONDS
            ]
            for ip in stale_ips:
                self._current_period.pop(ip, None)
                self._last_period.pop(ip, None)
        
        # Sort by total traffic (highest first)
        result.sort(key=lambda t: t.bytes_sent + t.bytes_recv, reverse=True)
        
        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Callback error: {e}")
        
        return result
    
    def add_callback(self, callback: Callable):
        """Add a callback function to be called on each update."""
        self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable):
        """Remove a callback function."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    @property
    def is_monitoring(self) -> bool:
        """Check if monitoring is active."""
        return self._is_monitoring
    
    @staticmethod
    def format_speed(speed_bytes: float) -> str:
        """Format speed in human-readable format."""
        if speed_bytes < 1024:
            return f"{speed_bytes:.0f} B/s"
        elif speed_bytes < 1024 * 1024:
            return f"{speed_bytes / 1024:.1f} KB/s"
        elif speed_bytes < 1024 * 1024 * 1024:
            return f"{speed_bytes / (1024 * 1024):.2f} MB/s"
        else:
            return f"{speed_bytes / (1024 * 1024 * 1024):.2f} GB/s"
    
    @staticmethod
    def format_bytes(total_bytes: int) -> str:
        """Format total bytes in human-readable format."""
        if total_bytes < 1024:
            return f"{total_bytes} B"
        elif total_bytes < 1024 * 1024:
            return f"{total_bytes / 1024:.2f} KB"
        elif total_bytes < 1024 * 1024 * 1024:
            return f"{total_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{total_bytes / (1024 * 1024 * 1024):.2f} GB"
