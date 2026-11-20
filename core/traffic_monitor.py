"""
Traffic Monitor Module
Real-time network traffic monitoring using psutil.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
import psutil

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


class InterfaceSpeedTracker:
    """
    Computes per-interface speeds from the delta between successive calls.

    Holding the previous sample means callers get a speed without having to
    sleep between two readings, which is what made the old implementation
    block the GUI thread.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._last_time: Optional[float] = None
        self._last_counters: Dict = {}

    def sample(self) -> List[Dict]:
        """Take a reading and return per-interface speeds in bytes/second."""
        now = time.time()
        counters = psutil.net_io_counters(pernic=True)

        with self._lock:
            last_time = self._last_time
            last_counters = self._last_counters
            self._last_time = now
            self._last_counters = counters

        # First call has nothing to diff against; report zeros.
        elapsed = (now - last_time) if last_time else 0.0

        result = []
        for name, io in counters.items():
            upload_speed = download_speed = 0.0
            previous = last_counters.get(name)
            if previous is not None and elapsed > 0:
                upload_speed = max(0.0, (io.bytes_sent - previous.bytes_sent) / elapsed)
                download_speed = max(0.0, (io.bytes_recv - previous.bytes_recv) / elapsed)

            result.append({
                "name": name,
                "upload_speed": upload_speed,
                "download_speed": download_speed,
                "total_speed": upload_speed + download_speed
            })

        return result


# Shared across the app so every caller contributes to the same delta series.
_interface_speeds = InterfaceSpeedTracker()


@dataclass
class TrafficSnapshot:
    """Snapshot of network traffic at a specific moment."""
    timestamp: float
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    upload_speed: float  # bytes per second
    download_speed: float  # bytes per second


class TrafficMonitor:
    """
    Real-time network traffic monitor.
    
    Tracks bandwidth usage across network interfaces by sampling
    network I/O counters at regular intervals and calculating
    the difference between samples to determine speed.
    """
    
    def __init__(self, interface: Optional[str] = None, sample_interval: float = 1.0):
        """
        Initialize the traffic monitor.
        
        Args:
            interface: Network interface name (None = all interfaces)
            sample_interval: Seconds between samples (default: 1.0)
        """
        self.interface = interface
        self.sample_interval = sample_interval
        self._is_monitoring = False
        self._last_snapshot: Optional[TrafficSnapshot] = None
        self._history: List[TrafficSnapshot] = []
        self._callbacks: List[Callable] = []
        self._max_history = 300  # Keep 5 minutes of data at 1s intervals
    
    def start(self):
        """Start monitoring network traffic."""
        if self._is_monitoring:
            logger.warning("Traffic monitoring already started")
            return
        
        self._is_monitoring = True
        self._history = []
        self._last_snapshot = None
        
        # Take initial snapshot
        self._last_snapshot = self._take_snapshot()
        
        logger.info(f"Traffic monitoring started for {self.interface or 'all interfaces'}")
        
        # Log to activity logger
        try:
            act_logger = get_activity_logger()
            act_logger.log_traffic_monitoring_started(self.interface or "all interfaces")
        except Exception as e:
            logger.debug(f"Non-fatal error: {e}")
    
    def stop(self):
        """Stop monitoring network traffic. A no-op if not running."""
        # cleanup() calls this unconditionally; see PerDeviceTrafficMonitor.stop.
        if not self._is_monitoring:
            return

        self._is_monitoring = False
        logger.info("Traffic monitoring stopped")
        
        # Log to activity logger
        try:
            act_logger = get_activity_logger()
            act_logger.log_traffic_monitoring_stopped()
        except Exception as e:
            logger.debug(f"Non-fatal error: {e}")
    
    def _take_snapshot(self) -> TrafficSnapshot:
        """
        Take a snapshot of current network I/O.
        
        Returns:
            TrafficSnapshot with current counters and calculated speeds
        """
        # Get network I/O counters
        if self.interface:
            # Get counters for specific interface
            counters = psutil.net_io_counters(pernic=True)
            if self.interface in counters:
                io = counters[self.interface]
            else:
                # Fallback to total
                io = psutil.net_io_counters()
        else:
            # Get total counters across all interfaces
            io = psutil.net_io_counters()
        
        current_time = time.time()
        
        # Calculate speeds if we have a previous snapshot
        upload_speed = 0.0
        download_speed = 0.0
        
        if self._last_snapshot:
            time_delta = current_time - self._last_snapshot.timestamp
            if time_delta > 0:
                upload_speed = (io.bytes_sent - self._last_snapshot.bytes_sent) / time_delta
                download_speed = (io.bytes_recv - self._last_snapshot.bytes_recv) / time_delta
        
        snapshot = TrafficSnapshot(
            timestamp=current_time,
            bytes_sent=io.bytes_sent,
            bytes_recv=io.bytes_recv,
            packets_sent=io.packets_sent,
            packets_recv=io.packets_recv,
            upload_speed=upload_speed,
            download_speed=download_speed
        )
        
        return snapshot
    
    def get_current_speed(self) -> Dict[str, float]:
        """
        Get current upload and download speeds.
        
        Returns:
            Dictionary with 'upload' and 'download' speeds in bytes/second
        """
        snapshot = self._take_snapshot()
        return {
            'upload': snapshot.upload_speed,
            'download': snapshot.download_speed
        }
    
    def get_history(self) -> List[TrafficSnapshot]:
        """
        Get traffic history.
        
        Returns:
            List of TrafficSnapshot objects
        """
        return self._history.copy()
    
    def get_statistics(self) -> Dict[str, float]:
        """
        Get cumulative traffic statistics.
        
        Returns:
            Dictionary with total bytes sent/received and current speeds
        """
        if not self._history:
            return {
                'total_sent': 0,
                'total_recv': 0,
                'current_upload': 0,
                'current_download': 0
            }
        
        latest = self._history[-1]
        return {
            'total_sent': latest.bytes_sent,
            'total_recv': latest.bytes_recv,
            'current_upload': latest.upload_speed,
            'current_download': latest.download_speed
        }
    
    def update(self) -> Optional[TrafficSnapshot]:
        """
        Update monitoring with new sample.
        
        Returns:
            New TrafficSnapshot if monitoring is active, None otherwise
        """
        if not self._is_monitoring:
            return None
        
        # Take new snapshot
        snapshot = self._take_snapshot()
        
        # Store in history
        self._history.append(snapshot)
        
        # Trim history if too long
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]
        
        # Update last snapshot
        self._last_snapshot = snapshot
        
        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(snapshot)
            except Exception as e:
                logger.error(f"Callback error: {e}")
        
        return snapshot
    
    def add_callback(self, callback: Callable):
        """Add a callback function to be called on each update."""
        self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable):
        """Remove a callback function."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    @staticmethod
    def format_speed(speed_bytes: float) -> str:
        """
        Format speed in human-readable format.
        
        Args:
            speed_bytes: Speed in bytes per second
            
        Returns:
            Formatted string (e.g., "1.23 MB/s")
        """
        if speed_bytes < 1024:
            return f"{speed_bytes:.2f} B/s"
        elif speed_bytes < 1024 * 1024:
            return f"{speed_bytes / 1024:.2f} KB/s"
        elif speed_bytes < 1024 * 1024 * 1024:
            return f"{speed_bytes / (1024 * 1024):.2f} MB/s"
        else:
            return f"{speed_bytes / (1024 * 1024 * 1024):.2f} GB/s"
    
    @staticmethod
    def format_bytes(total_bytes: int) -> str:
        """
        Format total bytes in human-readable format.
        
        Args:
            total_bytes: Total bytes transferred
            
        Returns:
            Formatted string (e.g., "1.23 GB")
        """
        if total_bytes < 1024:
            return f"{total_bytes} B"
        elif total_bytes < 1024 * 1024:
            return f"{total_bytes / 1024:.2f} KB"
        elif total_bytes < 1024 * 1024 * 1024:
            return f"{total_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{total_bytes / (1024 * 1024 * 1024):.2f} GB"
    
    @staticmethod
    def get_interfaces() -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List of interface names
        """
        counters = psutil.net_io_counters(pernic=True)
        return list(counters.keys())
    
    @staticmethod
    def get_interfaces_with_stats() -> List[Dict]:
        """
        Get all interfaces with their current traffic statistics.
        
        Returns:
            List of dictionaries with interface info:
            [{"name": "Wi-Fi", "bytes_sent": 1234, "bytes_recv": 5678, 
              "packets_sent": 100, "packets_recv": 200}, ...]
        """
        counters = psutil.net_io_counters(pernic=True)
        result = []
        
        for name, io in counters.items():
            result.append({
                "name": name,
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv
            })
        
        return result
    
    @staticmethod
    def get_interfaces_speeds() -> List[Dict]:
        """
        Get all interfaces with their current speeds.

        Speeds are derived from the delta against the previous call, so this
        never blocks. The old implementation slept 100ms between two samples,
        which stalled the GUI thread on every refresh.

        Returns:
            List of dictionaries with interface speeds:
            [{"name": "Wi-Fi", "upload_speed": 1234.5, "download_speed": 5678.9}, ...]
        """
        return _interface_speeds.sample()
    
    @property
    def is_monitoring(self) -> bool:
        """Check if monitoring is active."""
        return self._is_monitoring
