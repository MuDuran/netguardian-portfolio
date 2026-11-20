"""
Device Discovery Tab
UI component for scanning and displaying network devices.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar
)
from PySide6.QtCore import Qt, Signal, QThread
import logging
from concurrent.futures import ThreadPoolExecutor
from core.device_scanner import DeviceScanner, lookup_mac_vendor
from config import MODEM_DEFAULT_IP, MODEM_DEFAULT_USERNAME, MODEM_DEFAULT_PASSWORD

logger = logging.getLogger(__name__)


class DeviceDiscoveryWorker(QThread):
    """Background worker for ARP scanning with modem data merge."""
    
    device_found = Signal(dict)
    scan_complete = Signal(list)
    error_occurred = Signal(str)
    status_update = Signal(str)
    
    def __init__(self, ip_range: str = None, scanner=None, modem_scraper=None):
        super().__init__()
        self._ip_range = ip_range
        # Reused across scans so the hostname cache and the modem login
        # survive from one scan to the next.
        self._scanner = scanner or DeviceScanner(timeout=3)
        self._modem_scraper = modem_scraper
    
    def run(self):
        """Perform ARP scan and merge with modem device data."""
        try:
            # The modem query and the ARP sweep are independent, and the modem
            # is by far the slower of the two (this model takes ~18s to render
            # its status page). Run them concurrently instead of making the
            # scan wait for the modem.
            self.status_update.emit("Querying modem and scanning network...")

            with ThreadPoolExecutor(max_workers=2) as pool:
                modem_future = pool.submit(self._get_modem_devices)

                if self._ip_range:
                    ip_range = self._ip_range
                else:
                    ip_range = self._scanner.get_local_ip_range()

                arp_future = pool.submit(self._scanner.scan_network, ip_range)

                devices = arp_future.result()
                self.status_update.emit("Waiting for modem...")
                modem_devices = modem_future.result()


            # Step 3: Merge modem data with ARP results
            self.status_update.emit("Merging device data...")
            merged_devices = self._merge_device_data(devices, modem_devices)
            
            # Emit each device
            for device in merged_devices:
                self.device_found.emit(device)
            
            self.scan_complete.emit(merged_devices)
            
        except PermissionError:
            self.error_occurred.emit("Permission denied. Run as administrator for ARP scanning.")
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def _get_modem_devices(self) -> dict:
        """
        Get connected devices from modem.
        Returns dict keyed by IP address.
        """
        modem_devices = {}
        try:
            if self._modem_scraper is None:
                if not MODEM_DEFAULT_IP:
                    return modem_devices
                from core.modem_scraper import ModemScraper
                self._modem_scraper = ModemScraper(
                    modem_ip=MODEM_DEFAULT_IP,
                    username=MODEM_DEFAULT_USERNAME,
                    password=MODEM_DEFAULT_PASSWORD
                )
            status = self._modem_scraper.get_status()
            
            if not status.error:
                for device in status.connected_devices:
                    modem_devices[device.ip_address] = {
                        "device": device.name,
                        "connection_type": device.connection_type,
                        "interface": device.interface,
                        "mac": device.mac_address
                    }
                
                # Also add LAN port devices
                for port in status.lan_ports:
                    if port.device_name and port.status == "Connected":
                        # LAN devices might already be in the list
                        for ip, info in modem_devices.items():
                            if info["device"] == port.device_name:
                                info["connection_type"] = "LAN"
                                info["interface"] = port.port_name
        except Exception as e:
            # The modem is optional enrichment; an ARP-only scan is still useful.
            logger.debug(f"Modem query failed, continuing with ARP only: {e}")

        return modem_devices
    
    def _merge_device_data(self, arp_devices: list, modem_devices: dict) -> list:
        """
        Merge ARP scan results with modem device data.
        Priority: modem data for connection type, ARP for IP/MAC.
        """
        merged = []
        seen_ips = set()
        
        # First: add all modem devices (they have connection types)
        for ip, info in modem_devices.items():
            device = {
                "ip": ip,
                "mac": info.get("mac", ""),
                "device": info.get("device", "Unknown"),
                "hostname": info.get("device", "Unknown"),
                "connection": f'{info.get("connection_type", "Unknown")} ({info.get("interface", "")})',
                "status": "Online"
            }
            merged.append(device)
            seen_ips.add(ip)
        
        # Then: add ARP devices not already in modem list
        for arp_device in arp_devices:
            ip = arp_device.get("ip", "")
            if ip not in seen_ips:
                # Try to infer device type from hostname
                hostname = arp_device.get("hostname", "Unknown")
                device_name = arp_device.get("device", "Unknown")
                
                # If OUI lookup failed, try hostname-based detection
                if device_name == "Unknown" and hostname != "Unknown":
                    device_name = self._guess_device_from_hostname(hostname)
                
                device = {
                    "ip": ip,
                    "mac": arp_device.get("mac", ""),
                    "device": device_name,
                    "hostname": hostname,
                    "connection": "Unknown",
                    "status": arp_device.get("status", "Online")
                }
                merged.append(device)
                seen_ips.add(ip)
        
        return merged
    
    def _guess_device_from_hostname(self, hostname: str) -> str:
        """
        Try to guess device type from hostname patterns.
        """
        hostname_lower = hostname.lower()
        
        # Common hostname patterns
        if "galaxy" in hostname_lower:
            return "Samsung " + hostname.split("-")[0] if "-" in hostname else "Samsung"
        elif "iphone" in hostname_lower:
            return "Apple iPhone"
        elif "ipad" in hostname_lower:
            return "Apple iPad"
        elif "macbook" in hostname_lower or "mac" in hostname_lower:
            return "Apple Mac"
        elif "redmi" in hostname_lower:
            return "Xiaomi Redmi"
        elif "poco" in hostname_lower:
            return "Xiaomi POCO"
        elif "mi-" in hostname_lower or "xiaomi" in hostname_lower:
            return "Xiaomi"
        elif "honor" in hostname_lower:
            return "Honor"
        elif "huawei" in hostname_lower:
            return "Huawei"
        elif "oneplus" in hostname_lower:
            return "OnePlus"
        elif "pixel" in hostname_lower:
            return "Google Pixel"
        elif "desktop" in hostname_lower or "pc" in hostname_lower:
            return "Desktop PC"
        elif "laptop" in hostname_lower:
            return "Laptop"
        elif "tv" in hostname_lower or "roku" in hostname_lower:
            return "Smart TV"
        elif "echo" in hostname_lower or "alexa" in hostname_lower:
            return "Amazon Echo"
        elif "nintendo" in hostname_lower or "switch" in hostname_lower:
            return "Nintendo Switch"
        elif "playstation" in hostname_lower or "ps5" in hostname_lower or "ps4" in hostname_lower:
            return "PlayStation"
        elif "xbox" in hostname_lower:
            return "Xbox"
        
        return "Unknown"
    
    def stop(self):
        """Stop the scanning thread."""
        self._is_running = False


class DeviceDiscoveryTab(QWidget):
    """Tab for discovering and displaying network devices."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        # Long-lived so the hostname cache and modem session persist between scans
        self._scanner = DeviceScanner(timeout=3)
        self._modem_scraper = None
        self._setup_ui()

    def start_scan(self):
        """Start a network scan. Public entry point for the Tools menu."""
        if self._worker is not None and self._worker.isRunning():
            return
        self._start_scan()

    def cleanup(self):
        """Wait for an in-flight scan before the tab goes away."""
        if self._worker is not None and self._worker.isRunning():
            self._worker.requestInterruption()
            if not self._worker.wait(5000):
                self._worker.terminate()
                self._worker.wait(1000)
    
    def _setup_ui(self):
        """Set up the UI components."""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("Device Discovery")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        # Scan button
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.clicked.connect(self._start_scan)
        header_layout.addWidget(self.scan_button)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready to scan network")
        layout.addWidget(self.status_label)
        
        # Device table
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels([
            "Device", "IP Address", "MAC Address", "Hostname", "Connection", "Status"
        ])
        self.device_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.device_table)
        
        # Summary label
        self.summary_label = QLabel("No devices found")
        layout.addWidget(self.summary_label)
    
    def _start_scan(self):
        """Start the network scan."""
        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText("Scanning network...")
        self.device_table.setRowCount(0)
        
        # Hand the worker the shared scanner and modem session so the hostname
        # cache and the modem login survive across scans. Constructing the
        # scraper is just object setup, no I/O, so it is safe here.
        if self._modem_scraper is None and MODEM_DEFAULT_IP:
            from core.modem_scraper import ModemScraper
            self._modem_scraper = ModemScraper(
                modem_ip=MODEM_DEFAULT_IP,
                username=MODEM_DEFAULT_USERNAME,
                password=MODEM_DEFAULT_PASSWORD
            )

        self._worker = DeviceDiscoveryWorker(
            scanner=self._scanner, modem_scraper=self._modem_scraper
        )
        self._worker.device_found.connect(self._on_device_found)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.status_update.connect(self._on_status_update)
        self._worker.start()
    
    def _on_status_update(self, message: str):
        """Handle status updates from worker."""
        self.status_label.setText(message)
    
    def _on_device_found(self, device_info: dict):
        """Handle when a new device is found."""
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        
        self.device_table.setItem(row, 0, QTableWidgetItem(device_info.get("device", "Unknown")))
        self.device_table.setItem(row, 1, QTableWidgetItem(device_info.get("ip", "")))
        self.device_table.setItem(row, 2, QTableWidgetItem(device_info.get("mac", "")))
        self.device_table.setItem(row, 3, QTableWidgetItem(device_info.get("hostname", "")))
        self.device_table.setItem(row, 4, QTableWidgetItem(device_info.get("connection", "Unknown")))
        self.device_table.setItem(row, 5, QTableWidgetItem(device_info.get("status", "")))
    
    def _on_scan_complete(self, devices: list):
        """Handle when scan is complete."""
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Scan complete - {len(devices)} devices found")
        
        # Count by connection type
        wifi_count = sum(1 for d in devices if "WiFi" in d.get("connection", ""))
        lan_count = sum(1 for d in devices if "LAN" in d.get("connection", ""))
        unknown_count = sum(1 for d in devices if d.get("connection", "Unknown") == "Unknown")
        
        summary = f"Total: {len(devices)} devices"
        if wifi_count > 0:
            summary += f" | WiFi: {wifi_count}"
        if lan_count > 0:
            summary += f" | LAN: {lan_count}"
        if unknown_count > 0:
            summary += f" | Unknown: {unknown_count}"
        
        self.summary_label.setText(summary)
    
    def _on_error(self, error_message: str):
        """Handle errors during scanning."""
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Error: {error_message}")
