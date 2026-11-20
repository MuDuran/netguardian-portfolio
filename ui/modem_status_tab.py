"""
Modem Status Tab
UI component for viewing modem information and connected devices.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QLineEdit, QFormLayout, QProgressBar, QTabWidget
)
from PySide6.QtCore import Qt, Signal, QThread
from core.modem_scraper import ModemScraper, ModemStatus
from config import (
    MODEM_DEFAULT_IP, MODEM_DEFAULT_USERNAME, MODEM_DEFAULT_PASSWORD,
)


class ModemStatusWorker(QThread):
    """Background worker for modem status scraping."""
    
    status_complete = Signal(object)
    error_occurred = Signal(str)
    
    def __init__(self, modem_ip: str, username: str, password: str,
                 scraper=None, force_refresh: bool = True):
        super().__init__()
        self._modem_ip = modem_ip
        self._username = username
        self._password = password
        # Reused across refreshes so the login session survives.
        self._scraper = scraper
        self._force_refresh = force_refresh

    def run(self):
        """Perform modem status scrape."""
        try:
            if self._scraper is None:
                self._scraper = ModemScraper(
                    modem_ip=self._modem_ip,
                    username=self._username,
                    password=self._password
                )
            # Pressing Refresh means the user wants current data, so bypass the
            # cache. Background callers take whatever is recent.
            status = self._scraper.get_status(
                max_age=0 if self._force_refresh else None
            )
            self.status_complete.emit(status)
        except Exception as e:
            self.error_occurred.emit(str(e))


class ModemStatusTab(QWidget):
    """Tab for displaying modem status and connected devices."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        # Long-lived scraper so the modem login session is reused.
        self._scraper = None
        self._scraper_settings = None
        self._setup_ui()


    def _remember_scraper(self, _status):
        """Keep the worker's scraper so its session is reused next time."""
        if self._worker is not None:
            self._scraper = self._worker._scraper

    def cleanup(self):
        """Wait for an in-flight refresh before the tab goes away."""
        if getattr(self, "_worker", None) is not None and self._worker.isRunning():
            self._worker.requestInterruption()
            if not self._worker.wait(5000):
                self._worker.terminate()
                self._worker.wait(1000)

    def _setup_ui(self):
        """Set up the UI components."""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("Modem Status")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        # Refresh button
        self.refresh_button = QPushButton("Refresh Status")
        header_layout.addWidget(self.refresh_button)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Modem connection settings
        settings_group = QGroupBox("Modem Settings")
        settings_layout = QHBoxLayout(settings_group)
        
        settings_layout.addWidget(QLabel("Modem IP:"))
        self.ip_input = QLineEdit(MODEM_DEFAULT_IP)
        self.ip_input.setMaximumWidth(150)
        settings_layout.addWidget(self.ip_input)
        
        settings_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit(MODEM_DEFAULT_USERNAME)
        self.username_input.setMaximumWidth(100)
        settings_layout.addWidget(self.username_input)
        
        settings_layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit(MODEM_DEFAULT_PASSWORD)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMaximumWidth(100)
        settings_layout.addWidget(self.password_input)
        
        settings_layout.addStretch()
        layout.addWidget(settings_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Create tabs for different sections
        self.tab_widget = QTabWidget()
        
        # === Overview Tab ===
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        
        # GPON/Fiber info
        gpon_group = QGroupBox("GPON / Fiber Status")
        gpon_layout = QFormLayout(gpon_group)
        
        self.gpon_status_label = QLabel("N/A")
        gpon_layout.addRow("Link Status:", self.gpon_status_label)
        
        self.gpon_rx_label = QLabel("N/A")
        gpon_layout.addRow("Rx Power:", self.gpon_rx_label)
        
        self.gpon_tx_label = QLabel("N/A")
        gpon_layout.addRow("Tx Power:", self.gpon_tx_label)
        
        overview_layout.addWidget(gpon_group)
        
        # Internet info
        internet_group = QGroupBox("Internet Connection")
        internet_layout = QFormLayout(internet_group)
        
        self.internet_status_label = QLabel("N/A")
        internet_layout.addRow("Status:", self.internet_status_label)
        
        self.ipv4_public_label = QLabel("N/A")
        internet_layout.addRow("Public IPv4:", self.ipv4_public_label)
        
        self.ipv4_local_label = QLabel("N/A")
        internet_layout.addRow("Local IPv4:", self.ipv4_local_label)
        
        self.gateway_label = QLabel("N/A")
        internet_layout.addRow("Gateway:", self.gateway_label)
        
        self.dns_primary_label = QLabel("N/A")
        internet_layout.addRow("Primary DNS:", self.dns_primary_label)
        
        self.dns_secondary_label = QLabel("N/A")
        internet_layout.addRow("Secondary DNS:", self.dns_secondary_label)
        
        overview_layout.addWidget(internet_group)
        
        # Modem info
        modem_info_group = QGroupBox("Modem Information")
        modem_info_layout = QFormLayout(modem_info_group)
        
        self.model_label = QLabel("N/A")
        modem_info_layout.addRow("Model:", self.model_label)
        
        self.ip_label = QLabel("N/A")
        modem_info_layout.addRow("Modem IP:", self.ip_label)
        
        overview_layout.addWidget(modem_info_group)
        
        overview_layout.addStretch()
        self.tab_widget.addTab(overview_tab, "Overview")
        
        # === WiFi Tab ===
        wifi_tab = QWidget()
        wifi_layout = QVBoxLayout(wifi_tab)
        
        # WiFi 2.4GHz
        wifi_24g_group = QGroupBox("WiFi 2.4 GHz")
        wifi_24g_layout = QFormLayout(wifi_24g_group)
        
        self.ssid_24g_label = QLabel("N/A")
        wifi_24g_layout.addRow("SSID:", self.ssid_24g_label)
        
        self.wifi_status_24g_label = QLabel("N/A")
        wifi_24g_layout.addRow("Status:", self.wifi_status_24g_label)
        
        self.channel_24g_label = QLabel("N/A")
        wifi_24g_layout.addRow("Channel:", self.channel_24g_label)
        
        self.security_24g_label = QLabel("N/A")
        wifi_24g_layout.addRow("Security:", self.security_24g_label)
        
        self.wps_24g_label = QLabel("N/A")
        wifi_24g_layout.addRow("WPS:", self.wps_24g_label)
        
        wifi_layout.addWidget(wifi_24g_group)
        
        # WiFi 5GHz
        wifi_5g_group = QGroupBox("WiFi 5 GHz")
        wifi_5g_layout = QFormLayout(wifi_5g_group)
        
        self.ssid_5g_label = QLabel("N/A")
        wifi_5g_layout.addRow("SSID:", self.ssid_5g_label)
        
        self.wifi_status_5g_label = QLabel("N/A")
        wifi_5g_layout.addRow("Status:", self.wifi_status_5g_label)
        
        self.channel_5g_label = QLabel("N/A")
        wifi_5g_layout.addRow("Channel:", self.channel_5g_label)
        
        self.security_5g_label = QLabel("N/A")
        wifi_5g_layout.addRow("Security:", self.security_5g_label)
        
        self.wps_5g_label = QLabel("N/A")
        wifi_5g_layout.addRow("WPS:", self.wps_5g_label)
        
        wifi_layout.addWidget(wifi_5g_group)
        
        wifi_layout.addStretch()
        self.tab_widget.addTab(wifi_tab, "WiFi")
        
        # === Devices Tab ===
        devices_tab = QWidget()
        devices_layout = QVBoxLayout(devices_tab)
        
        # Connected devices table
        self.devices_table = QTableWidget()
        self.devices_table.setColumnCount(5)
        self.devices_table.setHorizontalHeaderLabels([
            "Device Name", "IP Address", "MAC Address", "Connection", "Interface"
        ])
        self.devices_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self.devices_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.devices_table.setEditTriggers(QTableWidget.NoEditTriggers)
        devices_layout.addWidget(self.devices_table)
        
        self.tab_widget.addTab(devices_tab, "Connected Devices")
        
        # === LAN Tab ===
        lan_tab = QWidget()
        lan_layout = QVBoxLayout(lan_tab)
        
        # LAN ports table
        self.lan_table = QTableWidget()
        self.lan_table.setColumnCount(3)
        self.lan_table.setHorizontalHeaderLabels([
            "Port", "Status", "Device"
        ])
        self.lan_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self.lan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.lan_table.setEditTriggers(QTableWidget.NoEditTriggers)
        lan_layout.addWidget(self.lan_table)
        
        self.tab_widget.addTab(lan_tab, "LAN Ports")
        
        layout.addWidget(self.tab_widget)
        
        # Status
        self.status_label = QLabel("Click 'Refresh Status' to load modem information")
        layout.addWidget(self.status_label)
        
        # Connect signals
        self.refresh_button.clicked.connect(self._refresh_status)
    
    def _refresh_status(self):
        """Refresh modem status."""
        modem_ip = self.ip_input.text().strip()
        if not modem_ip:
            self.status_label.setText("Enter the modem IP address in Modem Settings.")
            return

        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        self.refresh_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText("Loading modem status...")

        # Reuse the scraper unless the connection settings changed, so the
        # login session carries over between refreshes.
        settings = (modem_ip, username, password)
        if getattr(self, "_scraper_settings", None) != settings:
            self._scraper = None
            self._scraper_settings = settings

        # Start worker thread
        self._worker = ModemStatusWorker(
            modem_ip, username, password,
            scraper=self._scraper, force_refresh=True
        )
        self._worker.status_complete.connect(self._remember_scraper)
        self._worker.status_complete.connect(self._on_status_complete)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.start()
    
    def _on_status_complete(self, status: ModemStatus):
        """Handle status load completion."""
        self.refresh_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if status.error:
            self.status_label.setText(f"Error: {status.error}")
            return
        
        # Update GPON info
        if status.modem_info:
            self.ip_label.setText(status.modem_info.ip_address)
            self.model_label.setText(status.modem_info.model)
            
            # GPON status
            self.gpon_status_label.setText(status.modem_info.gpon_status)
            self.gpon_rx_label.setText(status.modem_info.gpon_rx_power)
            self.gpon_tx_label.setText(status.modem_info.gpon_tx_power)
            
            # Internet status
            self.internet_status_label.setText(status.modem_info.internet_status)
            self.ipv4_public_label.setText(status.modem_info.ipv4_public)
            self.ipv4_local_label.setText(status.modem_info.ipv4_local)
            self.gateway_label.setText(status.modem_info.gateway)
            self.dns_primary_label.setText(status.modem_info.dns_primary)
            self.dns_secondary_label.setText(status.modem_info.dns_secondary)
        
        # Update WiFi 2.4GHz info
        if status.wifi_info_24ghz:
            self.ssid_24g_label.setText(status.wifi_info_24ghz.ssid)
            self.wifi_status_24g_label.setText(status.wifi_info_24ghz.status)
            self.channel_24g_label.setText(str(status.wifi_info_24ghz.channel))
            self.security_24g_label.setText(status.wifi_info_24ghz.security)
            self.wps_24g_label.setText(status.wifi_info_24ghz.wps_enabled)
        
        # Update WiFi 5GHz info
        if status.wifi_info_5ghz:
            self.ssid_5g_label.setText(status.wifi_info_5ghz.ssid)
            self.wifi_status_5g_label.setText(status.wifi_info_5ghz.status)
            self.channel_5g_label.setText(str(status.wifi_info_5ghz.channel))
            self.security_5g_label.setText(status.wifi_info_5ghz.security)
            self.wps_5g_label.setText(status.wifi_info_5ghz.wps_enabled)
        
        # Update connected devices table
        self.devices_table.setRowCount(0)
        for device in status.connected_devices:
            row = self.devices_table.rowCount()
            self.devices_table.insertRow(row)
            
            self.devices_table.setItem(row, 0, QTableWidgetItem(device.name))
            self.devices_table.setItem(row, 1, QTableWidgetItem(device.ip_address))
            self.devices_table.setItem(row, 2, QTableWidgetItem(device.mac_address))
            self.devices_table.setItem(row, 3, QTableWidgetItem(device.connection_type))
            self.devices_table.setItem(row, 4, QTableWidgetItem(device.interface))
        
        # Update LAN ports table
        self.lan_table.setRowCount(0)
        for port in status.lan_ports:
            row = self.lan_table.rowCount()
            self.lan_table.insertRow(row)
            
            self.lan_table.setItem(row, 0, QTableWidgetItem(port.port_name))
            self.lan_table.setItem(row, 1, QTableWidgetItem(port.status))
            self.lan_table.setItem(row, 2, QTableWidgetItem(port.device_name))
        
        # Update status
        device_count = len(status.connected_devices)
        lan_count = len([p for p in status.lan_ports if p.status == "Connected"])
        self.status_label.setText(
            f"Status loaded successfully - {device_count} devices connected, "
            f"{lan_count} LAN ports active"
        )
    
    def _on_error(self, error_message: str):
        """Handle error during status load."""
        self.refresh_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Error: {error_message}")
