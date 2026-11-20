"""
Port Scanner Tab
UI component for scanning network ports and services.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QSpinBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QGroupBox, QCheckBox, QProgressBar
)
from PySide6.QtCore import Qt, Signal, QThread
from core.port_scanner import (
    PortScanner, ScanResult,
    COMMON_PORTS, InvalidScanTarget, validate_target, validate_ports,
)


class PortScannerWorker(QThread):
    """Background worker for port scanning."""
    
    scan_complete = Signal(object)
    error_occurred = Signal(str)
    
    def __init__(self, target: str, ports: str, scan_type: str, service_detection: bool):
        super().__init__()
        self._target = target
        self._ports = ports
        self._scan_type = scan_type
        self._service_detection = service_detection
        self._scanner = PortScanner()
    
    def run(self):
        """Perform port scan."""
        try:
            result = self._scanner.scan(
                self._target,
                self._ports,
                self._scan_type,
                self._service_detection
            )
            self.scan_complete.emit(result)
        except Exception as e:
            self.error_occurred.emit(str(e))


class PortScannerTab(QWidget):
    """Tab for scanning network ports and identifying services."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self._setup_ui()

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
        title_label = QLabel("Port Scanner")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Target input
        target_group = QGroupBox("Scan Target")
        target_layout = QHBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("IP Address/Range:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.1 or 192.168.1.0/24")
        target_layout.addWidget(self.target_input)
        
        target_layout.addWidget(QLabel("Port Range:"))
        self.port_start = QSpinBox()
        self.port_start.setRange(1, 65535)
        self.port_start.setValue(1)
        target_layout.addWidget(self.port_start)
        
        target_layout.addWidget(QLabel("to"))
        self.port_end = QSpinBox()
        self.port_end.setRange(1, 65535)
        self.port_end.setValue(1024)
        target_layout.addWidget(self.port_end)
        
        # Scan button
        self.scan_button = QPushButton("Scan Ports")
        target_layout.addWidget(self.scan_button)
        
        layout.addWidget(target_group)
        
        # Scan options
        options_layout = QHBoxLayout()
        
        self.quick_scan_cb = QCheckBox("Quick Scan (Top 100 ports)")
        options_layout.addWidget(self.quick_scan_cb)
        
        self.service_detection_cb = QCheckBox("Service Detection (slower)")
        self.service_detection_cb.setToolTip(
            "Runs nmap -sV to identify service versions.\n"
            "This is the slowest phase of a scan; turn it off for a quick sweep."
        )
        self.service_detection_cb.setChecked(True)
        options_layout.addWidget(self.service_detection_cb)
        
        options_layout.addStretch()
        layout.addLayout(options_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results table
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Port", "Protocol", "State", "Service", "Version", "Process"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        results_layout.addWidget(self.results_table)
        
        layout.addWidget(results_group)
        
        # Status
        self.status_label = QLabel("Ready to scan ports")
        layout.addWidget(self.status_label)
        
        # Connect signals
        self.scan_button.clicked.connect(self._start_scan)
    
    def _start_scan(self):
        """Start the port scan."""
        if self._worker is not None and self._worker.isRunning():
            return

        # Determine port range
        if self.quick_scan_cb.isChecked():
            ports = COMMON_PORTS
            scan_type = "quick"
        else:
            start = self.port_start.value()
            end = self.port_end.value()
            ports = f"{start}-{end}"
            scan_type = "full" if (end - start) > 1000 else "quick"

        # Validate before touching the UI or spawning a thread, so a typo gives
        # an immediate message instead of an nmap error.
        try:
            target = validate_target(self.target_input.text())
            ports = validate_ports(ports)
        except InvalidScanTarget as e:
            self.status_label.setText(f"Error: {e}")
            return

        # Update UI
        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText(f"Scanning {target}...")
        self.results_table.setRowCount(0)
        
        # Start worker thread
        self._worker = PortScannerWorker(
            target,
            ports,
            scan_type,
            self.service_detection_cb.isChecked()
        )
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.start()
    
    def _on_scan_complete(self, result: ScanResult):
        """Handle scan completion."""
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if result is None:
            self.status_label.setText("Scan failed")
            return
        
        if result.state == "down":
            self.status_label.setText(f"Host {result.ip} is down or unreachable")
            return
        
        # Populate results table
        for port_info in result.ports:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            self.results_table.setItem(row, 0, QTableWidgetItem(str(port_info.port)))
            self.results_table.setItem(row, 1, QTableWidgetItem(port_info.protocol))
            self.results_table.setItem(row, 2, QTableWidgetItem(port_info.state))
            self.results_table.setItem(row, 3, QTableWidgetItem(port_info.service))
            
            # Combine version info
            version_info = port_info.version
            if port_info.banner:
                version_info = f"{port_info.banner} {version_info}".strip()
            self.results_table.setItem(row, 4, QTableWidgetItem(version_info))
            
            # Process info
            process_info = port_info.process_name
            if port_info.pid and not process_info.startswith("PID:"):
                process_info = f"{process_info} (PID:{port_info.pid})"
            self.results_table.setItem(row, 5, QTableWidgetItem(process_info))
        
        # Update status
        hostname = f" ({result.hostname})" if result.hostname else ""
        self.status_label.setText(
            f"Scan complete: {result.ip}{hostname} - "
            f"{len(result.ports)} ports found"
        )
    
    def _on_error(self, error_message: str):
        """Handle scan error."""
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Error: {error_message}")
