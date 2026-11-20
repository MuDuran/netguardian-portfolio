"""
Traffic Monitoring Tab
UI component for real-time bandwidth monitoring with per-device breakdown.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QComboBox, QGroupBox, QMessageBox, QCheckBox, QTableWidget,
    QTableWidgetItem, QHeaderView
)
from PySide6.QtCore import Qt, QTimer
import pyqtgraph as pg
from core.traffic_monitor import TrafficMonitor
from core.per_device_traffic import PerDeviceTrafficMonitor


class TrafficMonitoringTab(QWidget):
    """Tab for monitoring network traffic in real-time with per-device breakdown."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._monitor = TrafficMonitor()
        self._per_device_monitor = PerDeviceTrafficMonitor()
        self._timer = QTimer()
        self._interface_timer = QTimer()
        self._per_device_timer = QTimer()
        self._zero_speed_count = 0
        self._monitored_interface = None
        self._sample_index = 0
        self._setup_ui()
        self._setup_connections()
        self._refresh_interfaces()
    
    def _setup_ui(self):
        """Set up the UI components."""
        layout = QVBoxLayout(self)
        
        # Configure PyQtGraph for dark theme
        pg.setConfigOptions(antialias=True)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("Traffic Monitoring")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        # Interface selector
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(250)
        header_layout.addWidget(QLabel("Interface:"))
        header_layout.addWidget(self.interface_combo)
        
        # Refresh interfaces button
        self.refresh_interfaces_btn = QPushButton("Refresh List")
        self.refresh_interfaces_btn.setToolTip("Refresh list of network interfaces with current traffic")
        header_layout.addWidget(self.refresh_interfaces_btn)
        
        # Start/Stop button
        self.start_button = QPushButton("Start Monitoring")
        header_layout.addWidget(self.start_button)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Per-device monitoring toggle
        per_device_toggle_layout = QHBoxLayout()
        self.per_device_checkbox = QCheckBox("Enable Per-Device Traffic Monitoring")
        self.per_device_checkbox.setToolTip(
            "Shows bandwidth usage per device on your network.\n"
            "Uses packet sniffing (requires admin privileges)."
        )
        per_device_toggle_layout.addWidget(self.per_device_checkbox)
        per_device_toggle_layout.addStretch()
        layout.addLayout(per_device_toggle_layout)
        
        # Real-time graph
        graph_group = QGroupBox("Real-time Traffic Graph")
        graph_layout = QVBoxLayout(graph_group)
        
        # Create plot widget
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground('w')  # White background
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.setLabel('left', 'Speed', units='B/s')
        self.plot_widget.setLabel('bottom', 'Time', units='s')
        self.plot_widget.addLegend()
        
        # Create plot curves
        self.download_curve = self.plot_widget.plot(
            pen=pg.mkPen(color='b', width=2),  # Blue line
            name='Download'
        )
        self.upload_curve = self.plot_widget.plot(
            pen=pg.mkPen(color='r', width=2),  # Red line
            name='Upload'
        )
        
        # Data storage for graph
        self._time_data = []
        self._download_data = []
        self._upload_data = []
        self._max_points = 60  # Show last 60 seconds
        
        graph_layout.addWidget(self.plot_widget)
        layout.addWidget(graph_group)
        
        # Stats
        stats_layout = QHBoxLayout()
        
        # Download speed
        download_group = QGroupBox("Download Speed")
        download_layout = QVBoxLayout(download_group)
        self.download_label = QLabel("0.00 B/s")
        self.download_label.setStyleSheet("font-size: 24px; font-weight: bold; color: blue;")
        self.download_label.setAlignment(Qt.AlignCenter)
        download_layout.addWidget(self.download_label)
        stats_layout.addWidget(download_group)
        
        # Upload speed
        upload_group = QGroupBox("Upload Speed")
        upload_layout = QVBoxLayout(upload_group)
        self.upload_label = QLabel("0.00 B/s")
        self.upload_label.setStyleSheet("font-size: 24px; font-weight: bold; color: red;")
        self.upload_label.setAlignment(Qt.AlignCenter)
        upload_layout.addWidget(self.upload_label)
        stats_layout.addWidget(upload_group)
        
        # Total data
        data_group = QGroupBox("Total Data")
        data_layout = QVBoxLayout(data_group)
        self.data_label = QLabel("0.00 B")
        self.data_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        self.data_label.setAlignment(Qt.AlignCenter)
        data_layout.addWidget(self.data_label)
        stats_layout.addWidget(data_group)
        
        layout.addLayout(stats_layout)
        
        # Per-device traffic table
        per_device_group = QGroupBox("Per-Device Traffic")
        per_device_inner_layout = QVBoxLayout(per_device_group)
        
        self.per_device_table = QTableWidget()
        self.per_device_table.setColumnCount(6)
        self.per_device_table.setHorizontalHeaderLabels([
            "Device", "IP Address", "Upload Speed", "Download Speed",
            "Total Up", "Total Down"
        ])
        self.per_device_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self.per_device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.per_device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.per_device_table.setMaximumHeight(200)
        per_device_inner_layout.addWidget(self.per_device_table)
        
        layout.addWidget(per_device_group)
        
        # Status
        self.status_label = QLabel("Ready to monitor traffic")
        layout.addWidget(self.status_label)
    
    def _setup_connections(self):
        """Set up signal/slot connections."""
        self.start_button.clicked.connect(self._toggle_monitoring)
        self._timer.timeout.connect(self._update_monitoring)
        self.interface_combo.currentTextChanged.connect(self._on_interface_changed)
        self.refresh_interfaces_btn.clicked.connect(self._refresh_interfaces)
        self._interface_timer.timeout.connect(self._refresh_interfaces)
        self._per_device_timer.timeout.connect(self._update_per_device)
        self.per_device_checkbox.stateChanged.connect(self._on_per_device_toggled)
    
    def _on_per_device_toggled(self, state):
        """Handle per-device monitoring toggle."""
        if state == Qt.Checked and self._monitor.is_monitoring:
            self._start_per_device_monitoring()
        elif state != Qt.Checked:
            self._stop_per_device_monitoring()
    
    def _start_per_device_monitoring(self):
        """Start per-device traffic monitoring."""
        self._per_device_monitor.interface = self._selected_interface()
        self._per_device_monitor.start()
        self._per_device_timer.start(1000)
    
    def _stop_per_device_monitoring(self):
        """Stop per-device traffic monitoring."""
        self._per_device_timer.stop()
        if self._per_device_monitor.is_monitoring:
            self._per_device_monitor.stop()
        self.per_device_table.setRowCount(0)
    
    def _update_per_device(self):
        """
        Update the per-device traffic table.

        Cells are written in place rather than clearing and rebuilding the
        table. Rebuilding once a second destroyed and recreated every widget
        item, which flickered and threw away the user's selection and scroll
        position.
        """
        traffic_data = self._per_device_monitor.update()

        table = self.per_device_table
        table.setUpdatesEnabled(False)
        try:
            if table.rowCount() != len(traffic_data):
                table.setRowCount(len(traffic_data))

            for row, device in enumerate(traffic_data):
                display_name = device.device_name
                if display_name == "Unknown":
                    display_name = device.hostname
                if display_name == "Unknown":
                    display_name = device.ip

                values = (
                    display_name,
                    device.ip,
                    PerDeviceTrafficMonitor.format_speed(device.upload_speed),
                    PerDeviceTrafficMonitor.format_speed(device.download_speed),
                    PerDeviceTrafficMonitor.format_bytes(device.bytes_sent),
                    PerDeviceTrafficMonitor.format_bytes(device.bytes_recv),
                )

                for column, value in enumerate(values):
                    item = table.item(row, column)
                    if item is None:
                        table.setItem(row, column, QTableWidgetItem(value))
                    elif item.text() != value:
                        item.setText(value)
        finally:
            table.setUpdatesEnabled(True)
    
    def set_device_info(self, devices: list):
        """Set device information for per-device correlation."""
        self._per_device_monitor.set_device_info_batch(devices)
    
    def _toggle_monitoring(self):
        """Toggle monitoring on/off."""
        if self._monitor.is_monitoring:
            self._stop_monitoring()
        else:
            self._start_monitoring()
    
    def _selected_interface(self):
        """
        The interface name currently selected, or None for "All Interfaces".

        Read from the item's stored data rather than parsed out of the label:
        the label carries a live speed and would also break on any interface
        whose real name contains " (".
        """
        name = self.interface_combo.currentData()
        return name if name else None

    def _refresh_interfaces(self):
        """Refresh the list of interfaces with current traffic rates."""
        # Remember the interface itself, not the label. The label embeds a
        # speed that changes every refresh, so matching on it always failed and
        # silently reset the selection, which restarted monitoring every 5s.
        current_interface = self._selected_interface()

        # Repopulating fires currentTextChanged for every item; block it so the
        # refresh cannot be mistaken for the user picking a new interface.
        self.interface_combo.blockSignals(True)
        try:
            self.interface_combo.clear()
            self.interface_combo.addItem("All Interfaces", None)

            interfaces_with_speeds = TrafficMonitor.get_interfaces_speeds()

            # Sort by total speed (highest first) to show active interfaces first
            interfaces_with_speeds.sort(key=lambda x: x["total_speed"], reverse=True)

            for iface in interfaces_with_speeds:
                name = iface["name"]
                total = iface["upload_speed"] + iface["download_speed"]
                speed_str = TrafficMonitor.format_speed(total)
                self.interface_combo.addItem(f"{name} ({speed_str})", name)

            # Restore the previous selection by interface, not by label
            index = self.interface_combo.findData(current_interface)
            self.interface_combo.setCurrentIndex(index if index >= 0 else 0)
        finally:
            self.interface_combo.blockSignals(False)
    
    def _start_monitoring(self):
        """Start traffic monitoring."""
        interface = self._selected_interface()

        # Update monitor interface
        self._monitor.interface = interface
        self._monitored_interface = interface
        
        # Start monitoring
        self._monitor.start()
        
        # Start update timer (1 second interval)
        self._timer.start(1000)
        
        # Start interface refresh timer (5 seconds interval)
        self._interface_timer.start(5000)
        
        # Reset zero speed counter
        self._zero_speed_count = 0
        
        # Start per-device monitoring if checkbox is checked
        if self.per_device_checkbox.isChecked():
            self._start_per_device_monitoring()
        
        # Update UI
        self.start_button.setText("Stop Monitoring")
        self.status_label.setText(f"Monitoring {interface or 'all interfaces'}...")
    
    def _stop_monitoring(self):
        """Stop traffic monitoring."""
        # Stop timers and monitor
        self._timer.stop()
        self._interface_timer.stop()
        self._monitor.stop()
        
        # Stop per-device monitoring
        self._stop_per_device_monitoring()
        
        # Update UI
        self.start_button.setText("Start Monitoring")
        self.status_label.setText("Monitoring stopped")
    
    def _on_interface_changed(self, interface_name: str):
        """Handle interface selection change."""
        if not self._monitor.is_monitoring:
            return

        # Only restart if the user actually picked a different interface.
        # A label whose speed text changed is not a new selection.
        if self._selected_interface() == self._monitored_interface:
            return

        self._stop_monitoring()
        self._start_monitoring()
    
    def _update_monitoring(self):
        """Update monitoring data and UI."""
        # Get current snapshot
        snapshot = self._monitor.update()
        
        if snapshot is None:
            return
        
        # Update labels
        self.download_label.setText(TrafficMonitor.format_speed(snapshot.download_speed))
        self.upload_label.setText(TrafficMonitor.format_speed(snapshot.upload_speed))
        
        # Update total data
        total_bytes = snapshot.bytes_sent + snapshot.bytes_recv
        self.data_label.setText(TrafficMonitor.format_bytes(total_bytes))
        
        # Check for zero speed and warn user
        interface_name = self._monitored_interface or "All Interfaces"
        if snapshot.download_speed == 0 and snapshot.upload_speed == 0:
            self._zero_speed_count += 1
            if self._zero_speed_count >= 10 and self._monitored_interface:
                self.status_label.setText(
                    f"⚠️ No traffic detected on {interface_name}. "
                    "Try 'All Interfaces' or click 'Refresh List'."
                )
        else:
            self._zero_speed_count = 0
            self.status_label.setText(f"Monitoring {interface_name}...")

        # Update graph data. Use a monotonic sample counter, not len(), which
        # stopped advancing once the buffer filled and froze the x axis.
        self._sample_index += 1
        self._time_data.append(self._sample_index)
        self._download_data.append(snapshot.download_speed)
        self._upload_data.append(snapshot.upload_speed)
        
        # Trim old data
        if len(self._time_data) > self._max_points:
            self._time_data = self._time_data[-self._max_points:]
            self._download_data = self._download_data[-self._max_points:]
            self._upload_data = self._upload_data[-self._max_points:]
        
        # Update plot curves
        self.download_curve.setData(self._time_data, self._download_data)
        self.upload_curve.setData(self._time_data, self._upload_data)
    
    def cleanup(self):
        """Clean up resources when tab is closed."""
        self._stop_monitoring()
        self._per_device_monitor.stop()
        self._timer.deleteLater()
