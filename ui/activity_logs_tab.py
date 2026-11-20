"""
Activity Logs Tab
UI component for displaying network activity logs.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QTextEdit, QDateEdit, QComboBox, QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt, QDate, QTimer
from core.activity_logger import ActivityLogger
from datetime import datetime


class ActivityLogsTab(QWidget):
    """Tab for displaying network activity logs."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        # Shared instance: a second ActivityLogger would open a second
        # connection to the same database, and closeEvent only closes one.
        self._logger = ActivityLogger.instance()
        self._setup_ui()
        self._setup_connections()
        self._load_events()
    
    def _setup_ui(self):
        """Set up the UI components."""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("Activity Logs")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        # Filter controls
        header_layout.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "All Events",
            "Device Discovery",
            "Traffic Monitor",
            "Port Scanner",
            "Modem Status",
            "Firewall Manager",
            "System"
        ])
        header_layout.addWidget(self.filter_combo)
        
        header_layout.addWidget(QLabel("Date:"))
        self.date_edit = QDateEdit()
        self.date_edit.setDate(QDate.currentDate())
        self.date_edit.setCalendarPopup(True)
        header_layout.addWidget(self.date_edit)
        
        # Export button
        self.export_button = QPushButton("Export Logs")
        header_layout.addWidget(self.export_button)
        
        # Refresh button
        self.refresh_button = QPushButton("Refresh")
        header_layout.addWidget(self.refresh_button)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Log table
        log_group = QGroupBox("Event Log")
        log_layout = QVBoxLayout(log_group)
        
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(5)
        self.log_table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Source", "Details", "Severity"
        ])
        self.log_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        log_layout.addWidget(self.log_table)
        
        layout.addWidget(log_group)
        
        # Log details
        details_group = QGroupBox("Event Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        details_layout.addWidget(self.details_text)
        
        layout.addWidget(details_group)
        
        # Status bar
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        
        self.count_label = QLabel("Total events: 0")
        status_layout.addWidget(self.count_label)
        
        status_layout.addStretch()
        layout.addLayout(status_layout)
    
    def _setup_connections(self):
        """Set up signal/slot connections."""
        self.filter_combo.currentTextChanged.connect(self._on_filter_changed)
        self.date_edit.dateChanged.connect(self._on_date_changed)
        self.export_button.clicked.connect(self._export_logs)
        self.refresh_button.clicked.connect(self._load_events)
        self.log_table.itemSelectionChanged.connect(self._on_selection_changed)
    
    def _load_events(self):
        """Load events from database."""
        self.status_label.setText("Loading events...")
        
        # Get filter values
        filter_text = self.filter_combo.currentText()
        selected_date = self.date_edit.date().toPython()
        
        # Map filter text to event type
        event_type_map = {
            "All Events": None,
            "Device Discovery": "DEVICE_DISCOVERY",
            "Traffic Monitor": "TRAFFIC_MONITOR",
            "Port Scanner": "PORT_SCAN",
            "Modem Status": "MODEM_STATUS",
            "Firewall Manager": "FIREWALL",
            "System": "SYSTEM"
        }
        
        event_type = event_type_map.get(filter_text)
        
        # Get start and end of selected day
        start_date = datetime.combine(selected_date, datetime.min.time())
        end_date = datetime.combine(selected_date, datetime.max.time())
        
        # Load events
        events = self._logger.get_events(
            event_type=event_type,
            start_date=start_date,
            end_date=end_date,
            limit=500
        )
        
        # Update table
        self._update_table(events)
        
        # Update status
        total_count = self._logger.get_event_count()
        self.status_label.setText(f"Showing {len(events)} events for {selected_date}")
        self.count_label.setText(f"Total events: {total_count}")
    
    def _update_table(self, events):
        """Update the events table."""
        self.log_table.setRowCount(0)
        
        for event in events:
            row = self.log_table.rowCount()
            self.log_table.insertRow(row)
            
            # Format timestamp
            timestamp_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            
            # Get event type display name
            event_type_display = self._logger.EVENT_TYPES.get(
                event.event_type, 
                event.event_type
            )
            
            self.log_table.setItem(row, 0, QTableWidgetItem(timestamp_str))
            self.log_table.setItem(row, 1, QTableWidgetItem(event_type_display))
            self.log_table.setItem(row, 2, QTableWidgetItem(event.source))
            self.log_table.setItem(row, 3, QTableWidgetItem(event.details))
            self.log_table.setItem(row, 4, QTableWidgetItem(event.severity))
    
    def _on_filter_changed(self, filter_text):
        """Handle filter change."""
        self._load_events()
    
    def _on_date_changed(self, date):
        """Handle date change."""
        self._load_events()
    
    def _on_selection_changed(self):
        """Handle table selection change."""
        selected_rows = self.log_table.selectionModel().selectedRows()
        
        if not selected_rows:
            self.details_text.clear()
            return
        
        # Get selected event details
        row = selected_rows[0].row()
        timestamp = self.log_table.item(row, 0).text()
        event_type = self.log_table.item(row, 1).text()
        source = self.log_table.item(row, 2).text()
        details = self.log_table.item(row, 3).text()
        severity = self.log_table.item(row, 4).text()
        
        # Show details
        detail_text = f"""Timestamp: {timestamp}
Event Type: {event_type}
Source: {source}
Severity: {severity}

Details:
{details}"""
        
        self.details_text.setPlainText(detail_text)
    
    def _export_logs(self):
        """Export logs to CSV file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Activity Logs",
            "activity_logs.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            success = self._logger.export_events_csv(file_path)
            if success:
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Logs exported to:\n{file_path}"
                )
            else:
                QMessageBox.warning(
                    self,
                    "Export Failed",
                    "Failed to export logs. Please check the file path."
                )
    
    def log_event(self, event_type: str, source: str, details: str, severity: str = "Info"):
        """
        Log an event and refresh the display.
        
        This method can be called from other features to log activities.
        """
        self._logger.log(event_type, source, details, severity)
        self._load_events()
