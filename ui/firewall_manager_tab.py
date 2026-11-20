"""
Firewall Manager Tab
UI component for managing Windows Firewall rules with checkbox selection.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QLineEdit, QComboBox, QFormLayout, QMessageBox, QProgressBar,
    QCheckBox
)
from PySide6.QtCore import Qt, Signal, QThread
from typing import Optional, List
from core.firewall_manager import FirewallManager, FirewallRule


class FirewallWorker(QThread):
    """Background worker for firewall operations."""

    operation_complete = Signal(str)
    error_occurred = Signal(str)
    # Carries the parsed rules and the admin flag so the GUI thread never has
    # to re-run the (expensive) netsh dump just to get at the data.
    # Typed as object, not list: the payload is FirewallRule dataclasses, and a
    # queued cross-thread connection would otherwise marshal them via
    # QVariantList.
    rules_loaded = Signal(object, bool)

    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self._operation = operation
        self._kwargs = kwargs
        self._manager = FirewallManager()

    def run(self):
        """Perform firewall operation."""
        try:
            if self._operation == "get_rules":
                show_all = self._kwargs.get("show_all", False)
                rules = self._manager.get_all_rules() if show_all else self._manager.get_rules()
                self.rules_loaded.emit(rules, self._manager.is_admin)
                self.operation_complete.emit(f"Loaded {len(rules)} rules")

            elif self._operation == "batch":
                self._run_batch()

            elif self._operation == "add_rule":
                success = self._manager.add_rule(
                    name=self._kwargs.get("name", ""),
                    action=self._kwargs.get("action", "Block"),
                    protocol=self._kwargs.get("protocol", "TCP"),
                    port=self._kwargs.get("port", ""),
                    direction=self._kwargs.get("direction", "Inbound"),
                    enabled=self._kwargs.get("enabled", True)
                )
                if success:
                    self.operation_complete.emit("Rule added successfully")
                else:
                    self.error_occurred.emit("Failed to add rule - Check if running as Administrator")
            
            elif self._operation == "delete_rule":
                success = self._manager.delete_rule(self._kwargs.get("name", ""))
                if success:
                    self.operation_complete.emit("Rule deleted successfully")
                else:
                    self.error_occurred.emit("Failed to delete rule")
            
            elif self._operation == "enable_rule":
                success = self._manager.enable_rule(self._kwargs.get("name", ""))
                if success:
                    self.operation_complete.emit("Rule enabled successfully")
                else:
                    self.error_occurred.emit("Failed to enable rule")
            
            elif self._operation == "disable_rule":
                success = self._manager.disable_rule(self._kwargs.get("name", ""))
                if success:
                    self.operation_complete.emit("Rule disabled successfully")
                else:
                    self.error_occurred.emit("Failed to disable rule")

        except Exception as e:
            self.error_occurred.emit(str(e))

    def _run_batch(self):
        """
        Apply one operation to many rules inside a single worker.

        Previously the tab spawned a fresh QThread per rule and reassigned
        self._worker each time, which could drop the last reference to a
        still-running thread.
        """
        operation = self._kwargs.get("batch_operation", "")
        names = self._kwargs.get("names", [])
        handlers = {
            "delete_rule": self._manager.delete_rule,
            "enable_rule": self._manager.enable_rule,
            "disable_rule": self._manager.disable_rule,
        }
        handler = handlers.get(operation)
        if handler is None:
            self.error_occurred.emit(f"Unknown batch operation: {operation}")
            return

        failures = []
        for name in names:
            if self.isInterruptionRequested():
                break
            try:
                if not handler(name):
                    failures.append(name)
            except Exception as e:
                failures.append(f"{name} ({e})")

        verb = operation.replace("_rule", "")
        if failures:
            self.error_occurred.emit(
                f"Batch {verb}: {len(failures)} of {len(names)} rule(s) failed"
            )
        else:
            self.operation_complete.emit(
                f"Batch {verb} complete - {len(names)} rule(s) processed"
            )


class FirewallManagerTab(QWidget):
    """Tab for managing Windows Firewall rules with checkbox selection."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        # Live workers are held here so a running QThread is never collected.
        self._workers: List[FirewallWorker] = []
        self._rules = []
        self._show_all_rules = False
        self._setup_ui()
        self._load_rules()

    def cleanup(self):
        """Stop any in-flight worker before the tab goes away."""
        for worker in list(self._workers):
            worker.requestInterruption()
            if not worker.wait(5000):
                worker.terminate()
                worker.wait(1000)
        self._workers.clear()
    
    def _setup_ui(self):
        """Set up the UI components."""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("Firewall Manager")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Admin warning
        self.admin_label = QLabel("")
        self.admin_label.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(self.admin_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Add rule form
        add_rule_group = QGroupBox("Add New Rule")
        add_rule_layout = QFormLayout(add_rule_group)
        
        self.rule_name_input = QLineEdit()
        self.rule_name_input.setPlaceholderText("e.g., Block Port 8080")
        add_rule_layout.addRow("Rule Name:", self.rule_name_input)
        
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Block", "Allow"])
        add_rule_layout.addRow("Action:", self.action_combo)
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "Any"])
        add_rule_layout.addRow("Protocol:", self.protocol_combo)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("e.g., 80, 443, 8080 or 1-1024")
        add_rule_layout.addRow("Port(s):", self.port_input)
        
        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["Inbound", "Outbound"])
        add_rule_layout.addRow("Direction:", self.direction_combo)
        
        # Add rule button
        self.add_rule_button = QPushButton("Add Rule")
        add_rule_layout.addRow("", self.add_rule_button)
        
        layout.addWidget(add_rule_group)
        
        # Existing rules
        rules_group = QGroupBox("Existing Rules")
        rules_layout = QVBoxLayout(rules_group)
        
        # Toggle for showing all rules
        toggle_layout = QHBoxLayout()
        self.show_all_checkbox = QCheckBox("Show All Windows Firewall Rules")
        self.show_all_checkbox.setToolTip(
            "Toggle between NetGuardian rules only (default) and all system firewall rules.\n"
            "System rules are displayed in gray and cannot be modified."
        )
        self.show_all_checkbox.stateChanged.connect(self._on_toggle_show_all)
        toggle_layout.addWidget(self.show_all_checkbox)
        toggle_layout.addStretch()
        rules_layout.addLayout(toggle_layout)
        
        # Rules table with checkbox column
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(6)
        self.rules_table.setHorizontalHeaderLabels([
            "", "Name", "Action", "Protocol", "Port", "Enabled"
        ])
        # Set first column (checkbox) to be narrow and fixed
        self.rules_table.setColumnWidth(0, 40)
        self.rules_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        for col in range(2, 6):
            self.rules_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeToContents
            )
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.rules_table.setEditTriggers(QTableWidget.NoEditTriggers)
        rules_layout.addWidget(self.rules_table)
        
        # Rule management buttons
        rules_button_layout = QHBoxLayout()
        
        self.check_all_button = QPushButton("Check All")
        self.check_all_button.clicked.connect(self._check_all_rules)
        rules_button_layout.addWidget(self.check_all_button)
        
        self.uncheck_all_button = QPushButton("Uncheck All")
        self.uncheck_all_button.clicked.connect(self._uncheck_all_rules)
        rules_button_layout.addWidget(self.uncheck_all_button)
        
        rules_button_layout.addSpacing(20)
        
        self.enable_button = QPushButton("Enable Checked")
        rules_button_layout.addWidget(self.enable_button)
        
        self.disable_button = QPushButton("Disable Checked")
        rules_button_layout.addWidget(self.disable_button)
        
        self.delete_button = QPushButton("Delete Checked")
        rules_button_layout.addWidget(self.delete_button)
        
        rules_button_layout.addStretch()
        
        self.refresh_button = QPushButton("Refresh Rules")
        rules_button_layout.addWidget(self.refresh_button)
        
        rules_layout.addLayout(rules_button_layout)
        
        layout.addWidget(rules_group)
        
        # Status
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        # Connect signals
        self.add_rule_button.clicked.connect(self._add_rule)
        self.enable_button.clicked.connect(self._enable_checked_rules)
        self.disable_button.clicked.connect(self._disable_checked_rules)
        self.delete_button.clicked.connect(self._delete_checked_rules)
        self.refresh_button.clicked.connect(self._load_rules)
    
    def _on_toggle_show_all(self, state):
        """Handle toggle between NetGuardian rules and all rules."""
        self._show_all_rules = state == Qt.Checked
        self._load_rules()
    
    def _start_worker(self, operation: str, **kwargs) -> FirewallWorker:
        """
        Start a firewall worker, retiring any previous one first.

        Keeping the reference in self._workers until finished() fires stops
        Python from collecting a QThread that is still running.
        """
        worker = FirewallWorker(operation, **kwargs)
        self._workers.append(worker)
        worker.finished.connect(lambda w=worker: self._retire_worker(w))
        worker.error_occurred.connect(self._on_error)
        self._worker = worker
        return worker

    def _retire_worker(self, worker: FirewallWorker):
        """Drop a finished worker."""
        if worker in self._workers:
            self._workers.remove(worker)
        worker.deleteLater()

    def _load_rules(self):
        """Load existing firewall rules."""
        self.status_label.setText("Loading rules...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        worker = self._start_worker("get_rules", show_all=self._show_all_rules)
        worker.rules_loaded.connect(self._on_rules_loaded)
        worker.operation_complete.connect(self.status_label.setText)
        worker.start()

    def _on_rules_loaded(self, rules, is_admin: bool):
        """
        Handle rules loaded.

        The rules arrive from the worker. The old version threw the worker's
        result away and re-ran the whole netsh dump here, on the GUI thread.
        """
        self.progress_bar.setVisible(False)
        self._rules = rules

        if not is_admin:
            self.admin_label.setText("Warning: Not running as administrator. Some operations may fail.")
        else:
            self.admin_label.setText("")

        self._update_rules_table()
    
    def _update_rules_table(self):
        """Update the rules table with current rules."""
        self.rules_table.setRowCount(0)
        
        for rule in self._rules:
            row = self.rules_table.rowCount()
            self.rules_table.insertRow(row)
            
            # Checkbox column
            check_item = QTableWidgetItem()
            check_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            check_item.setCheckState(Qt.Unchecked)
            
            # Remove prefix from name for display
            display_name = rule.name.replace(f"{FirewallManager.RULE_PREFIX} - ", "")
            is_netguardian = rule.name.startswith(FirewallManager.RULE_PREFIX)
            
            # If showing all rules, dim system rules
            if self._show_all_rules and not is_netguardian:
                check_item.setFlags(Qt.ItemIsEnabled)  # Cannot check system rules
                dim_color = Qt.gray
            else:
                dim_color = None
            
            self.rules_table.setItem(row, 0, check_item)
            
            name_item = QTableWidgetItem(display_name)
            action_item = QTableWidgetItem(rule.action)
            protocol_item = QTableWidgetItem(rule.protocol)
            port_item = QTableWidgetItem(rule.port)
            enabled_item = QTableWidgetItem("Yes" if rule.enabled else "No")
            
            # Apply dim color for system rules
            if dim_color:
                for item in [name_item, action_item, protocol_item, port_item, enabled_item]:
                    item.setForeground(dim_color)
            
            self.rules_table.setItem(row, 1, name_item)
            self.rules_table.setItem(row, 2, action_item)
            self.rules_table.setItem(row, 3, protocol_item)
            self.rules_table.setItem(row, 4, port_item)
            self.rules_table.setItem(row, 5, enabled_item)
    
    def _get_checked_rule_names(self) -> List[str]:
        """Get names of all checked rules."""
        checked_names = []
        
        for row in range(self.rules_table.rowCount()):
            check_item = self.rules_table.item(row, 0)
            if check_item and check_item.checkState() == Qt.Checked:
                name = self.rules_table.item(row, 1).text()
                checked_names.append(name)
        
        return checked_names
    
    def _check_all_rules(self):
        """Check all checkboxes for modifiable rules."""
        for row in range(self.rules_table.rowCount()):
            check_item = self.rules_table.item(row, 0)
            if check_item and check_item.flags() & Qt.ItemIsUserCheckable:
                check_item.setCheckState(Qt.Checked)
    
    def _uncheck_all_rules(self):
        """Uncheck all checkboxes."""
        for row in range(self.rules_table.rowCount()):
            check_item = self.rules_table.item(row, 0)
            if check_item:
                check_item.setCheckState(Qt.Unchecked)
    
    def _add_rule(self):
        """Add a new firewall rule."""
        name = self.rule_name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Please enter a rule name")
            return
        
        port = self.port_input.text().strip()
        if not port:
            QMessageBox.warning(self, "Error", "Please enter port(s)")
            return
        
        # Get values from UI
        action = self.action_combo.currentText()
        protocol = self.protocol_combo.currentText()
        direction = self.direction_combo.currentText()
        
        self.status_label.setText(f"Adding rule '{name}'...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        worker = self._start_worker(
            "add_rule",
            name=name,
            action=action,
            protocol=protocol,
            port=port,
            direction=direction,
            enabled=True
        )
        worker.operation_complete.connect(self._on_rule_added)
        worker.start()
    
    def _on_rule_added(self, message: str):
        """Handle rule added."""
        self.progress_bar.setVisible(False)
        self.status_label.setText(message)
        self.rule_name_input.clear()
        self.port_input.clear()
        self._load_rules()
    
    def _enable_checked_rules(self):
        """Enable all checked rules."""
        checked = self._get_checked_rule_names()
        if not checked:
            QMessageBox.warning(self, "Error", "Please check at least one rule to enable")
            return
        
        self.status_label.setText(f"Enabling {len(checked)} rule(s)...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self._batch_operation("enable_rule", checked)
    
    def _disable_checked_rules(self):
        """Disable all checked rules."""
        checked = self._get_checked_rule_names()
        if not checked:
            QMessageBox.warning(self, "Error", "Please check at least one rule to disable")
            return
        
        self.status_label.setText(f"Disabling {len(checked)} rule(s)...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self._batch_operation("disable_rule", checked)
    
    def _delete_checked_rules(self):
        """Delete all checked rules."""
        checked = self._get_checked_rule_names()
        if not checked:
            QMessageBox.warning(self, "Error", "Please check at least one rule to delete")
            return
        
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete {len(checked)} rule(s)?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        self.status_label.setText(f"Deleting {len(checked)} rule(s)...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self._batch_operation("delete_rule", checked)
    
    def _batch_operation(self, operation: str, rule_names: List[str]):
        """
        Perform an operation on multiple rules.

        The whole batch runs inside one worker. The previous version started a
        separate QThread per rule and chained them through signal callbacks.
        """
        worker = self._start_worker(
            "batch", batch_operation=operation, names=list(rule_names)
        )
        worker.operation_complete.connect(self._on_batch_complete)
        worker.error_occurred.connect(self._on_batch_complete)
        worker.start()

    def _on_batch_complete(self, message: str):
        """Handle a finished batch, successful or partial."""
        self.progress_bar.setVisible(False)
        self.status_label.setText(message)
        self._load_rules()


    def _on_error(self, error_message: str):
        """Handle error."""
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Error: {error_message}")
