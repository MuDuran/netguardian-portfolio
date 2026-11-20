"""
NetGuardian - Home Network Management Desktop Application
Main entry point for the application.
"""

import ctypes
import logging
import os
import subprocess
import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
    QLabel, QStatusBar, QMenuBar, QMenu, QMessageBox
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QAction, QIcon

import config
from core.activity_logger import ActivityLogger
from utils.timing import perf_summary

logger = logging.getLogger(__name__)

# Import tab widgets
from ui.device_discovery_tab import DeviceDiscoveryTab
from ui.traffic_monitoring_tab import TrafficMonitoringTab
from ui.port_scanner_tab import PortScannerTab
from ui.modem_status_tab import ModemStatusTab
from ui.firewall_manager_tab import FirewallManagerTab
from ui.activity_logs_tab import ActivityLogsTab


def is_frozen() -> bool:
    """Whether we are running from a PyInstaller bundle."""
    return getattr(sys, "frozen", False)


def is_admin():
    """Check if the application is running with administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def request_admin_elevation():
    """
    Request administrator privileges by restarting the application with UAC elevation.

    This function will trigger a UAC prompt asking the user to allow admin access.
    If the user accepts, the application restarts with admin privileges.
    If the user declines, the application continues without admin rights.
    """
    if is_admin():
        return True

    # Relaunching differs between the two ways this app runs. Frozen, the exe
    # IS the target and there is no script path to pass; from source, we relaunch
    # the interpreter with main.py. The old code always did the second form,
    # which produced a broken command line inside a PyInstaller bundle.
    if is_frozen():
        target = sys.executable
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        target = sys.executable
        params = subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:])

    try:
        # verb "runas" requests elevation (triggers the UAC prompt)
        result = ctypes.windll.shell32.ShellExecuteW(
            None,      # Parent window handle
            "runas",   # Verb (run as administrator)
            target,    # Application to run
            params,    # Arguments
            None,      # Working directory
            1          # SW_SHOWNORMAL (show the window)
        )

        # ShellExecuteW returns <= 32 on failure, including when the user
        # declines the UAC prompt. Carry on unelevated rather than exiting.
        if result <= 32:
            logger.warning(f"Elevation declined or failed (code {result})")
            return False

        # Elevated instance is starting; this one steps aside.
        sys.exit(0)

    except OSError as e:
        logger.warning(f"Admin elevation failed: {e}")
        logger.warning(
            "Some features (Firewall Manager, packet capture) will not work "
            "without administrator privileges."
        )
        return False


class MainWindow(QMainWindow):
    """Main application window with tabbed navigation."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(config.WINDOW_TITLE)
        self.setMinimumSize(QSize(config.WINDOW_MIN_WIDTH, config.WINDOW_MIN_HEIGHT))
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs for each feature
        self._create_tabs()
        
        # Create menu bar
        self._create_menu_bar()
        
        # Create status bar
        self._create_status_bar()
    
    def _create_tabs(self):
        """Create tabs for all 6 features using actual tab widgets."""
        self.device_discovery_tab = DeviceDiscoveryTab()
        self.traffic_monitoring_tab = TrafficMonitoringTab()
        self.port_scanner_tab = PortScannerTab()
        self.modem_status_tab = ModemStatusTab()
        self.firewall_manager_tab = FirewallManagerTab()
        self.activity_logs_tab = ActivityLogsTab()

        for tab, title in (
            (self.device_discovery_tab, "🔍 Device Discovery"),
            (self.traffic_monitoring_tab, "📊 Traffic Monitoring"),
            (self.port_scanner_tab, "🔌 Port Scanner"),
            (self.modem_status_tab, "📡 Modem Status"),
            (self.firewall_manager_tab, "🛡️ Firewall Manager"),
            (self.activity_logs_tab, "📋 Activity Logs"),
        ):
            self.tab_widget.addTab(tab, title)

    def closeEvent(self, event):
        """
        Shut down cleanly.

        Each tab owns background threads and timers; without this the scapy
        sniffer and firewall workers outlived the window. Tabs define
        cleanup() only if they have something to release.
        """
        for index in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(index)
            cleanup = getattr(tab, "cleanup", None)
            if callable(cleanup):
                try:
                    cleanup()
                except Exception as e:
                    logger.warning(f"Cleanup failed for {type(tab).__name__}: {e}")

        try:
            ActivityLogger.instance().close()
        except Exception as e:
            logger.debug(f"Could not close activity logger: {e}")

        if config.PERF_LOGGING:
            print(perf_summary(), file=sys.stderr)

        super().closeEvent(event)
    
    def _create_menu_bar(self):
        """Create the menu bar with File, Tools, and Help menus."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        # Exit action
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        # Scan Network action
        scan_action = QAction("&Scan Network", self)
        scan_action.setShortcut("Ctrl+S")
        scan_action.triggered.connect(self._on_scan_network)
        tools_menu.addAction(scan_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        # About action
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)
    
    def _create_status_bar(self):
        """Create the status bar at the bottom of the window."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def _on_scan_network(self):
        """Handle Scan Network action by driving the Device Discovery tab."""
        self.tab_widget.setCurrentWidget(self.device_discovery_tab)
        self.device_discovery_tab.start_scan()
        self.status_bar.showMessage("Scanning network...")

    def _on_about(self):
        """Show About dialog."""
        QMessageBox.about(
            self,
            "About NetGuardian",
            "<h3>NetGuardian</h3>"
            "<p>Home Network Management Desktop Application</p>"
            f"<p>Version: {config.APP_VERSION}</p>"
            "<p>A powerful tool for monitoring and managing your home network.</p>"
        )


def main():
    """Main entry point for the application."""
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format=config.LOG_FORMAT,
    )

    # --no-elevate skips the UAC prompt. Useful for testing the unelevated
    # path, and for launching without an interactive prompt. Firewall writes
    # and packet capture will not work in that mode.
    if "--no-elevate" in sys.argv:
        logger.info("Starting without elevation (--no-elevate)")
    else:
        request_admin_elevation()

    # Keep the audit log from growing without bound.
    try:
        ActivityLogger.instance().prune()
    except Exception as e:
        logger.warning(f"Could not prune activity log: {e}")

    app = QApplication(sys.argv)
    app.setApplicationName(config.APP_NAME)
    app.setApplicationVersion(config.APP_VERSION)
    app.setOrganizationName(config.APP_NAME)

    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
