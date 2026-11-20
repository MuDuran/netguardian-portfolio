"""
Headless GUI smoke tests.

These run Qt with the offscreen platform plugin, so they exercise the real
widget construction and signal wiring without needing a display. They cover
the parts that unit tests cannot: that tabs build, that timers and workers
start and stop cleanly, and that closing the window releases everything.

They deliberately do not require admin rights. Anything needing elevation
(firewall writes, packet capture) degrades to a no-op and is skipped.
"""

import os

import pytest

# Must be set before QApplication is created.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    """One QApplication for the whole session; Qt allows only one."""
    app = QApplication.instance() or QApplication([])
    yield app


def pump(app, ms=250):
    """Let the event loop run briefly so queued signals are delivered."""
    from PySide6.QtCore import QDeadlineTimer, QEventLoop
    deadline = QDeadlineTimer(ms)
    while not deadline.hasExpired():
        app.processEvents(QEventLoop.AllEvents, 20)


class TestTabConstruction:
    """Every tab must build without raising."""

    def test_device_discovery_tab(self, qapp):
        from ui.device_discovery_tab import DeviceDiscoveryTab
        tab = DeviceDiscoveryTab()
        assert tab.device_table.columnCount() == 6
        tab.cleanup()

    def test_traffic_monitoring_tab(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        # _refresh_interfaces runs in __init__ and must have populated the combo
        assert tab.interface_combo.count() >= 1
        assert tab.interface_combo.itemText(0) == "All Interfaces"
        tab.cleanup()

    def test_port_scanner_tab(self, qapp):
        from ui.port_scanner_tab import PortScannerTab
        tab = PortScannerTab()
        assert tab.results_table.columnCount() == 6
        tab.cleanup()

    def test_modem_status_tab(self, qapp):
        from ui.modem_status_tab import ModemStatusTab
        tab = ModemStatusTab()
        tab.cleanup()

    def test_firewall_manager_tab(self, qapp):
        from ui.firewall_manager_tab import FirewallManagerTab
        tab = FirewallManagerTab()
        pump(qapp, 2000)  # let the rule-loading worker finish
        tab.cleanup()

    def test_activity_logs_tab(self, qapp):
        from ui.activity_logs_tab import ActivityLogsTab
        tab = ActivityLogsTab()
        assert tab.log_table.columnCount() >= 4


class TestInterfaceSelection:
    """
    The combo box regression: repopulating must not look like a user change.

    This is the bug that silently restarted monitoring every 5 seconds.
    """

    def test_selection_survives_refresh(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        try:
            if tab.interface_combo.count() < 2:
                pytest.skip("no real interfaces available")

            tab.interface_combo.setCurrentIndex(1)
            chosen = tab._selected_interface()
            assert chosen is not None

            # Refresh several times; the label text changes as speeds move.
            for _ in range(5):
                tab._refresh_interfaces()

            assert tab._selected_interface() == chosen
        finally:
            tab.cleanup()

    def test_refresh_does_not_emit_interface_changed(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        try:
            fired = []
            tab.interface_combo.currentTextChanged.connect(fired.append)
            tab._refresh_interfaces()
            assert fired == [], f"refresh emitted {len(fired)} spurious change(s)"
        finally:
            tab.cleanup()

    def test_selected_interface_is_none_for_all(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        try:
            tab.interface_combo.setCurrentIndex(0)
            assert tab._selected_interface() is None
        finally:
            tab.cleanup()

    def test_interface_name_not_parsed_from_label(self, qapp):
        """An interface whose name contains ' (' must still resolve correctly."""
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        try:
            tricky = "Ethernet (Realtek) #2"
            tab.interface_combo.addItem(f"{tricky} (0 B/s)", tricky)
            tab.interface_combo.setCurrentIndex(tab.interface_combo.count() - 1)
            assert tab._selected_interface() == tricky
        finally:
            tab.cleanup()


class TestMonitoringLifecycle:
    def test_start_and_stop(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        try:
            tab._start_monitoring()
            assert tab._monitor.is_monitoring is True
            pump(qapp, 300)
            tab._stop_monitoring()
            assert tab._monitor.is_monitoring is False
        finally:
            tab.cleanup()

    def test_graph_accumulates_samples(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        try:
            tab._start_monitoring()
            for _ in range(5):
                tab._update_monitoring()
            assert len(tab._time_data) == 5
            # x axis must advance monotonically, not restart
            assert tab._time_data == sorted(tab._time_data)
            assert len(set(tab._time_data)) == 5
        finally:
            tab._stop_monitoring()
            tab.cleanup()

    def test_graph_buffer_is_bounded(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        try:
            tab._start_monitoring()
            for _ in range(tab._max_points + 25):
                tab._update_monitoring()
            assert len(tab._time_data) == tab._max_points
            # and it still advances after trimming
            assert tab._time_data == sorted(tab._time_data)
        finally:
            tab._stop_monitoring()
            tab.cleanup()

    def test_cleanup_is_idempotent(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        tab = TrafficMonitoringTab()
        tab.cleanup()
        tab.cleanup()


class TestPerDeviceTable:
    def test_updates_in_place_without_rebuilding(self, qapp):
        """
        Rows must be reused across updates, not destroyed and recreated.

        Recreating them each second is what threw away selection and scroll.
        """
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        from core.per_device_traffic import DeviceTraffic

        tab = TrafficMonitoringTab()
        try:
            sample = [
                DeviceTraffic("192.0.2.1", "host-a", "Device A", 100, 200, 10, 20, 0),
                DeviceTraffic("192.0.2.2", "host-b", "Device B", 300, 400, 30, 40, 0),
            ]
            tab._per_device_monitor.update = lambda: sample

            tab._update_per_device()
            assert tab.per_device_table.rowCount() == 2
            first_item = tab.per_device_table.item(0, 0)

            tab._update_per_device()
            # Same QTableWidgetItem object means the row was reused
            assert tab.per_device_table.item(0, 0) is first_item
        finally:
            tab.cleanup()

    def test_shrinking_list_removes_rows(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        from core.per_device_traffic import DeviceTraffic

        tab = TrafficMonitoringTab()
        try:
            rows = [
                DeviceTraffic(f"192.0.2.{i}", "h", "D", 1, 1, 1, 1, 0)
                for i in range(5)
            ]
            tab._per_device_monitor.update = lambda: rows
            tab._update_per_device()
            assert tab.per_device_table.rowCount() == 5

            tab._per_device_monitor.update = lambda: rows[:2]
            tab._update_per_device()
            assert tab.per_device_table.rowCount() == 2
        finally:
            tab.cleanup()

    def test_falls_back_through_name_then_hostname_then_ip(self, qapp):
        from ui.traffic_monitoring_tab import TrafficMonitoringTab
        from core.per_device_traffic import DeviceTraffic

        tab = TrafficMonitoringTab()
        try:
            tab._per_device_monitor.update = lambda: [
                DeviceTraffic("192.0.2.1", "known-host", "Unknown", 0, 0, 0, 0, 0),
                DeviceTraffic("192.0.2.2", "Unknown", "Unknown", 0, 0, 0, 0, 0),
            ]
            tab._update_per_device()
            assert tab.per_device_table.item(0, 0).text() == "known-host"
            assert tab.per_device_table.item(1, 0).text() == "192.0.2.2"
        finally:
            tab.cleanup()


class TestPortScannerValidationInUi:
    """Invalid input must be reported in the UI, not raised or sent to nmap."""

    def test_bad_target_shows_error_and_starts_no_worker(self, qapp):
        from ui.port_scanner_tab import PortScannerTab
        tab = PortScannerTab()
        try:
            tab.target_input.setText("192.168.1.1; rm -rf /")
            tab._start_scan()
            assert "Error" in tab.status_label.text()
            assert tab._worker is None
            assert tab.scan_button.isEnabled()
        finally:
            tab.cleanup()

    def test_empty_target_shows_error(self, qapp):
        from ui.port_scanner_tab import PortScannerTab
        tab = PortScannerTab()
        try:
            tab.target_input.setText("")
            tab._start_scan()
            assert "Error" in tab.status_label.text()
            assert tab._worker is None
        finally:
            tab.cleanup()

    def test_backwards_port_range_shows_error(self, qapp):
        from ui.port_scanner_tab import PortScannerTab
        tab = PortScannerTab()
        try:
            tab.target_input.setText("127.0.0.1")
            tab.port_start.setValue(1000)
            tab.port_end.setValue(100)
            tab._start_scan()
            assert "Error" in tab.status_label.text()
            assert tab._worker is None
        finally:
            tab.cleanup()


class TestFirewallTabWiring:
    def test_rules_arrive_through_the_signal(self, qapp):
        """
        The worker must deliver the rules; the GUI thread must not refetch.

        This is the double-fetch regression.
        """
        from ui.firewall_manager_tab import FirewallManagerTab
        from core.firewall_manager import FirewallManager

        calls = []
        original = FirewallManager._fetch_rules

        def counted(self, netguardian_only):
            calls.append(netguardian_only)
            return original(self, netguardian_only)

        FirewallManager._fetch_rules = counted
        try:
            tab = FirewallManagerTab()
            pump(qapp, 3000)
            tab.cleanup()
        finally:
            FirewallManager._fetch_rules = original

        assert len(calls) == 1, (
            f"expected 1 netsh fetch per load, got {len(calls)} "
            "(the GUI-thread refetch is back)"
        )

    def test_admin_check_makes_no_subprocess(self, qapp):
        import subprocess
        from core.firewall_manager import FirewallManager

        FirewallManager._admin_cache = None
        spawned = []
        original = subprocess.run
        subprocess.run = lambda *a, **k: spawned.append(a) or original(*a, **k)
        try:
            FirewallManager._check_admin_privileges()
        finally:
            subprocess.run = original
        assert spawned == [], "admin check is still shelling out"

    def test_admin_result_is_cached(self, qapp):
        from core.firewall_manager import FirewallManager
        FirewallManager._admin_cache = None
        first = FirewallManager._check_admin_privileges()
        assert FirewallManager._check_admin_privileges() is first


class TestMainWindow:
    def test_builds_with_all_tabs(self, qapp):
        from main import MainWindow
        window = MainWindow()
        try:
            assert window.tab_widget.count() == 6
        finally:
            window.close()

    def test_close_event_cleans_up_every_tab(self, qapp):
        from main import MainWindow
        window = MainWindow()
        pump(qapp, 2000)

        cleaned = []
        for i in range(window.tab_widget.count()):
            tab = window.tab_widget.widget(i)
            if hasattr(tab, "cleanup"):
                original = tab.cleanup
                tab.cleanup = lambda t=type(tab).__name__, o=original: (
                    cleaned.append(t), o()
                )[1]

        window.close()
        assert len(cleaned) == 5, f"only cleaned up {cleaned}"

    def test_close_survives_a_failing_cleanup(self, qapp):
        """One tab raising must not prevent the others from being cleaned."""
        from main import MainWindow
        window = MainWindow()
        pump(qapp, 2000)

        def boom():
            raise RuntimeError("simulated cleanup failure")

        window.device_discovery_tab.cleanup = boom
        cleaned = []
        original = window.port_scanner_tab.cleanup
        window.port_scanner_tab.cleanup = lambda: (cleaned.append(1), original())[1]

        window.close()  # must not raise
        assert cleaned == [1]

    def test_scan_network_menu_action_is_wired(self, qapp, monkeypatch):
        """The menu item used to pop a 'will be implemented in Phase 1!' box."""
        from main import MainWindow
        window = MainWindow()
        try:
            started = []
            monkeypatch.setattr(
                window.device_discovery_tab, "start_scan",
                lambda: started.append(True)
            )
            window._on_scan_network()
            assert started == [True]
            assert window.tab_widget.currentWidget() is window.device_discovery_tab
        finally:
            window.close()


class TestElevation:
    def test_frozen_build_passes_no_script_path(self, monkeypatch):
        """
        Under PyInstaller the exe is the target; there is no main.py to pass.

        The old code always passed a script path, producing a broken command
        line inside a bundle.
        """
        import main

        captured = {}

        def fake_shell_execute(hwnd, verb, target, params, cwd, show):
            captured["target"] = target
            captured["params"] = params
            return 42  # > 32 means success

        monkeypatch.setattr(main, "is_admin", lambda: False)
        monkeypatch.setattr(main, "is_frozen", lambda: True)
        monkeypatch.setattr(main.sys, "argv", ["NetGuardian.exe"])
        monkeypatch.setattr(
            main.ctypes.windll.shell32, "ShellExecuteW", fake_shell_execute
        )

        with pytest.raises(SystemExit):
            main.request_admin_elevation()

        assert "main.py" not in captured["params"]

    def test_source_run_passes_the_script(self, monkeypatch):
        import main

        captured = {}

        def fake_shell_execute(hwnd, verb, target, params, cwd, show):
            captured["params"] = params
            return 42

        monkeypatch.setattr(main, "is_admin", lambda: False)
        monkeypatch.setattr(main, "is_frozen", lambda: False)
        monkeypatch.setattr(main.sys, "argv", ["main.py"])
        monkeypatch.setattr(
            main.ctypes.windll.shell32, "ShellExecuteW", fake_shell_execute
        )

        with pytest.raises(SystemExit):
            main.request_admin_elevation()

        assert "main.py" in captured["params"]

    def test_declined_prompt_continues_unelevated(self, monkeypatch):
        """Declining UAC must not kill the app."""
        import main

        monkeypatch.setattr(main, "is_admin", lambda: False)
        monkeypatch.setattr(main, "is_frozen", lambda: False)
        monkeypatch.setattr(
            main.ctypes.windll.shell32, "ShellExecuteW",
            lambda *a: 5  # SE_ERR_ACCESSDENIED: user said no
        )

        assert main.request_admin_elevation() is False

    def test_already_admin_is_a_no_op(self, monkeypatch):
        import main
        monkeypatch.setattr(main, "is_admin", lambda: True)
        assert main.request_admin_elevation() is True


class TestSingleDatabaseConnection:
    """
    The whole app must share one ActivityLogger.

    A second instance opens a second connection to the same database, and
    closeEvent only closes the shared one.
    """

    def test_logs_tab_uses_the_shared_instance(self, qapp):
        from core.activity_logger import ActivityLogger
        from ui.activity_logs_tab import ActivityLogsTab

        tab = ActivityLogsTab()
        assert tab._logger is ActivityLogger.instance()

    def test_startup_initializes_the_database_once(self, qapp, caplog):
        import logging
        from core.activity_logger import ActivityLogger
        from main import MainWindow

        # Force a clean singleton so the count is meaningful.
        if ActivityLogger._instance is not None:
            ActivityLogger._instance.close()
            ActivityLogger._instance = None

        with caplog.at_level(logging.INFO, logger="core.activity_logger"):
            ActivityLogger.instance()
            window = MainWindow()
            try:
                pump(qapp, 1500)
            finally:
                window.close()

        initializations = [
            r for r in caplog.records
            if "Activity logger initialized" in r.getMessage()
        ]
        assert len(initializations) == 1, (
            f"database opened {len(initializations)} times; "
            "something is bypassing ActivityLogger.instance()"
        )
