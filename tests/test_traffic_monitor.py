"""Tests for traffic monitoring speed calculation."""

import time
from collections import namedtuple

import pytest

from core.traffic_monitor import InterfaceSpeedTracker, TrafficMonitor

FakeCounters = namedtuple(
    "FakeCounters", "bytes_sent bytes_recv packets_sent packets_recv"
)


class TestInterfaceSpeedTracker:
    def test_first_sample_reports_zero(self, monkeypatch):
        import psutil
        monkeypatch.setattr(
            psutil, "net_io_counters",
            lambda pernic=False: {"eth0": FakeCounters(1000, 2000, 10, 20)}
        )
        result = InterfaceSpeedTracker().sample()
        assert result[0]["upload_speed"] == 0.0
        assert result[0]["download_speed"] == 0.0

    def test_second_sample_computes_delta(self, monkeypatch):
        import psutil
        state = {"n": 0}

        def counters(pernic=False):
            state["n"] += 1
            sent = 1000 * state["n"]
            return {"eth0": FakeCounters(sent, sent * 2, 10, 20)}

        monkeypatch.setattr(psutil, "net_io_counters", counters)

        tracker = InterfaceSpeedTracker()
        tracker.sample()
        time.sleep(0.05)
        result = tracker.sample()

        # 1000 bytes over ~0.05s is a large but positive rate
        assert result[0]["upload_speed"] > 0
        assert result[0]["download_speed"] > result[0]["upload_speed"]

    def test_does_not_block(self, monkeypatch):
        import psutil
        monkeypatch.setattr(
            psutil, "net_io_counters",
            lambda pernic=False: {"eth0": FakeCounters(1, 1, 1, 1)}
        )
        tracker = InterfaceSpeedTracker()
        tracker.sample()

        started = time.perf_counter()
        tracker.sample()
        elapsed = time.perf_counter() - started

        # The old implementation slept 100ms inside this call.
        assert elapsed < 0.05, f"sample() blocked for {elapsed * 1000:.0f}ms"

    def test_counter_reset_does_not_produce_negative_speed(self, monkeypatch):
        import psutil
        state = {"n": 0}

        def counters(pernic=False):
            state["n"] += 1
            # Second reading is lower, as after an interface reset
            value = 10_000 if state["n"] == 1 else 5
            return {"eth0": FakeCounters(value, value, 1, 1)}

        monkeypatch.setattr(psutil, "net_io_counters", counters)

        tracker = InterfaceSpeedTracker()
        tracker.sample()
        result = tracker.sample()

        assert result[0]["upload_speed"] >= 0
        assert result[0]["download_speed"] >= 0

    def test_new_interface_appearing_midstream(self, monkeypatch):
        import psutil
        state = {"n": 0}

        def counters(pernic=False):
            state["n"] += 1
            data = {"eth0": FakeCounters(100, 100, 1, 1)}
            if state["n"] > 1:
                data["wlan0"] = FakeCounters(50, 50, 1, 1)
            return data

        monkeypatch.setattr(psutil, "net_io_counters", counters)

        tracker = InterfaceSpeedTracker()
        tracker.sample()
        result = tracker.sample()

        names = {r["name"] for r in result}
        assert names == {"eth0", "wlan0"}
        wlan = next(r for r in result if r["name"] == "wlan0")
        assert wlan["upload_speed"] == 0.0  # no baseline to diff against


class TestFormatting:
    @pytest.mark.parametrize("value,expected", [
        (0, "0.00 B/s"),
        (512, "512.00 B/s"),
        (1024, "1.00 KB/s"),
        (1024 * 1024, "1.00 MB/s"),
        (1024 * 1024 * 1024, "1.00 GB/s"),
    ])
    def test_format_speed(self, value, expected):
        assert TrafficMonitor.format_speed(value) == expected

    @pytest.mark.parametrize("value,expected", [
        (0, "0 B"),
        (1024, "1.00 KB"),
        (1024 * 1024, "1.00 MB"),
    ])
    def test_format_bytes(self, value, expected):
        assert TrafficMonitor.format_bytes(value) == expected


class TestStopIsIdempotent:
    """
    stop() is called unconditionally by cleanup(), so it must be quiet and
    safe when monitoring was never started. Otherwise the logs claim sniffing
    ran when it did not.
    """

    def test_stop_without_start_logs_nothing(self, caplog):
        import logging
        monitor = TrafficMonitor()
        with caplog.at_level(logging.INFO, logger="core.traffic_monitor"):
            monitor.stop()
        assert "stopped" not in caplog.text.lower()

    def test_stop_after_start_does_log(self, caplog):
        import logging
        monitor = TrafficMonitor()
        monitor.start()
        with caplog.at_level(logging.INFO, logger="core.traffic_monitor"):
            monitor.stop()
        assert "stopped" in caplog.text.lower()

    def test_double_stop_is_safe(self):
        monitor = TrafficMonitor()
        monitor.start()
        monitor.stop()
        monitor.stop()
        assert monitor.is_monitoring is False


class TestPerDeviceStopIsIdempotent:
    def test_stop_without_start_logs_nothing(self, caplog):
        import logging
        from core.per_device_traffic import PerDeviceTrafficMonitor
        monitor = PerDeviceTrafficMonitor()
        with caplog.at_level(logging.INFO, logger="core.per_device_traffic"):
            monitor.stop()
        assert "stopped" not in caplog.text.lower()

    def test_double_stop_is_safe(self):
        from core.per_device_traffic import PerDeviceTrafficMonitor
        monitor = PerDeviceTrafficMonitor()
        monitor.stop()
        monitor.stop()
        assert monitor.is_monitoring is False
