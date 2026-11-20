"""Tests for per-device traffic accounting."""

import time

import pytest
from scapy.all import IP, TCP, Ether

from core.per_device_traffic import PerDeviceTrafficMonitor


LOCAL_IP = "192.168.15.10"


@pytest.fixture
def monitor():
    m = PerDeviceTrafficMonitor()
    m._local_ip = LOCAL_IP
    m._is_monitoring = True
    return m


def packet(src, dst, payload=b"x" * 100):
    return IP(src=src, dst=dst) / TCP() / payload


class TestPrnContract:
    """
    scapy prints whatever the prn callback returns.

    Returning True wrote a line to stdout for every captured packet: 12,449
    lines in one short session, each a blocking write holding the GIL.
    """

    def test_returns_none_for_a_tracked_packet(self, monitor):
        assert monitor._process_packet(packet(LOCAL_IP, "8.8.8.8")) is None

    def test_returns_none_for_a_non_ip_packet(self, monitor):
        assert monitor._process_packet(Ether()) is None

    def test_returns_none_when_stopped(self, monitor):
        monitor._is_monitoring = False
        assert monitor._process_packet(packet(LOCAL_IP, "8.8.8.8")) is None

    def test_returns_none_for_third_party_traffic(self, monitor):
        assert monitor._process_packet(packet("10.0.0.1", "10.0.0.2")) is None

    def test_prints_nothing(self, monitor, capsys):
        for _ in range(50):
            monitor._process_packet(packet(LOCAL_IP, "8.8.8.8"))
        captured = capsys.readouterr()
        assert captured.out == "", f"prn callback wrote to stdout: {captured.out[:80]!r}"


class TestDirectionAccounting:
    def test_outgoing_counts_as_sent(self, monitor):
        monitor._process_packet(packet(LOCAL_IP, "8.8.8.8"))
        assert monitor._current_period[LOCAL_IP]["bytes_sent"] > 0
        assert monitor._current_period[LOCAL_IP]["bytes_recv"] == 0

    def test_incoming_counts_as_received(self, monitor):
        monitor._process_packet(packet("8.8.8.8", LOCAL_IP))
        assert monitor._current_period[LOCAL_IP]["bytes_recv"] > 0
        assert monitor._current_period[LOCAL_IP]["bytes_sent"] == 0

    def test_third_party_traffic_ignored(self, monitor):
        monitor._process_packet(packet("10.0.0.1", "10.0.0.2"))
        assert monitor._current_period == {}

    def test_non_ip_packet_ignored(self, monitor):
        monitor._process_packet(Ether())
        assert monitor._current_period == {}

    def test_ignored_entirely_when_stopped(self, monitor):
        monitor._is_monitoring = False
        monitor._process_packet(packet(LOCAL_IP, "8.8.8.8"))
        assert monitor._current_period == {}

    def test_both_ends_counted_when_local_ip_unknown(self, monitor):
        monitor._local_ip = None
        monitor._process_packet(packet("10.0.0.1", "10.0.0.2"))
        assert set(monitor._current_period) == {"10.0.0.1", "10.0.0.2"}


class TestStaleEviction:
    def test_stale_ip_clears_both_period_maps(self, monitor):
        """
        Leaving a stale entry in _last_period made a returning device get
        diffed against an old, larger total and report no traffic.
        """
        from core import per_device_traffic

        monitor._process_packet(packet(LOCAL_IP, "8.8.8.8"))
        monitor.update()
        assert LOCAL_IP in monitor._last_period

        # Age the entry past the eviction threshold
        monitor._current_period[LOCAL_IP]["last_seen"] = (
            time.time() - per_device_traffic.STALE_AFTER_SECONDS - 1
        )
        monitor.update()

        assert LOCAL_IP not in monitor._current_period
        assert LOCAL_IP not in monitor._last_period

    def test_returning_device_reports_traffic_again(self, monitor):
        from core import per_device_traffic

        for _ in range(10):
            monitor._process_packet(packet(LOCAL_IP, "8.8.8.8"))
        monitor.update()

        monitor._current_period[LOCAL_IP]["last_seen"] = (
            time.time() - per_device_traffic.STALE_AFTER_SECONDS - 1
        )
        monitor.update()

        # Device comes back
        for _ in range(10):
            monitor._process_packet(packet(LOCAL_IP, "8.8.8.8"))
        results = monitor.update()

        entry = next(r for r in results if r.ip == LOCAL_IP)
        assert entry.upload_speed > 0, "returning device reported zero traffic"


class TestUpdate:
    def test_speeds_are_never_negative(self, monitor):
        monitor._process_packet(packet(LOCAL_IP, "8.8.8.8"))
        for entry in monitor.update():
            assert entry.upload_speed >= 0
            assert entry.download_speed >= 0

    def test_sorted_by_total_traffic(self, monitor):
        monitor._local_ip = None
        monitor._process_packet(packet("10.0.0.1", "10.0.0.2", b"x" * 1000))
        monitor._process_packet(packet("10.0.0.3", "10.0.0.4", b"x" * 10))
        results = monitor.update()
        totals = [r.bytes_sent + r.bytes_recv for r in results]
        assert totals == sorted(totals, reverse=True)

    def test_empty_when_nothing_captured(self, monitor):
        assert monitor.update() == []
