"""Tests for network calculation and hostname resolution in the device scanner."""

import socket
import time

import pytest

from core.device_scanner import DeviceScanner


@pytest.fixture
def scanner():
    return DeviceScanner(timeout=1)


class TestCalculateNetwork:
    @pytest.mark.parametrize("ip,netmask,expected", [
        ("192.168.15.42", "255.255.255.0", "192.168.15.0/24"),
        ("192.168.1.1", "255.255.255.0", "192.168.1.0/24"),
        ("10.0.5.7", "255.255.0.0", "10.0.0.0/16"),
        ("172.16.30.9", "255.255.255.128", "172.16.30.0/25"),
        ("192.168.1.66", "255.255.255.192", "192.168.1.64/26"),
    ])
    def test_respects_the_actual_netmask(self, scanner, ip, netmask, expected):
        # The old implementation hardcoded /24 regardless of the mask.
        assert scanner._calculate_network(ip, netmask) == expected

    def test_oversized_network_is_narrowed(self, scanner):
        # A /8 ARP sweep is 16M hosts; not practical.
        assert scanner._calculate_network("10.0.5.7", "255.0.0.0") == "10.0.5.0/24"

    @pytest.mark.parametrize("ip,netmask", [
        ("not-an-ip", "255.255.255.0"),
        ("192.168.1.1", "not-a-mask"),
        ("", ""),
    ])
    def test_falls_back_on_bad_input(self, scanner, ip, netmask):
        assert scanner._calculate_network(ip, netmask) == "192.168.1.0/24"


class TestHostnameResolution:
    def test_cache_prevents_repeat_lookups(self, scanner, monkeypatch):
        calls = []

        def fake_gethostbyaddr(ip):
            calls.append(ip)
            return ("host.example", [], [ip])

        monkeypatch.setattr(socket, "gethostbyaddr", fake_gethostbyaddr)

        assert scanner._get_hostname("192.0.2.1") == "host.example"
        assert scanner._get_hostname("192.0.2.1") == "host.example"
        assert len(calls) == 1

    def test_failure_is_cached_as_unknown(self, scanner, monkeypatch):
        def always_fails(ip):
            raise socket.herror("no PTR record")

        monkeypatch.setattr(socket, "gethostbyaddr", always_fails)
        assert scanner._get_hostname("192.0.2.2") == "Unknown"

    def test_empty_batch(self, scanner):
        assert scanner._resolve_hostnames([]) == {}

    def test_batch_returns_entry_for_every_ip(self, scanner, monkeypatch):
        monkeypatch.setattr(
            socket, "gethostbyaddr",
            lambda ip: (f"host-{ip.split('.')[-1]}", [], [ip])
        )
        ips = [f"192.0.2.{i}" for i in range(1, 11)]
        result = scanner._resolve_hostnames(ips)

        assert set(result) == set(ips)
        assert result["192.0.2.5"] == "host-5"

    def test_slow_lookups_hit_the_deadline_not_the_sum(self, scanner, monkeypatch):
        # Ten lookups that each block for 1s must finish in roughly the batch
        # deadline, not 10s. This is the whole point of resolving in parallel.
        def slow(ip):
            time.sleep(1.0)
            return (f"host-{ip}", [], [ip])

        monkeypatch.setattr(socket, "gethostbyaddr", slow)

        started = time.perf_counter()
        result = scanner._resolve_hostnames([f"192.0.2.{i}" for i in range(1, 11)])
        elapsed = time.perf_counter() - started

        assert elapsed < 3.0, f"took {elapsed:.1f}s; lookups are not concurrent"
        assert len(result) == 10

    def test_unresolvable_ips_do_not_block_forever(self, scanner, monkeypatch):
        from core import device_scanner

        def hangs(ip):
            time.sleep(30)
            return ("never", [], [ip])

        monkeypatch.setattr(socket, "gethostbyaddr", hangs)
        monkeypatch.setattr(device_scanner, "HOSTNAME_BATCH_TIMEOUT", 0.5)

        started = time.perf_counter()
        result = scanner._resolve_hostnames(["192.0.2.99"])
        elapsed = time.perf_counter() - started

        assert elapsed < 3.0
        assert result["192.0.2.99"] == "Unknown"
