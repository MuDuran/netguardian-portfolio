"""Tests for port scanner input validation and argument building."""

import pytest

from core.port_scanner import (
    COMMON_PORTS,
    InvalidScanTarget,
    PortScanner,
    validate_ports,
    validate_target,
)


class TestValidateTarget:
    @pytest.mark.parametrize("target", [
        "192.168.1.1",
        "10.0.0.1",
        "192.168.1.0/24",
        "10.0.0.0/8",
        "::1",
        "2001:db8::1",
        "example.com",
        "my-nas.local",
        "localhost",
    ])
    def test_accepts_valid_targets(self, target):
        assert validate_target(target) == target

    def test_strips_surrounding_whitespace(self):
        assert validate_target("  192.168.1.1  ") == "192.168.1.1"

    @pytest.mark.parametrize("target", [
        "",
        "   ",
        "192.168.1.1 -oX /tmp/out",       # extra nmap flag
        "192.168.1.1; rm -rf /",          # shell metacharacters
        "--script=http-vuln",             # flag masquerading as a target
        "192.168.1.1 --script vuln",
        "host name with spaces",
        "-oN -",
    ])
    def test_rejects_injection_and_junk(self, target):
        with pytest.raises(InvalidScanTarget):
            validate_target(target)


class TestValidatePorts:
    @pytest.mark.parametrize("spec,expected", [
        ("80", "80"),
        ("80,443", "80,443"),
        ("1-1024", "1-1024"),
        ("22,80,443,8000-8100", "22,80,443,8000-8100"),
        ("1-65535", "1-65535"),
        (" 80 , 443 ", "80,443"),
        ("80-80", "80-80"),
    ])
    def test_accepts_valid_specs(self, spec, expected):
        assert validate_ports(spec) == expected

    @pytest.mark.parametrize("spec", [
        "",
        "0",              # below range
        "65536",          # above range
        "100-2",          # backwards
        "80 --script x",  # injected flag
        "80;443",
        "abc",
        "80,",
        "-100",
    ])
    def test_rejects_invalid_specs(self, spec):
        with pytest.raises(InvalidScanTarget):
            validate_ports(spec)

    def test_common_ports_constant_is_valid(self):
        assert validate_ports(COMMON_PORTS) == COMMON_PORTS

    def test_common_ports_has_100_entries(self):
        assert len(COMMON_PORTS.split(",")) == 100


class TestScanArguments:
    def _build(self, scan_type, service_detection):
        return PortScanner._build_scan_arguments(
            None, scan_type, service_detection
        )

    def test_does_not_emit_normal_output_flag(self):
        # python-nmap already runs nmap with "-oX -"; a second output flag
        # interleaves plain text into the XML it parses.
        assert "-oN" not in self._build("quick", True)

    def test_service_detection_can_be_disabled(self):
        assert "-sV" in self._build("quick", True)
        assert "-sV" not in self._build("quick", False)

    @pytest.mark.parametrize("scan_type,expected", [
        ("quick", "-T4"),
        ("full", "-T3"),
        ("stealth", "-sS"),
    ])
    def test_timing_per_scan_type(self, scan_type, expected):
        assert expected in self._build(scan_type, False)

    def test_dns_resolution_always_disabled(self):
        assert "-n" in self._build("quick", False)


class TestLocalTargetDetection:
    @pytest.mark.parametrize("target", ["127.0.0.1", "localhost", "::1"])
    def test_loopback_is_local(self, target):
        assert PortScanner._is_local_target(target) is True

    @pytest.mark.parametrize("target", ["8.8.8.8", "192.0.2.1", "example.com"])
    def test_remote_is_not_local(self, target):
        assert PortScanner._is_local_target(target) is False
