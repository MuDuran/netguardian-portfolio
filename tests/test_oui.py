"""Tests for MAC OUI vendor lookup."""

import pytest

from core import oui
from core.oui import (
    is_locally_administered,
    lookup_mac_vendor,
    normalize_oui,
)
from core.oui_data import CURATED_OUI


class TestNormalizeOui:
    @pytest.mark.parametrize("mac", [
        "aa:bb:cc:dd:ee:ff",
        "AA:BB:CC:DD:EE:FF",
        "aa-bb-cc-dd-ee-ff",
        "AABB.CCDD.EEFF",
        "aabbccddeeff",
        "AA BB CC DD EE FF",
    ])
    def test_accepts_common_notations(self, mac):
        assert normalize_oui(mac) == "AA:BB:CC"

    @pytest.mark.parametrize("mac", ["", None, "zz:zz:zz", "aabb", "not a mac"])
    def test_rejects_junk(self, mac):
        assert normalize_oui(mac) is None


class TestLookup:
    @pytest.fixture(autouse=True)
    def offline_lookup(self, monkeypatch):
        monkeypatch.setattr(oui, "_ieee_registry", {})

    def test_curated_table_used_as_fallback(self):
        assert lookup_mac_vendor("A4:83:E7:11:22:33") == "Apple iPhone"

    def test_raspberry_pi_correction(self):
        # B8:27:EB is Raspberry Pi; the original table listed it as Samsung.
        assert lookup_mac_vendor("B8:27:EB:11:22:33") == "Raspberry Pi"

    def test_unknown_burned_in_mac(self):
        # Globally administered (bit 1 of first octet clear) and not in any table
        assert lookup_mac_vendor("00:00:00:11:22:33") in ("Unknown", CURATED_OUI.get("00:00:00"))

    def test_randomized_mac_reported_as_such(self):
        # 0x02 has the locally-administered bit set
        assert lookup_mac_vendor("02:11:22:33:44:55") == "Randomized MAC"

    def test_empty_input(self):
        assert lookup_mac_vendor("") == "Unknown"

    def test_no_two_octet_prefix_guessing(self):
        # The old implementation scanned for any key sharing the first two
        # octets and returned an arbitrary vendor. A2 is not a real prefix here.
        result = lookup_mac_vendor("A4:00:00:11:22:33")
        assert result != "Apple iPhone"


class TestLocallyAdministered:
    @pytest.mark.parametrize("mac", ["02:00:00:00:00:00", "06:12:34:00:00:01",
                                     "AA:BB:CC:DD:EE:FF"])
    def test_detects_randomized(self, mac):
        assert is_locally_administered(mac) is True

    @pytest.mark.parametrize("mac", ["00:1A:2B:00:00:01", "B8:27:EB:00:00:01",
                                     "A4:83:E7:00:00:01"])
    def test_detects_burned_in(self, mac):
        assert is_locally_administered(mac) is False


class TestCuratedData:
    def test_no_duplicate_keys(self):
        # The literals are deduped at build time; this guards regressions.
        assert len(CURATED_OUI) == len(set(CURATED_OUI))

    def test_all_keys_well_formed(self):
        for key in CURATED_OUI:
            assert normalize_oui(key) == key, f"malformed OUI key: {key}"

    def test_no_empty_vendors(self):
        assert all(v.strip() for v in CURATED_OUI.values())


class TestIeeeRegistry:
    def test_missing_registry_is_not_an_error(self, monkeypatch, tmp_path):
        monkeypatch.setattr(oui, "OUI_CSV_PATH", tmp_path / "absent.csv")
        oui.reload_registry()
        assert oui.get_registry() == {}
        oui.reload_registry()

    def test_registry_overrides_curated_table(self, monkeypatch, tmp_path):
        csv_path = tmp_path / "oui.csv"
        csv_path.write_text(
            "Registry,Assignment,Organization Name,Organization Address\n"
            "MA-L,A483E7,Test Organization Inc,Somewhere\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(oui, "OUI_CSV_PATH", csv_path)
        oui.reload_registry()
        try:
            assert lookup_mac_vendor("A4:83:E7:11:22:33") == "Test Organization Inc"
        finally:
            oui.reload_registry()
