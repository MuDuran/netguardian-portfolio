"""
MAC OUI Lookup
Resolves a MAC address to a device manufacturer.

The official IEEE MA-L registry (data/oui.csv) takes precedence over the
built-in CURATED_OUI fallback table.

Fetch the IEEE registry with:

    python scripts/update_oui.py

Without it the built-in table still works; it is just smaller and, for a
handful of prefixes, ambiguous.
"""

import csv
import logging
import re
from pathlib import Path
from typing import Dict, Optional

import config
from core.oui_data import CURATED_OUI

logger = logging.getLogger(__name__)

OUI_CSV_PATH = config.DATA_DIR / "oui.csv"

_MAC_SEPARATORS = re.compile(r"[-.\s]")

# Populated on first use.
_ieee_registry: Optional[Dict[str, str]] = None


def _load_ieee_registry() -> Dict[str, str]:
    """
    Load the IEEE MA-L registry from data/oui.csv if it is present.

    Returns an empty mapping when the file is missing or unreadable, so the
    curated table remains the source of truth.
    """
    registry: Dict[str, str] = {}

    if not OUI_CSV_PATH.exists():
        logger.debug(f"IEEE OUI registry not found at {OUI_CSV_PATH}")
        return registry

    try:
        with open(OUI_CSV_PATH, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                assignment = (row.get("Assignment") or "").strip().upper()
                organization = (row.get("Organization Name") or "").strip()
                if len(assignment) == 6 and organization:
                    key = ":".join(
                        assignment[i:i + 2] for i in range(0, 6, 2)
                    )
                    registry[key] = organization
        logger.info(f"Loaded {len(registry)} OUI entries from {OUI_CSV_PATH}")
    except (OSError, csv.Error) as e:
        logger.warning(f"Could not read {OUI_CSV_PATH}: {e}")
        return {}

    return registry


def get_registry() -> Dict[str, str]:
    """Get the IEEE registry, loading it once on first use."""
    global _ieee_registry
    if _ieee_registry is None:
        _ieee_registry = _load_ieee_registry()
    return _ieee_registry


def reload_registry():
    """Force the IEEE registry to be re-read on the next lookup."""
    global _ieee_registry
    _ieee_registry = None


def normalize_oui(mac_address: str) -> Optional[str]:
    """
    Extract the OUI from a MAC address in any common notation.

    Handles "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff" and
    bare hex.

    Args:
        mac_address: MAC address in any common format

    Returns:
        "AA:BB:CC" style OUI, or None if the input is not a usable MAC
    """
    if not mac_address:
        return None

    hex_only = _MAC_SEPARATORS.sub("", mac_address.replace(":", "")).upper()
    if len(hex_only) < 6 or not all(c in "0123456789ABCDEF" for c in hex_only[:6]):
        return None

    return ":".join(hex_only[i:i + 2] for i in range(0, 6, 2))


def is_locally_administered(mac_address: str) -> bool:
    """
    Whether the MAC is randomized rather than burned in.

    Modern phones rotate a locally-administered MAC per network for privacy.
    Such an address has no manufacturer to look up, so saying so beats
    reporting "Unknown" as though the lookup merely failed.
    """
    oui = normalize_oui(mac_address)
    if oui is None:
        return False
    # Bit 1 of the first octet is the local/global flag.
    return bool(int(oui[:2], 16) & 0b10)


def lookup_mac_vendor(mac_address: str) -> str:
    """
    Look up device manufacturer from MAC address OUI.

    Args:
        mac_address: MAC address in format "XX:XX:XX:XX:XX:XX"

    Returns:
        Device manufacturer/model string, or "Unknown" if not found
    """
    oui = normalize_oui(mac_address)
    if oui is None:
        return "Unknown"

    vendor = get_registry().get(oui) or CURATED_OUI.get(oui)
    if vendor:
        return vendor

    # A randomized MAC is not a failed lookup; it has no vendor by design.
    # The old code fell back to scanning the whole table for any key sharing
    # the first two octets, which returned an arbitrary unrelated vendor.
    if is_locally_administered(oui):
        return "Randomized MAC"

    return "Unknown"
