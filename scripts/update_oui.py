"""
Download the IEEE MA-L (OUI) registry into data/oui.csv.

The registry maps the first three octets of a MAC address to the organization
that registered them. With it in place, NetGuardian identifies device
manufacturers from the authoritative source instead of the small built-in
fallback table.

Run occasionally to refresh:

    python scripts/update_oui.py
"""

import csv
import io
import sys
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import config  # noqa: E402

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
DESTINATION = config.DATA_DIR / "oui.csv"
REQUEST_TIMEOUT = 120


def main() -> int:
    print(f"Downloading {IEEE_OUI_URL} ...")
    try:
        response = requests.get(IEEE_OUI_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Download failed: {e}", file=sys.stderr)
        return 1

    # Validate before overwriting whatever is already there.
    try:
        reader = csv.DictReader(io.StringIO(response.text))
        rows = sum(
            1 for row in reader
            if (row.get("Assignment") or "").strip()
            and (row.get("Organization Name") or "").strip()
        )
    except csv.Error as e:
        print(f"Downloaded file is not valid CSV: {e}", file=sys.stderr)
        return 1

    if rows < 10000:
        print(
            f"Only {rows} usable rows found; that does not look like the full "
            "registry. Leaving the existing file alone.",
            file=sys.stderr,
        )
        return 1

    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(response.text, encoding="utf-8")
    size_mb = DESTINATION.stat().st_size / (1024 * 1024)
    print(f"Wrote {rows} OUI entries to {DESTINATION} ({size_mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
