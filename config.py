"""
NetGuardian Configuration
Application settings and constants.
"""

import os
from pathlib import Path

# Application Info
APP_NAME = "NetGuardian"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Home Network Management Desktop Application"

# Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
DB_PATH = DATA_DIR / "netguardian.db"

# Network Settings
DEFAULT_SCAN_TIMEOUT = 5  # seconds
DEFAULT_PORT_RANGE = (1, 1024)  # Well-known ports
ARP_SCAN_TIMEOUT = 3  # seconds

# Modem Settings (MitraStar GPT-2741GNAO-N1)
# Supply connection settings through the UI or environment variables.
MODEM_DEFAULT_IP = os.environ.get("NETGUARDIAN_MODEM_IP", "")
MODEM_DEFAULT_USERNAME = os.environ.get("NETGUARDIAN_MODEM_USER", "")
MODEM_DEFAULT_PASSWORD = os.environ.get("NETGUARDIAN_MODEM_PASSWORD", "")
MODEM_REQUEST_TIMEOUT = 30  # seconds

# UI Settings
WINDOW_MIN_WIDTH = 1024
WINDOW_MIN_HEIGHT = 768
WINDOW_TITLE = f"{APP_NAME} - Home Network Manager"

# Firewall Settings
FIREWALL_RULE_PREFIX = "NetGuardian"

# Logging
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"

# Database
DB_TIMEOUT = 10  # seconds
LOG_RETENTION_DAYS = 30  # activity_logs rows older than this are pruned at startup

# Performance instrumentation
# Set NETGUARDIAN_PERF=1 to emit [PERF] timings for the hot paths.
PERF_LOGGING = os.environ.get("NETGUARDIAN_PERF", "") not in ("", "0", "false", "False")

# Create directories if they don't exist
def ensure_directories():
    """Create necessary directories if they don't exist."""
    DATA_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)

# Initialize directories on import
ensure_directories()
