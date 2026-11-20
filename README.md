# NetGuardian

Home Network Management Desktop Application

## Overview

NetGuardian is a desktop application for monitoring and managing your home network. Built with Python and PySide6, it provides a unified interface for device discovery, real-time traffic monitoring, port scanning, modem status, firewall management, and activity logging.

## Features

### Device Discovery
- ARP-based network scanning to find all connected devices
- MAC address OUI lookup for device manufacturer identification (IEEE registry, optional)
- Modem integration for WiFi/LAN connection type detection
- Hostname-based device guessing when OUI lookup fails

### Traffic Monitoring
- Real-time bandwidth graphs updated once per second using PyQtGraph
- Interface selection with live traffic rates
- Per-device traffic breakdown using packet sniffing (scapy)
- Upload/download speed tracking with auto-refresh

### Port Scanner
- Nmap-based port scanning with optional service detection
- Process identification for local ports (via psutil)
- Quick scan (nmap's top 100 ports) or custom port range
- TCP and UDP protocol support

### Modem Status
- Web scraping for MitraStar modem status pages
- MD5 hashed login with session management
- GPON, Internet, WiFi, LAN port status tabs
- Connected devices list with connection types

### Firewall Manager
- Windows Firewall rule creation and management
- Checkbox-based multi-select with batch operations
- Toggle to show all system firewall rules (read-only)
- Rule enable/disable/delete with visual feedback

### Activity Logs
- SQLite database for persistent event logging
- Filtering and search capabilities, with automatic pruning of old entries
- Automatic logging of scans, firewall changes, and device discoveries

## Requirements

- **Python:** 3.11 or higher
- **OS:** Windows 10/11 (required for firewall management and netsh commands)
- **Nmap:** Required for port scanning features ([Download](https://nmap.org/download.html))
- **Npcap:** Required for packet capture and per-device traffic monitoring ([Download](https://npcap.com/#download))
- **Admin privileges:** Required for firewall management and packet sniffing (UAC elevation prompt on startup)

## Installation

1. Clone this repository using the URL from GitHub's **Code** menu, then open the project folder.

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install Nmap and Npcap if not already installed.

5. *(Optional)* Download the IEEE OUI registry for accurate device
   manufacturer identification. Without it, a smaller built-in table is used:
   ```bash
   python scripts/update_oui.py
   ```

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

The suite covers the parts that are easy to get wrong and hard to eyeball:
netsh output parsing in both English and Portuguese, nmap argument validation,
OUI lookup, SQLite concurrency, subnet arithmetic, and the concurrency of
hostname resolution. Network tests use simulated inputs. The Windows GUI
smoke tests can read firewall rules without changing them.

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. Accept the UAC prompt when requested (required for admin features).

3. Use the tabbed interface to access different features:
   - **Device Discovery:** Click "Scan Network" to find devices
   - **Traffic Monitoring:** Select an interface and click "Start Monitoring"
   - **Port Scanner:** Enter a target IP and click "Scan Ports"
   - **Modem Status:** Enter the modem IP and login details, then click "Refresh Status"
   - **Firewall Manager:** Add rules or manage existing ones
   - **Activity Logs:** View logged events with filters

## Project Structure

```
netguardian/
├── main.py                     # Application entry point
├── config.py                   # Configuration settings
├── requirements.txt            # Python dependencies
├── requirements-dev.txt        # Test dependencies
├── pytest.ini                  # Test configuration
├── core/                       # Core business logic
│   ├── traffic_monitor.py      # Real-time traffic monitoring (psutil)
│   ├── per_device_traffic.py   # Per-device traffic (scapy)
│   ├── device_scanner.py       # ARP scanning (scapy)
│   ├── oui.py                  # MAC vendor lookup (IEEE registry + fallback)
│   ├── oui_data.py             # Built-in OUI fallback table
│   ├── port_scanner.py         # Port scanning (nmap) + process lookup
│   ├── modem_scraper.py        # Modem web scraping + MD5 login
│   ├── firewall_manager.py     # Windows Firewall management (netsh)
│   └── activity_logger.py      # SQLite event logging
├── ui/                         # UI components (PySide6)
│   ├── device_discovery_tab.py
│   ├── traffic_monitoring_tab.py
│   ├── port_scanner_tab.py
│   ├── modem_status_tab.py
│   ├── firewall_manager_tab.py
│   └── activity_logs_tab.py
├── utils/
│   └── timing.py               # Performance instrumentation
├── scripts/
│   └── update_oui.py           # Download the IEEE OUI registry
├── tests/                      # pytest suite
├── models/                     # Data models
├── data/                       # Application data (SQLite DB, OUI registry)
└── logs/                       # Application logs
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11+ |
| GUI | PySide6 (Qt 6) |
| Real-time Graphs | PyQtGraph |
| Packet Capture | scapy |
| Port Scanning | python-nmap |
| System Info | psutil |
| Modem Scraping | requests + BeautifulSoup4 |
| Firewall | subprocess + netsh |
| Database | SQLite3 |

## Configuration

Settings are defined in `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `MODEM_DEFAULT_IP` | Empty | Modem IP address |
| `MODEM_DEFAULT_USERNAME` | Empty | Modem login username |
| `MODEM_DEFAULT_PASSWORD` | Empty | Modem login password |
| `ARP_SCAN_TIMEOUT` | `3` seconds | How long to wait for ARP responses |
| `DEFAULT_PORT_RANGE` | `1-1024` | Default port scan range |
| `FIREWALL_RULE_PREFIX` | `NetGuardian` | Prefix for managed firewall rules |
| `LOG_RETENTION_DAYS` | `30` | Activity log entries older than this are pruned at startup |

### Modem credentials

Enter your modem's connection settings in **Modem Status**. To prefill those
fields and enable modem lookup in **Device Discovery**, set these environment
variables before launching the application. Device Discovery uses ARP alone
when the modem IP is unset.

| Variable | Overrides |
|----------|-----------|
| `NETGUARDIAN_MODEM_IP` | `MODEM_DEFAULT_IP` |
| `NETGUARDIAN_MODEM_USER` | `MODEM_DEFAULT_USERNAME` |
| `NETGUARDIAN_MODEM_PASSWORD` | `MODEM_DEFAULT_PASSWORD` |

### Performance instrumentation

Set `NETGUARDIAN_PERF=1` to log timings for the hot paths (firewall rule
loading, ARP scans, DNS resolution, modem polling, port scans) to stderr, plus
a summary table on exit:

```powershell
$env:NETGUARDIAN_PERF=1; python main.py
```

## Known Limitations

- **Windows only:** Firewall management uses `netsh` commands specific to Windows
- **Modem-specific:** Modem scraping is built for MitraStar GPT-2741GNAO-N1 (may work with similar models)
- **Nmap required:** Port scanning features will not work without Nmap installed
- **Npcap required:** Per-device traffic monitoring requires Npcap for packet capture
- **Admin required:** Firewall operations and packet sniffing require administrator privileges
- **Local processes only:** Process identification is shown only when scanning this machine; a remote host's processes are not visible

## License

This project is licensed under the MIT License.

## Acknowledgments

- [PySide6](https://doc.qt.io/qtforpython-6/) - Qt for Python
- [PyQtGraph](https://www.pyqtgraph.org/documentation/) - Real-time plotting
- [python-nmap](https://xael.org/pages/python-nmap-en.html) - Nmap wrapper
- [scapy](https://scapy.readthedocs.io/) - Packet manipulation
- [psutil](https://psutil.readthedocs.io/) - System monitoring
