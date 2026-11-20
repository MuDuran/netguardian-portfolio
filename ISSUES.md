# NetGuardian - Issues List

## Purpose
Track issues and improvements discovered during development.
These will be addressed after all phases are implemented.

---

## Issues to Fix

### Issue #1: Wi-Fi Traffic Not Captured ✅ FIXED
- **Feature:** Traffic Monitoring
- **Description:** When selecting Wi-Fi interface and playing a YouTube video on a connected device, network traffic stays at 0 B/s
- **Expected:** Should see traffic spikes when video is streaming
- **Priority:** High
- **Status:** ✅ Fixed
- **Root Cause:** Traffic was routing through a different interface than "Wi-Fi"
- **Solution Implemented:**
  - Added `get_interfaces_with_stats()` method to get all interfaces with current traffic
  - Added `get_interfaces_speeds()` method to show real-time speeds per interface
  - Updated combo box to show interfaces with their current traffic rates (e.g., "Ethernet (1.2 MB/s)")
  - Interfaces are sorted by traffic (highest first) to help identify active ones
  - Auto-refreshes interface list every 5 seconds while monitoring
  - Added warning message if selected interface shows 0 B/s for 10+ seconds
- **Files Modified:** `core/traffic_monitor.py`, `ui/traffic_monitoring_tab.py`

### Issue #2: Modem Data Not Parsed Correctly ✅ FIXED
- **Feature:** Modem Status
- **Description:** Modem connects successfully but returns "Unknown" for most fields
- **Expected:** Should parse and display actual modem data
- **Priority:** High
- **Status:** ✅ Fixed
- **Root Cause:** 
  1. The configured login credentials did not match the modem.
  2. Login requires MD5 hashing: `hex_md5(password + ":" + session_id)`
  3. Parser used generic keywords that didn't match actual HTML structure
- **Solution Implemented:**
  - Fixed login with MD5 password hashing and session cookie authentication
  - Complete rewrite of HTML parser to match MitraStar modem's actual structure
  - Parses GPON status (link, Rx/Tx power)
  - Parses Internet status (PPP, IPv4/IPv6, DNS)
  - Parses WiFi 2.4GHz and 5GHz info (SSID, channel, security, status)
  - Parses connected devices from JavaScript variables
  - Parses LAN port status (4 ports)
  - Added tabbed UI with Overview, WiFi, Connected Devices, and LAN Ports tabs
- **Files Modified:** `core/modem_scraper.py`, `ui/modem_status_tab.py`
- **Key Discovery:** Modem uses frame-based interface with separate CGI files
  - Main status: `/cgi-bin/sophia_info.cgi`
  - Login: `/cgi-bin/login.cgi` with MD5 hashing

---

## Quality of Life Upgrades

### Upgrade #1: Per-Device Traffic Monitoring ✅ IMPLEMENTED
- **Feature:** Traffic Monitoring
- **Description:** User wants to see which specific device is generating traffic, including:
  - Device name or IP address
  - Upload speed per device
  - Download speed per device
- **Expected:** Instead of just total network traffic, show a breakdown by connected device
- **Priority:** Medium
- **Status:** ✅ Implemented
- **Notes:** 
  - Uses scapy packet sniffing to capture traffic per IP
  - Shows device name, IP, upload/download speed, and total data
  - Table auto-refreshes every second
  - Toggle checkbox to enable/disable (packet sniffing is resource-heavy)
  - Requires admin privileges for packet capture
  - Correlates IPs with discovered devices from Device Discovery
- **Files Created:** `core/per_device_traffic.py`
- **Files Modified:** `ui/traffic_monitoring_tab.py`

### Upgrade #2: Device Network Interface Display
- **Feature:** Device Discovery
- **Description:** Show which network interface each device is connected through
  - Example: "Wi-Fi", "Ethernet", "Bluetooth"
  - Helps identify connection type for troubleshooting
- **Expected:** User can see at a glance whether a device is on Wi-Fi or wired connection
- **Priority:** Medium (Nice-to-have)
- **Status:** ✅ Implemented in Modem Status
- **Notes:**
  - Now showing connection type (WiFi 2.4GHz, WiFi 5GHz, LAN) for each device
  - Shows specific interface name (e.g., "Example-WiFi-5G", "LAN1")

### Upgrade #3: Application/Process Identification for Ports ✅ IMPLEMENTED
- **Feature:** Port Scanner
- **Description:** Show which application or process is using each discovered port
  - Example: "Port 80 - httpd.exe (Apache)" or "Port 443 - chrome.exe"
  - Helps identify what's actually listening on that port
- **Expected:** Instead of just "HTTP" service name, show the actual application name
- **Priority:** Medium (Nice-to-have)
- **Status:** ✅ Implemented
- **Notes:**
  - Uses `psutil.net_connections()` to map ports to PIDs and process names
  - Added "Process" column (6th column) to scan results table
  - Shows both process name and PID
  - Only shows local process information (remote device processes are not accessible)
- **Files Modified:** `core/port_scanner.py`, `ui/port_scanner_tab.py`

### Upgrade #4: Visual Checkbox for Firewall Rule Selection ✅ IMPLEMENTED
- **Feature:** Firewall Manager
- **Description:** Add checkboxes to the rules table for better visual feedback
  - User can check/uncheck rules to select them
  - Visual indicator of which rules will be affected by actions (delete, enable, disable)
  - Could support multi-select operations
- **Expected:** Clear visual feedback showing selected rules before performing actions
- **Priority:** Medium (Nice-to-have)
- **Status:** ✅ Implemented
- **Notes:**
  - Added checkbox column (first column) to rules table
  - "Check All" / "Uncheck All" buttons for convenience
  - Enable/Disable/Delete buttons now operate on all checked rules (batch operations)
  - Batch operations process rules sequentially with progress feedback
  - System rules (when showing all) cannot be checked/modified
- **Files Modified:** `ui/firewall_manager_tab.py`

### Upgrade #5: Show All Firewall Rules Toggle ✅ IMPLEMENTED
- **Feature:** Firewall Manager
- **Description:** Add a toggle/checkbox to show all Windows Firewall rules, not just NetGuardian rules
  - Default: Show only NetGuardian rules (safe, focused)
  - Toggle ON: Show all system and user-created rules
  - System rules could be marked as "Do not modify" for safety
- **Expected:** User can optionally see the complete firewall configuration when needed
- **Priority:** Medium (Nice-to-have)
- **Status:** ✅ Implemented
- **Notes:**
  - Added "Show All Windows Firewall Rules" checkbox toggle
  - Default shows only NetGuardian rules
  - Toggle ON shows all rules, with system rules dimmed (gray text)
  - System rules cannot be checked/modified (read-only)
  - Added `get_all_rules()` method to `FirewallManager`
- **Files Modified:** `core/firewall_manager.py`, `ui/firewall_manager_tab.py`

### Upgrade #6: Device Model Column in Device Discovery ✅ IMPLEMENTED
- **Feature:** Device Discovery
- **Description:** Show the device manufacturer based on MAC address OUI lookup
  - Add "Device" column to the left of "IP Address" column
  - Use first 3 octets of MAC address to identify manufacturer
- **Expected:** User can identify device type/manufacturer at a glance
- **Priority:** Medium (Nice-to-have)
- **Status:** ✅ Implemented
- **Notes:**
  - Uses MAC address OUI (Organizationally Unique Identifier) lookup
  - Built-in database of common manufacturers (Apple, Samsung, Xiaomi, Huawei, etc.)
  - Falls back to "Unknown" for unrecognized MACs

### Upgrade #7: Connection Type Column in Device Discovery ✅ IMPLEMENTED
- **Feature:** Device Discovery
- **Description:** Show WiFi/LAN connection type for each device
  - Add "Connection" column showing "WiFi 5GHz (Example-WiFi-5G)" or "LAN (LAN1)"
  - Merges ARP scan data with modem device data for accurate connection info
  - Hostname-based device guessing when OUI lookup fails
- **Expected:** User can see at a glance how each device is connected
- **Priority:** Medium (Nice-to-have)
- **Status:** ✅ Implemented
- **Notes:**
  - Queries modem for connected devices with connection types
  - Merges ARP scan results with modem data
  - Falls back to hostname-based device guessing (e.g., "Galaxy-Phone" → "Samsung")
- **Files Modified:** `core/device_scanner.py`, `ui/device_discovery_tab.py`

---

## Notes for Next Session

### Priority Order for Next Session
1. ~~**Fix Wi-Fi Traffic Monitoring** (Issue #1)~~ ✅ Done
2. ~~**Fix Modem Data Parsing** (Issue #2)~~ ✅ Done
3. ~~**Implement remaining Upgrades #1, #3-5**~~ ✅ All Done

### Key Discoveries
- Modem status path: `/cgi-bin/sophia_info.cgi`
- Login requires MD5 hashing: `hex_md5(password + ":" + session_id)`
- Session managed via COOKIE_SESSION_KEY cookie
- Portuguese Windows uses different netsh syntax and encoding
- Admin privileges required for firewall operations
- scapy packet sniffing works well for per-device traffic monitoring
- psutil.net_connections() can map ports to local processes

---

---

## Performance & Robustness Pass (2026-08-23)

Full review of the codebase followed by a three-phase remediation. All items
below are implemented.

### Security

| # | Item | Files |
|---|------|-------|
| S1 | Modem settings supplied through the UI or `NETGUARDIAN_MODEM_*` environment variables | `config.py`, `core/modem_scraper.py` |

### Phase 1 - Performance

| # | Issue | Fix | Files |
|---|-------|-----|-------|
| P1 | Firewall rules fetched twice per load, second time on the GUI thread (~6 subprocess calls, ~3s frozen UI) | Worker emits the parsed rules; GUI-thread refetch deleted. Admin check uses `IsUserAnAdmin()` instead of spawning netsh. Two directional dumps collapsed into one. | `core/firewall_manager.py`, `ui/firewall_manager_tab.py` |
| P2 | Traffic tab restarted monitoring every 5s (combo repopulate reset the selection, since the label embeds a changing speed) | Interface stored in `Qt.UserRole` and matched with `findData`; repopulate wrapped in `blockSignals` | `ui/traffic_monitoring_tab.py` |
| P3 | `time.sleep(0.1)` on the GUI thread every 5s | `InterfaceSpeedTracker` derives speeds from the previous sample; no sleep | `core/traffic_monitor.py` |
| P4 | Reverse DNS ran serially, ~9.5s per unresolvable device | Concurrent resolution with a 2.5s batch deadline and an IP cache | `core/device_scanner.py` |
| P5 | A new SQLite connection opened per log line | One WAL connection behind a lock, `log_many` for batches, startup pruning | `core/activity_logger.py` |
| P6 | Modem re-authenticated on every poll (`_is_logged_in` was set but never read) | 5-minute session cache with one automatic retry on expiry | `core/modem_scraper.py` |
| P7 | No way to measure any of this | `utils/timing.py`, enabled with `NETGUARDIAN_PERF=1` | `utils/timing.py` |

### Phase 2 - Robustness

| # | Issue | Fix |
|---|-------|-----|
| R1 | netsh output decoded as latin-1, producing mojibake labels the parser special-cased (`Aзao:`) | Strict multi-encoding decode (UTF-8 first) plus accent-stripping label match; localized values mapped to English |
| R2 | Batch firewall ops spawned one QThread per rule and reassigned `self._worker` mid-flight | Whole batch runs in one worker; live workers held in a list until `finished` |
| R3 | UAC elevation passed a script path that does not exist in a PyInstaller bundle | Branches on `sys.frozen`; a declined prompt continues unelevated instead of exiting |
| R4 | `cleanup()` existed but nothing called it; scapy sniffer outlived the window | `MainWindow.closeEvent` calls `cleanup()` on every tab that defines one |
| R5 | `stop()` hung for its full timeout on a quiet interface (scapy checks `stop_filter` only on packet arrival) | Sniff in 1s bursts, re-checking the stop flag between them |
| R6 | Scan target and ports went to the nmap command line unvalidated; `-oN -` conflicted with python-nmap's own `-oX -` | `validate_target` / `validate_ports` reject injection; `-oN` removed |
| R7 | 10 bare `except:` clauses swallowing everything | Replaced with `except Exception` plus a debug log |

### Phase 3 - Quality

| # | Item | Detail |
|---|------|--------|
| Q1 | OUI database | Moved to `core/oui.py` + `core/oui_data.py`. 25 duplicate keys were silently overwriting each other; `B8:27:EB` was labelled Samsung but is Raspberry Pi. Now: IEEE registry (`scripts/update_oui.py`) > curated fallback. Randomized MACs reported as such instead of "Unknown". The O(n) two-octet prefix guess is gone. `device_scanner.py` shrank 1141 -> 290 lines. |
| Q2 | Test suite | 143 pytest cases covering netsh parsing (English + Portuguese), nmap validation, OUI lookup, SQLite concurrency and pruning, subnet arithmetic, and DNS concurrency. Network tests use simulated inputs. GUI smoke tests can read firewall rules. |
| Q3 | CI | `.github/workflows/tests.yml`, Windows runner, Python 3.11/3.12/3.13 |
| Q4 | Live tables | Per-device traffic table updated in place instead of cleared and rebuilt each second, preserving selection and scroll position |
| Q5 | Version drift | `config.py` said 0.1.0 while the README said v1.0; now 1.0.0 everywhere, read from config |
| Q6 | Dead code | Removed the "will be implemented in Phase 1!" menu stub (now drives a real scan) and the unreferenced `_on_rule_updated` |
| Q7 | Correctness | `_calculate_network` honours the real netmask instead of hardcoding /24; quick scan actually uses 100 ports; `scan_duration` is measured; process attribution only for local targets; stale per-device IPs clear both period maps |

### Measured

| Operation | Before | After |
|-----------|--------|-------|
| Firewall rule load | ~4 netsh dumps + 2 admin subprocesses, half on the GUI thread | 1 dump, 640ms, fully off-thread |
| Interface speed sample | 100ms blocking | ~6ms non-blocking |
| Reverse DNS, 1 unresolvable host | ~9.5s | 2.5s cap, 1ms when cached |
| Traffic monitoring | restarted every 5s | stable |

### Still open

- Per-device and firewall tables use in-place `QTableWidget` updates rather than
  a full `QAbstractTableModel`. This delivers the user-visible benefit (no
  flicker, selection preserved) at a fraction of the risk; a real model is
  worth it only if the tables grow much larger.
- The `netsh` text parser was hardened rather than replaced with
  `Get-NetFirewallRule`/COM. It is now locale-tolerant and covered by tests, so
  the remaining benefit of switching is modest.

---

*Last Updated: 2026-08-23*
*Total: 2 bugs fixed, 7 upgrades implemented, 1 performance & robustness pass (15 issues) completed*
