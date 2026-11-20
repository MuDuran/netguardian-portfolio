"""
Modem Scraper Module
Scrapes modem web interface for status information using requests and BeautifulSoup.

Target Modem: MitraStar GPT-2741GNAO-N1 (Vivo/Fiber)
Status path: /cgi-bin/sophia_info.cgi
"""

import hashlib
import logging
import re
import threading
import time
import requests
from bs4 import BeautifulSoup, Tag
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import config
from utils.timing import timed

logger = logging.getLogger(__name__)

# Activity logger (imported here to avoid circular imports)
_activity_logger = None


def get_activity_logger():
    """Get the activity logger instance."""
    global _activity_logger
    if _activity_logger is None:
        from core.activity_logger import ActivityLogger
        _activity_logger = ActivityLogger.instance()
    return _activity_logger


@dataclass
class ModemInfo:
    """Modem information."""
    model: str
    firmware: str
    hardware_version: str
    serial_number: str
    uptime: str
    ip_address: str
    # GPON/Fiber info
    gpon_status: str = "Unknown"
    gpon_rx_power: str = "Unknown"
    gpon_tx_power: str = "Unknown"
    # Internet info
    internet_status: str = "Unknown"
    ppp_status: str = "Unknown"
    ipv4_local: str = "Unknown"
    ipv4_public: str = "Unknown"
    gateway: str = "Unknown"
    dns_primary: str = "Unknown"
    dns_secondary: str = "Unknown"


@dataclass
class WifiInfo:
    """WiFi information."""
    ssid: str
    status: str  # Enabled/Disabled
    channel: int
    signal_strength: str
    security: str
    band: str = "2.4GHz"  # 2.4GHz or 5GHz
    wps_enabled: str = "Unknown"
    ssid_broadcast: str = "Unknown"


@dataclass
class ConnectedDevice:
    """Connected device information."""
    name: str
    ip_address: str
    mac_address: str
    connection_type: str  # WiFi 2.4GHz, WiFi 5GHz, LAN, etc.
    status: str  # Active/Inactive
    interface: str = ""  # Specific interface (LAN1, WiFi 5GHz, etc.)


@dataclass
class LanPort:
    """LAN port information."""
    port_name: str  # LAN1, LAN2, etc.
    status: str  # Connected/Disconnected
    device_name: str = ""


@dataclass
class ModemStatus:
    """Complete modem status."""
    modem_info: Optional[ModemInfo]
    wifi_info_24ghz: Optional[WifiInfo]
    wifi_info_5ghz: Optional[WifiInfo]
    connected_devices: List[ConnectedDevice]
    lan_ports: List[LanPort]
    last_updated: datetime
    error: Optional[str]


class ModemScraper:
    """
    Web scraper for MitraStar modem status.
    
    Connects to the modem's web interface and scrapes status information.
    Read-only operations - does not modify modem settings.
    """
    
    # A modem session cookie outlives a single refresh, so reuse it rather than
    # paying for a full handshake on every status poll.
    SESSION_TTL_SECONDS = 300

    # This modem takes ~18s to render sophia_info.cgi. That is its own
    # generation time, not something we can optimize away, so cache the parsed
    # result briefly and let the Device Discovery and Modem Status tabs share
    # one fetch instead of paying for it twice.
    STATUS_CACHE_SECONDS = 60

    def __init__(
        self,
        modem_ip: str = config.MODEM_DEFAULT_IP,
        username: str = config.MODEM_DEFAULT_USERNAME,
        password: str = config.MODEM_DEFAULT_PASSWORD,
        timeout: int = config.MODEM_REQUEST_TIMEOUT
    ):
        """
        Initialize the modem scraper.

        Args:
            modem_ip: IP address of the modem
            username: Login username
            password: Login password
            timeout: Request timeout in seconds
        """
        self.modem_ip = modem_ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.base_url = f"http://{modem_ip}"
        self._session = requests.Session()
        self._is_logged_in = False
        self._login_time: float = 0.0
        self._cached_status: Optional[ModemStatus] = None
        self._cached_status_time: float = 0.0
        # get_status may be called from several worker threads; only one of
        # them should pay the ~18s fetch.
        self._status_lock = threading.Lock()

    def _session_is_fresh(self) -> bool:
        """Whether the cached login is still usable."""
        return (
            self._is_logged_in
            and (time.monotonic() - self._login_time) < self.SESSION_TTL_SECONDS
        )

    def invalidate_session(self):
        """Drop the cached login so the next request re-authenticates."""
        self._is_logged_in = False
        self._login_time = 0.0
    
    def get_status(self, max_age: Optional[float] = None) -> ModemStatus:
        """
        Get complete modem status, reusing a recent result when possible.

        Args:
            max_age: Accept a cached result younger than this many seconds.
                     Defaults to STATUS_CACHE_SECONDS. Pass 0 to force a fetch.

        Returns:
            ModemStatus with all available information
        """
        ttl = self.STATUS_CACHE_SECONDS if max_age is None else max_age

        with self._status_lock:
            if (
                self._cached_status is not None
                and self._cached_status.error is None
                and (time.monotonic() - self._cached_status_time) < ttl
            ):
                logger.debug("Reusing cached modem status")
                return self._cached_status

            status = self._fetch_status()
            if status.error is None:
                self._cached_status = status
                self._cached_status_time = time.monotonic()
            return status

    def invalidate_status_cache(self):
        """Drop the cached status so the next call refetches."""
        with self._status_lock:
            self._cached_status = None
            self._cached_status_time = 0.0

    @timed("ModemScraper.get_status")
    def _fetch_status(self) -> ModemStatus:
        """
        Fetch and parse status for a configured modem.

        Returns:
            ModemStatus with all available information
        """
        try:
            # Try to login
            if not self._login():
                return ModemStatus(
                    modem_info=None,
                    wifi_info_24ghz=None,
                    wifi_info_5ghz=None,
                    connected_devices=[],
                    lan_ports=[],
                    last_updated=datetime.now(),
                    error="Failed to login to modem. Check credentials."
                )

            # Scrape the main status page
            status_page = self._fetch_status_page()

            # A cached session can expire on the modem side; retry once with a
            # fresh login before giving up.
            if not status_page:
                self.invalidate_session()
                if self._login():
                    status_page = self._fetch_status_page()

            if not status_page:
                return ModemStatus(
                    modem_info=None,
                    wifi_info_24ghz=None,
                    wifi_info_5ghz=None,
                    connected_devices=[],
                    lan_ports=[],
                    last_updated=datetime.now(),
                    error="Failed to fetch status page from modem."
                )
            
            # Parse different sections from the HTML
            modem_info = self._parse_modem_info(status_page)
            wifi_info_24ghz = self._parse_wifi_info(status_page, "2.4GHz")
            wifi_info_5ghz = self._parse_wifi_info(status_page, "5GHz")
            connected_devices = self._parse_connected_devices(status_page)
            lan_ports = self._parse_lan_ports(status_page)
            
            # Log to activity logger
            try:
                act_logger = get_activity_logger()
                act_logger.log_modem_status_loaded(self.modem_ip)
            except Exception as e:
                logger.debug(f"Non-fatal error: {e}")
            
            return ModemStatus(
                modem_info=modem_info,
                wifi_info_24ghz=wifi_info_24ghz,
                wifi_info_5ghz=wifi_info_5ghz,
                connected_devices=connected_devices,
                lan_ports=lan_ports,
                last_updated=datetime.now(),
                error=None
            )
            
        except requests.RequestException as e:
            logger.error(f"Connection error: {e}")
            return ModemStatus(
                modem_info=None,
                wifi_info_24ghz=None,
                wifi_info_5ghz=None,
                connected_devices=[],
                lan_ports=[],
                last_updated=datetime.now(),
                error=f"Connection error: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Scraping error: {e}")
            return ModemStatus(
                modem_info=None,
                wifi_info_24ghz=None,
                wifi_info_5ghz=None,
                connected_devices=[],
                lan_ports=[],
                last_updated=datetime.now(),
                error=f"Error: {str(e)}"
            )
    
    def _login(self) -> bool:
        """
        Login to modem web interface.
        
        The MitraStar modem uses MD5 hashing for password authentication:
        1. Fetch login page to get session ID (var sid = 'xxxx')
        2. Hash password: hex_md5(password + ":" + session_id)
        3. POST to login.cgi with Loginuser, LoginPasswordValue (hash), acceptLoginIndex=1
        4. Server sets COOKIE_SESSION_KEY cookie on success
        
        Returns:
            True if login successful, False otherwise
        """
        # Reuse a still-valid session instead of re-handshaking on every poll.
        if self._session_is_fresh():
            logger.debug("Reusing cached modem session")
            return True

        if not self.modem_ip:
            return False
        if not self.username or not self.password:
            return self._try_without_login()

        try:
            login_url = f"{self.base_url}/cgi-bin/login.cgi"
            
            # Step 1: Get login page and extract session ID
            response = self._session.get(login_url, timeout=self.timeout)
            if response.status_code != 200:
                logger.warning(f"Failed to load login page: {response.status_code}")
                return False
            
            session_id = self._extract_session_id(response.text)
            if not session_id:
                logger.warning("Could not extract session ID, trying without login")
                return self._try_without_login()
            
            # Step 2: Hash password with MD5
            password_hash = hashlib.md5(
                (self.password + ':' + session_id).encode()
            ).hexdigest()
            
            # Step 3: Submit login form
            login_data = {
                'Loginuser': self.username,
                'LoginPasswordValue': password_hash,
                'acceptLoginIndex': '1'
            }
            
            response = self._session.post(
                login_url,
                data=login_data,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Step 4: Check if we got the session cookie
            if 'COOKIE_SESSION_KEY' in self._session.cookies.get_dict():
                logger.info("Login successful - session cookie received")
                self._is_logged_in = True
                self._login_time = time.monotonic()
                return True
            
            # Fallback: check response body
            if response.status_code == 200 and 'location.href' in response.text:
                logger.info("Login successful - redirect received")
                self._is_logged_in = True
                self._login_time = time.monotonic()
                return True
            
            logger.warning("Login failed - no session cookie")
            return self._try_without_login()
                
        except Exception as e:
            logger.warning(f"Login request failed: {e}")
            return self._try_without_login()
    
    def _extract_session_id(self, html: str) -> Optional[str]:
        """
        Extract session ID from login page JavaScript.
        
        Looks for: var sid = 'xxxx'
        """
        match = re.search(r"var\s+sid\s*=\s*['\"]([^'\"]+)['\"]", html)
        if match:
            return match.group(1)
        return None
    
    def _try_without_login(self) -> bool:
        """
        Try accessing modem without login.
        
        Some modem pages might be accessible without authentication,
        or we might already have an active session.
        """
        try:
            # Try accessing the main frameset
            response = self._session.get(
                f"{self.base_url}/cgi-bin/",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                # Check if we got the frameset (means we have access)
                if 'frame' in response.text.lower():
                    logger.info("Accessing modem without login (frameset accessible)")
                    self._is_logged_in = True
                    self._login_time = time.monotonic()
                    return True
                
                # Try accessing status page directly
                response2 = self._session.get(
                    f"{self.base_url}/cgi-bin/sophia_info.cgi",
                    timeout=self.timeout
                )
                
                if response2.status_code == 200:
                    # Check if we got the status table
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response2.text, 'html.parser')
                    table = soup.find('table', {'id': 'status'})
                    
                    if table:
                        logger.info("Accessing modem without login (status page accessible)")
                        self._is_logged_in = True
                        self._login_time = time.monotonic()
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"Failed to access modem without login: {e}")
            return False
    
    def _fetch_status_page(self) -> Optional[str]:
        """
        Fetch the main status page from modem.
        
        The MitraStar modem uses a frame-based interface:
        - sophia_index.cgi loads the frameset
        - sophia_info.cgi contains the actual status data
        
        Returns:
            HTML content of status page or None
        """
        # Try multiple URLs for status page
        urls_to_try = [
            f"{self.base_url}/cgi-bin/sophia_info.cgi",  # Main status page
            f"{self.base_url}/cgi-bin/sophia_index.cgi",  # Index page (frameset)
            f"{self.base_url}/cgi-bin/",  # Main frameset
            f"{self.base_url}/status.htm",  # Static status page
            f"{self.base_url}/",  # Root page
        ]
        
        for url in urls_to_try:
            try:
                response = self._session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    # Check if this is the status page (has table with id="status")
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    table = soup.find('table', {'id': 'status'})
                    
                    if table:
                        logger.info(f"Successfully fetched status page from {url}")
                        return response.text
                    
                    # Check if this is a frameset (need to follow frame)
                    frames = soup.find_all('frame')
                    if frames:
                        # Find the basefrm frame (contains status page)
                        for frame in frames:
                            if frame.get('name') == 'basefrm':
                                frame_src = frame.get('src')
                                if frame_src:
                                    # Make absolute URL
                                    if frame_src.startswith('/'):
                                        frame_url = f"{self.base_url}{frame_src}"
                                    else:
                                        frame_url = f"{self.base_url}/cgi-bin/{frame_src}"
                                    
                                    # Fetch the frame content
                                    frame_response = self._session.get(frame_url, timeout=self.timeout)
                                    if frame_response.status_code == 200:
                                        logger.info(f"Successfully fetched status page from frame: {frame_url}")
                                        return frame_response.text
            except Exception as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                continue
        
        return None
    
    def _parse_modem_info(self, html: str) -> ModemInfo:
        """
        Parse modem info from HTML.
        
        Extracts: GPON status, Internet status, IP addresses, DNS, etc.
        """
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find the status table
        status_table = soup.find('table', {'id': 'status'})
        
        # Initialize with defaults
        modem_info = ModemInfo(
            model="MitraStar GPT-2741GNAO-N1",
            firmware="Unknown",
            hardware_version="Unknown",
            serial_number="Unknown",
            uptime="Unknown",
            ip_address=self.modem_ip
        )
        
        if not status_table:
            return modem_info
        
        # Find all table rows
        rows = status_table.find_all('tr')
        
        for row in rows:
            th = row.find('th')
            if not th:
                continue
            
            # Get section name from th
            span = th.find('span')
            if not span:
                continue
            
            section_name = span.get_text(strip=True).upper()
            
            # Parse GPON section
            if 'GPON' in section_name:
                self._parse_gpon_section(row, modem_info)
            
            # Parse Internet section
            elif 'INTERNET' in section_name:
                self._parse_internet_section(row, modem_info)
        
        # Extract IP address from the HTML
        ip_match = re.search(r'192\.168\.\d+\.\d+', html)
        if ip_match:
            modem_info.ipv4_local = ip_match.group(0)
        
        return modem_info
    
    def _parse_gpon_section(self, row: Tag, modem_info: ModemInfo):
        """Parse GPON/Fiber status from table row."""
        td = row.find('td')
        if not td:
            return
        
        # Find all status divs
        divs = td.find_all('div', class_=re.compile(r'status-line'))
        
        for div in divs:
            strong = div.find('strong')
            if not strong:
                continue
            
            label = strong.get_text(strip=True).replace(':', '').upper()
            value_text = div.get_text(strip=True)
            
            # Extract value (remove the label from the text)
            value = value_text.replace(strong.get_text(strip=True), '').strip()
            
            if 'LINK' in label:
                modem_info.gpon_status = value
            elif 'RX' in label or 'POTÊNCIA RX' in label.upper():
                modem_info.gpon_rx_power = value
            elif 'TX' in label or 'POTÊNCIA TX' in label.upper():
                modem_info.gpon_tx_power = value
    
    def _parse_internet_section(self, row: Tag, modem_info: ModemInfo):
        """Parse Internet status from table row."""
        td = row.find('td')
        if not td:
            return
        
        # Find PPP status
        divs = td.find_all('div', class_=re.compile(r'status-line'))
        for div in divs:
            strong = div.find('strong')
            if strong and 'PPP' in strong.get_text(strip=True).upper():
                span = div.find('span')
                if span:
                    modem_info.ppp_status = span.get_text(strip=True)
                    modem_info.internet_status = span.get_text(strip=True)
        
        # Find the details row (next sibling)
        details_row = row.find_next_sibling('tr')
        if details_row:
            # Look for IPv4 details
            ipv4_div = details_row.find('div', {'id': 'tabip-01'})
            if ipv4_div:
                self._parse_ipv4_details(ipv4_div, modem_info)
    
    def _parse_ipv4_details(self, div: Tag, modem_info: ModemInfo):
        """Parse IPv4 connection details."""
        # Find the table with IP addresses
        ip_table = div.find('div', {'id': 'internet_v4_table'})
        if not ip_table:
            return
        
        # Get all list items (LI elements)
        items = ip_table.find_all('li')
        
        # Also get labels from tabela_esquerda
        labels_div = div.find('div', {'id': 'tabela_esquerda'})
        labels = []
        if labels_div:
            labels = [li.get_text(strip=True) for li in labels_div.find_all('li')]
        
        # Map values to labels
        values = [li.get_text(strip=True) for li in items]
        
        if len(values) >= 1:
            modem_info.ipv4_local = values[0]
        if len(values) >= 2:
            modem_info.ipv4_public = values[1]
        if len(values) >= 3:
            modem_info.gateway = values[2]
        if len(values) >= 4:
            modem_info.dns_primary = values[3]
        if len(values) >= 5:
            modem_info.dns_secondary = values[4]
    
    def _parse_wifi_info(self, html: str, band: str) -> Optional[WifiInfo]:
        """
        Parse WiFi information from HTML.
        
        Args:
            html: HTML content
            band: "2.4GHz" or "5GHz"
        """
        soup = BeautifulSoup(html, 'html.parser')
        status_table = soup.find('table', {'id': 'status'})
        
        if not status_table:
            return None
        
        # Find the WiFi section based on band
        rows = status_table.find_all('tr')
        
        for row in rows:
            th = row.find('th')
            if not th:
                continue
            
            span = th.find('span')
            if not span:
                continue
            
            section_name = span.get_text(strip=True).upper()
            
            if band == "2.4GHz" and 'WI-FI 2.4' in section_name:
                return self._parse_wifi_row(row, band)
            elif band == "5GHz" and 'WI-FI 5' in section_name:
                return self._parse_wifi_row(row, band)
        
        return None
    
    def _parse_wifi_row(self, row: Tag, band: str) -> WifiInfo:
        """Parse WiFi information from a table row."""
        td = row.find('td')
        if not td:
            return self._default_wifi_info(band)
        
        # Find SSID and status
        divs = td.find_all('div', class_=re.compile(r'status-line'))
        
        ssid = "Unknown"
        status = "Unknown"
        
        for div in divs:
            strong = div.find('strong')
            if strong and 'SSID' in strong.get_text(strip=True).upper():
                # Get the text content after the strong tag
                # The SSID is the text node between <strong> and <br/> or <span>
                full_html = str(div)
                
                # Extract SSID using regex on the HTML
                # Pattern: <strong>SSID: </strong> SSID_VALUE<br/>
                ssid_match = re.search(r'SSID:\s*</strong>\s*(\S+?)(?:<br|<span|\s)', full_html)
                if ssid_match:
                    ssid = ssid_match.group(1).strip()
                
                # Get status from span
                span = div.find('span')
                if span:
                    status = span.get_text(strip=True)
        
        # Find the details row (next sibling)
        details_row = row.find_next_sibling('tr')
        
        channel = 0
        security = "Unknown"
        wps_enabled = "Unknown"
        ssid_broadcast = "Unknown"
        
        if details_row:
            # Look for the details in the list
            ul = details_row.find('ul')
            if ul:
                items = ul.find_all('li')
                for i, item in enumerate(items):
                    text = item.get_text(strip=True).upper()
                    if 'SEGURANÇA' in text or 'SECURITY' in text:
                        # Next item should be the value
                        if i + 1 < len(items):
                            security = items[i + 1].get_text(strip=True)
                    elif 'WPS' in text:
                        if i + 1 < len(items):
                            wps_enabled = items[i + 1].get_text(strip=True)
                    elif 'ANÚNCIO' in text or 'BROADCAST' in text:
                        if i + 1 < len(items):
                            ssid_broadcast = items[i + 1].get_text(strip=True)
                    elif 'CANAL' in text or 'CHANNEL' in text:
                        if i + 1 < len(items):
                            try:
                                channel = int(items[i + 1].get_text(strip=True))
                            except ValueError:
                                channel = 0
        
        return WifiInfo(
            ssid=ssid,
            status=status,
            channel=channel,
            signal_strength="N/A",  # Not available in status page
            security=security,
            band=band,
            wps_enabled=wps_enabled,
            ssid_broadcast=ssid_broadcast
        )
    
    def _default_wifi_info(self, band: str) -> WifiInfo:
        """Return default WiFi info when parsing fails."""
        return WifiInfo(
            ssid="Unknown",
            status="Unknown",
            channel=0,
            signal_strength="Unknown",
            security="Unknown",
            band=band
        )
    
    def _parse_connected_devices(self, html: str) -> List[ConnectedDevice]:
        """
        Parse connected devices from HTML.
        
        Devices are listed in JavaScript catFile variables.
        Pattern: var catFile_5g = "Hostname: DeviceName";
        """
        devices = []
        
        # Extract devices from JavaScript catFile variables
        # Pattern for WiFi devices
        wifi_device_pattern = re.compile(
            r'Hostname:\s*([^"\'\\]+).*?MAC:\s*([0-9A-Fa-f:]+).*?IP:\s*(\d+\.\d+\.\d+\.\d+)',
            re.DOTALL
        )
        
        # Find all WiFi device blocks
        # Look for pattern: Hostname -> MAC -> IP in sequence
        hostname_matches = list(re.finditer(r'Hostname:\s*([^"\'\\]+)', html))
        mac_matches = list(re.finditer(r'MAC:\s*([0-9A-Fa-f:]+)', html))
        ip_matches = list(re.finditer(r'IP:\s*(\d+\.\d+\.\d+\.\d+)', html))
        
        # Match them by position
        for i in range(min(len(hostname_matches), len(mac_matches), len(ip_matches))):
            name = hostname_matches[i].group(1).strip().rstrip('"').strip()
            mac = mac_matches[i].group(1).strip()
            ip = ip_matches[i].group(1).strip()
            
            # Determine connection type based on context
            # Look at the text around this match to determine if it's WiFi 5GHz, 2.4GHz, or LAN
            start_pos = hostname_matches[i].start()
            
            # Find the section markers before this device
            # WiFi sections: "WI-FI 2.4GHZ" or "WI-FI 5GHZ" in the HTML table
            # LAN section: "Rede Local" in the HTML table
            # Device info is in catFile_5g or catFile_Lan variables
            
            connection_type = "Unknown"
            interface = ""
            
            # Check the script variable name to determine section
            # Get the text around this match
            context_start = max(0, start_pos - 500)
            context = html[context_start:start_pos]
            
            # Check for LAN devices FIRST (catFile_Lan appears after catFile_5g)
            if 'catFile_Lan' in context:
                lan_match = re.search(r'LAN(\d+)', context)
                if lan_match:
                    interface = f"LAN{lan_match.group(1)}"
                connection_type = "LAN"
            # Check for WiFi 5GHz devices (catFile_5g scripts)
            elif 'catFile_5g' in context:
                # Find the SSID
                ssid_match = re.search(r'SSID:\s*(\S+)', context)
                if ssid_match:
                    interface = ssid_match.group(1)
                    if '5G' in interface:
                        connection_type = "WiFi 5GHz"
                    else:
                        connection_type = "WiFi 2.4GHz"
                else:
                    connection_type = "WiFi 5GHz"
            # Check for WiFi 2.4GHz
            elif 'catFile_24g' in context:
                connection_type = "WiFi 2.4GHz"
            
            devices.append(ConnectedDevice(
                name=name,
                ip_address=ip,
                mac_address=mac,
                connection_type=connection_type,
                status="Active",
                interface=interface
            ))
        
        # Remove duplicates based on MAC address
        seen_macs = set()
        unique_devices = []
        for device in devices:
            if device.mac_address not in seen_macs:
                seen_macs.add(device.mac_address)
                unique_devices.append(device)
        
        return unique_devices
    
    def _parse_lan_ports(self, html: str) -> List[LanPort]:
        """
        Parse LAN port status from HTML.
        """
        soup = BeautifulSoup(html, 'html.parser')
        status_table = soup.find('table', {'id': 'status'})
        
        lan_ports = []
        
        if not status_table:
            return lan_ports
        
        # Find the Rede Local (Local Network) section
        rows = status_table.find_all('tr')
        
        for row in rows:
            th = row.find('th')
            if not th:
                continue
            
            span = th.find('span')
            if not span:
                continue
            
            section_name = span.get_text(strip=True).upper()
            
            if 'REDE LOCAL' in section_name or 'LAN' in section_name:
                td = row.find('td')
                if td:
                    # Find all status divs for LAN ports
                    divs = td.find_all('div', class_=re.compile(r'status-line'))
                    
                    for div in divs:
                        strong = div.find('strong')
                        if strong:
                            port_name = strong.get_text(strip=True).replace(':', '')
                            
                            # Get device name or status
                            div_inner = div.find('div')
                            if div_inner:
                                device_name = div_inner.get_text(strip=True)
                            else:
                                device_name = ""
                            
                            # Determine status from CSS class
                            is_green = 'green' in div.get('class', [])
                            status = "Connected" if is_green else "Disconnected"
                            
                            lan_ports.append(LanPort(
                                port_name=port_name,
                                status=status,
                                device_name=device_name if device_name != "Desconectado" else ""
                            ))
                
                break
        
        return lan_ports
    
    def test_connection(self) -> bool:
        """
        Test connection to modem.
        
        Returns:
            True if modem is reachable, False otherwise
        """
        try:
            response = self._session.get(
                self.base_url,
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception as e:
            return False
