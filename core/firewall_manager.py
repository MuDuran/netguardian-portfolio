"""
Firewall Manager Module
Manages Windows Firewall rules using netsh commands.
"""

import ctypes
import logging
import unicodedata
import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

from utils.timing import timed

logger = logging.getLogger(__name__)

# Keeps netsh from flashing a console window in the windowed build.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a console command without popping up a window."""
    return subprocess.run(
        cmd,
        capture_output=True,
        timeout=timeout,
        creationflags=_NO_WINDOW,
    )


def _decode(raw: bytes) -> str:
    """
    Decode console output.

    The console code page varies by machine: UTF-8 (65001) on this one, but
    cp850 on a stock pt-BR install. Try each strictly and take the first that
    decodes cleanly, so accented labels like "Ação:" survive intact. Decoding
    as latin-1 unconditionally is what produced the mojibake field names the
    old parser had to special-case.
    """
    if not raw:
        return ""
    for encoding in ("utf-8", "oem", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")

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
class FirewallRule:
    """Firewall rule information."""
    name: str
    action: str  # Allow, Block
    protocol: str  # TCP, UDP, Any
    port: str  # Port number or range
    direction: str  # Inbound, Outbound
    enabled: bool
    profile: str  # Domain, Private, Public, Any


class FirewallManager:
    """
    Windows Firewall manager using netsh commands.
    
    Creates and manages firewall rules with a specific prefix
    to identify NetGuardian rules.
    """
    
    RULE_PREFIX = "NetGuardian"
    
    # Process-wide: elevation cannot change while the app runs, so there is no
    # reason to re-check it every time a manager is constructed.
    _admin_cache: Optional[bool] = None

    def __init__(self):
        """Initialize the firewall manager."""
        self._is_admin = self._check_admin_privileges()

    @classmethod
    def _check_admin_privileges(cls) -> bool:
        """
        Check if running with administrator privileges.

        Uses the Win32 API directly. The old version shelled out to
        `netsh advfirewall show allprofiles` on every construction, which cost
        a subprocess spawn (~200ms) just to answer a boolean.
        """
        if cls._admin_cache is None:
            try:
                cls._admin_cache = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except (AttributeError, OSError) as e:
                logger.debug(f"Could not determine admin status: {e}")
                cls._admin_cache = False
        return cls._admin_cache


    @property
    def is_admin(self) -> bool:
        """Check if running as administrator."""
        return self._is_admin
    
    @timed("FirewallManager.get_rules")
    def get_rules(self) -> List[FirewallRule]:
        """
        Get all NetGuardian firewall rules.

        Returns:
            List of FirewallRule objects
        """
        return self._fetch_rules(netguardian_only=True)

    @timed("FirewallManager.get_all_rules")
    def get_all_rules(self) -> List[FirewallRule]:
        """
        Get ALL Windows Firewall rules (not just NetGuardian).

        Returns:
            List of FirewallRule objects for all rules
        """
        return self._fetch_rules(netguardian_only=False)

    def _fetch_rules(self, netguardian_only: bool) -> List[FirewallRule]:
        """
        Dump every firewall rule in one netsh call and parse it.

        The previous implementation ran the full `show rule name=all` dump
        twice, once per direction, and each dump is the expensive part. The
        direction is already present in each rule block, so one call is enough.

        Args:
            netguardian_only: Keep only rules created by this app

        Returns:
            List of FirewallRule objects
        """
        try:
            result = _run([
                "netsh", "advfirewall", "firewall", "show", "rule", "name=all",
            ])

            if result.returncode != 0:
                logger.warning(f"netsh failed: {_decode(result.stderr).strip()}")
                return []

            return self._parse_rules(_decode(result.stdout), netguardian_only)

        except subprocess.TimeoutExpired:
            logger.error("Timed out reading firewall rules")
            return []
        except OSError as e:
            logger.error(f"Failed to get rules: {e}")
            return []

    # netsh localizes its field labels, so match on every spelling we know of.
    # Compared against a casefolded, accent-stripped line, which is why the
    # Portuguese entries appear here without accents.
    FIELD_NAMES = {
        "rule_name": ("rule name:", "nome da regra:"),
        "enabled": ("enabled:", "habilitado:", "habilitada:"),
        "action": ("action:", "acao:"),
        "protocol": ("protocol:", "protocolo:"),
        "local_port": ("localport:", "porta local:"),
        "profile": ("profile:", "perfis:", "perfil:"),
        "direction": ("direction:", "direcao:"),
    }

    ENABLED_VALUES = ("yes", "sim")
    ACTION_VALUES = {"permitir": "Allow", "bloquear": "Block",
                     "allow": "Allow", "block": "Block"}
    DIRECTION_VALUES = {"in": "Inbound", "entrada": "Inbound",
                        "out": "Outbound", "saida": "Outbound"}
    # netsh prints the localized word for "any"; keep the UI in one language.
    ANY_VALUES = ("qualquer", "any", "todos")

    @classmethod
    def _localized_any(cls, value: str, default: str = "Any") -> str:
        """Map a localized 'any' to the English label, otherwise pass through."""
        if not value:
            return default
        return "Any" if cls._normalize(value) in cls.ANY_VALUES else value

    @staticmethod
    def _normalize(text: str) -> str:
        """Casefold and strip accents so label matching is locale-tolerant."""
        decomposed = unicodedata.normalize("NFKD", text)
        return "".join(c for c in decomposed if not unicodedata.combining(c)).lower()

    @classmethod
    def _field(cls, line_normalized: str, field: str) -> bool:
        """Whether a normalized line starts with any label for this field."""
        return line_normalized.startswith(cls.FIELD_NAMES[field])

    def _parse_rules(self, output: str, netguardian_only: bool) -> List[FirewallRule]:
        """Parse the text netsh dump into FirewallRule objects."""
        rules: List[FirewallRule] = []
        block: List[str] = []

        def flush():
            rule = self._parse_block(block, netguardian_only)
            if rule is not None:
                rules.append(rule)

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if self._field(self._normalize(line), "rule_name") and block:
                flush()
                block = [line]
            else:
                block.append(line)

        if block:
            flush()

        return rules

    def _parse_block(self, block: List[str], netguardian_only: bool) -> Optional[FirewallRule]:
        """Turn one netsh rule block into a FirewallRule, or None to skip it."""
        fields: Dict[str, str] = {}

        for line in block:
            normalized = self._normalize(line)
            for field in self.FIELD_NAMES:
                if self._field(normalized, field) and field not in fields:
                    fields[field] = line.split(":", 1)[1].strip()
                    break

        name = fields.get("rule_name", "")
        if not name:
            return None
        if netguardian_only and not name.startswith(self.RULE_PREFIX):
            return None

        direction_raw = self._normalize(fields.get("direction", ""))
        enabled_raw = self._normalize(fields.get("enabled", "yes"))
        action_raw = self._normalize(fields.get("action", ""))

        return FirewallRule(
            name=name,
            action=self.ACTION_VALUES.get(action_raw, fields.get("action", "")),
            protocol=self._localized_any(fields.get("protocol", "")),
            port=self._localized_any(fields.get("local_port", "")),
            direction=self.DIRECTION_VALUES.get(direction_raw, "Inbound"),
            enabled=enabled_raw in self.ENABLED_VALUES,
            profile=fields.get("profile", "Any"),
        )

    
    def add_rule(
        self,
        name: str,
        action: str,
        protocol: str,
        port: str,
        direction: str,
        enabled: bool = True
    ) -> bool:
        """
        Add a new firewall rule.
        
        Args:
            name: Rule name
            action: "Allow" or "Block"
            protocol: "TCP", "UDP", or "Any"
            port: Port number or range (e.g., "80", "80,443", "1-1024")
            direction: "Inbound" or "Outbound"
            enabled: Whether rule is enabled
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Build the rule name with prefix
            full_name = f"{self.RULE_PREFIX} - {name}"
            
            # Map UI values to netsh values (lowercase)
            action_map = {"Allow": "allow", "Block": "block"}
            protocol_map = {"TCP": "tcp", "UDP": "udp", "Any": "any"}
            direction_map = {"Inbound": "in", "Outbound": "out"}
            
            netsh_action = action_map.get(action, action.lower())
            netsh_protocol = protocol_map.get(protocol, protocol.lower())
            netsh_direction = direction_map.get(direction, direction.lower())
            
            # Build netsh command
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={full_name}",
                f"action={netsh_action}",
                f"protocol={netsh_protocol}",
                f"localport={port}",
                f"dir={netsh_direction}",
                f"enable={'yes' if enabled else 'no'}",
                "profile=any"
            ]
            
            result = _run(cmd)
            
            if result.returncode == 0:
                logger.info(f"Rule '{full_name}' added successfully")
                
                # Log to activity logger
                try:
                    act_logger = get_activity_logger()
                    act_logger.log_firewall_rule_added(name, action, port)
                except Exception as e:
                    logger.debug(f"Non-fatal error: {e}")
                
                return True
            else:
                error_msg = _decode(result.stderr) or _decode(result.stdout)
                logger.error(f"Failed to add rule: {error_msg.strip()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to add rule: {e}")
            return False
    
    def delete_rule(self, name: str) -> bool:
        """
        Delete a firewall rule by name.
        
        Args:
            name: Rule name (without prefix)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            full_name = f"{self.RULE_PREFIX} - {name}"
            
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={full_name}"
            ]
            
            result = _run(cmd)
            
            if result.returncode == 0:
                logger.info(f"Rule '{full_name}' deleted successfully")
                
                # Log to activity logger
                try:
                    act_logger = get_activity_logger()
                    act_logger.log_firewall_rule_deleted(name)
                except Exception as e:
                    logger.debug(f"Non-fatal error: {e}")
                
                return True
            else:
                logger.error(f"Failed to delete rule: {_decode(result.stderr).strip()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to delete rule: {e}")
            return False
    
    def enable_rule(self, name: str) -> bool:
        """
        Enable a firewall rule.
        
        Args:
            name: Rule name (without prefix)
            
        Returns:
            True if successful, False otherwise
        """
        return self._set_rule_enabled(name, True)
    
    def disable_rule(self, name: str) -> bool:
        """
        Disable a firewall rule.
        
        Args:
            name: Rule name (without prefix)
            
        Returns:
            True if successful, False otherwise
        """
        return self._set_rule_enabled(name, False)
    
    def _set_rule_enabled(self, name: str, enabled: bool) -> bool:
        """Set the enabled state of a rule."""
        try:
            full_name = f"{self.RULE_PREFIX} - {name}"
            
            cmd = [
                "netsh", "advfirewall", "firewall", "set", "rule",
                f"name={full_name}",
                f"new", f"enable={'yes' if enabled else 'no'}"
            ]
            
            result = _run(cmd)
            
            if result.returncode == 0:
                state = "enabled" if enabled else "disabled"
                logger.info(f"Rule '{full_name}' {state}")
                return True
            else:
                logger.error(f"Failed to update rule: {_decode(result.stderr).strip()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update rule: {e}")
            return False
    
    def rule_exists(self, name: str) -> bool:
        """
        Check if a rule exists.
        
        Args:
            name: Rule name (without prefix)
            
        Returns:
            True if rule exists, False otherwise
        """
        rules = self.get_rules()
        full_name = f"{self.RULE_PREFIX} - {name}"
        return any(r.name == full_name for r in rules)
    
    def get_rule_count(self) -> int:
        """Get the number of NetGuardian rules."""
        return len(self.get_rules())
