"""
Activity Logger Module
Records network events with timestamps using SQLite database.

Uses a single long-lived connection in WAL mode guarded by a lock, because
events are logged from Qt worker threads as well as the GUI thread.
"""

import csv
import logging
import sqlite3
import threading
from typing import Iterable, List, Optional, Sequence, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import config
from utils.timing import timed

logger = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        source TEXT NOT NULL,
        details TEXT NOT NULL,
        severity TEXT DEFAULT 'Info'
    )
"""

CREATE_TIMESTAMP_INDEX_SQL = """
    CREATE INDEX IF NOT EXISTS idx_timestamp ON activity_logs(timestamp)
"""

CREATE_EVENT_TYPE_INDEX_SQL = """
    CREATE INDEX IF NOT EXISTS idx_event_type ON activity_logs(event_type)
"""

INSERT_SQL = """
    INSERT INTO activity_logs (event_type, source, details, severity)
    VALUES (?, ?, ?, ?)
"""

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass
class ActivityEvent:
    """Activity event information."""
    id: int
    timestamp: datetime
    event_type: str
    source: str
    details: str
    severity: str  # Info, Warning, Error


def _parse_timestamp(value: str) -> datetime:
    """Parse a timestamp column, tolerating both storage formats."""
    for parse in (
        lambda v: datetime.strptime(v, TIMESTAMP_FORMAT),
        datetime.fromisoformat,
    ):
        try:
            return parse(value)
        except (ValueError, TypeError):
            continue
    return datetime.now()


class ActivityLogger:
    """
    Network activity logger using SQLite database.

    Records events from all features with timestamps for
    audit trail and troubleshooting.
    """

    # Event types
    EVENT_TYPES = {
        "DEVICE_DISCOVERY": "Device Discovery",
        "TRAFFIC_MONITOR": "Traffic Monitor",
        "PORT_SCAN": "Port Scanner",
        "MODEM_STATUS": "Modem Status",
        "FIREWALL": "Firewall Manager",
        "SYSTEM": "System"
    }

    # Severity levels
    SEVERITY_INFO = "Info"
    SEVERITY_WARNING = "Warning"
    SEVERITY_ERROR = "Error"

    _instance: Optional["ActivityLogger"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "ActivityLogger":
        """
        Get the shared logger.

        Every feature module logs through this so the process holds exactly one
        database connection instead of one per module.
        """
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the activity logger.

        Args:
            db_path: Path to SQLite database file (default: from config)
        """
        self.db_path = db_path or config.DB_PATH
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_database()

    def _init_database(self):
        """Open the connection and create tables and indexes if needed."""
        try:
            # check_same_thread=False because QThread workers log too; every
            # access is serialized through self._lock.
            self._conn = sqlite3.connect(
                self.db_path,
                timeout=config.DB_TIMEOUT,
                check_same_thread=False,
            )

            with self._lock:
                cursor = self._conn.cursor()

                # WAL lets readers and the writer work concurrently and avoids
                # an fsync per commit, which matters when a scan logs a burst
                # of events.
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")

                cursor.execute(CREATE_TABLE_SQL)
                cursor.execute(CREATE_TIMESTAMP_INDEX_SQL)
                cursor.execute(CREATE_EVENT_TYPE_INDEX_SQL)

                self._conn.commit()

            logger.info(f"Activity logger initialized: {self.db_path}")

        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def close(self):
        """Close the database connection."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error as e:
                    logger.debug(f"Error closing database: {e}")
                self._conn = None

    def log(
        self,
        event_type: str,
        source: str,
        details: str,
        severity: str = "Info"
    ) -> bool:
        """
        Log an activity event.

        Args:
            event_type: Type of event (e.g., "DEVICE_DISCOVERY", "FIREWALL")
            source: Source of the event (e.g., "ARP Scanner", "Rule Manager")
            details: Event details/description
            severity: Severity level (Info, Warning, Error)

        Returns:
            True if successful, False otherwise
        """
        return self.log_many([(event_type, source, details, severity)])

    def log_many(self, events: Iterable[Sequence[str]]) -> bool:
        """
        Log several events in a single transaction.

        Preferred over calling log() in a loop: a network scan can produce
        dozens of events and one commit is far cheaper than one per row.

        Args:
            events: Iterable of (event_type, source, details, severity) tuples.
                    Severity may be omitted and defaults to Info.

        Returns:
            True if successful, False otherwise
        """
        rows: List[Tuple[str, str, str, str]] = []
        for event in events:
            event_type, source, details = event[0], event[1], event[2]
            severity = event[3] if len(event) > 3 else self.SEVERITY_INFO
            rows.append((event_type, source, details, severity))

        if not rows:
            return True

        try:
            with self._lock:
                if self._conn is None:
                    return False
                self._conn.executemany(INSERT_SQL, rows)
                self._conn.commit()
            logger.debug(f"Logged {len(rows)} event(s)")
            return True

        except sqlite3.Error as e:
            logger.error(f"Failed to log event(s): {e}")
            return False

    def _query(self, sql: str, params: Sequence = ()) -> List[tuple]:
        """Run a read query under the connection lock."""
        with self._lock:
            if self._conn is None:
                return []
            cursor = self._conn.execute(sql, params)
            return cursor.fetchall()

    @timed("ActivityLogger.get_events")
    def get_events(
        self,
        event_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[ActivityEvent]:
        """
        Get activity events with optional filters.

        Args:
            event_type: Filter by event type
            start_date: Filter by start date
            end_date: Filter by end date
            limit: Maximum number of events to return

        Returns:
            List of ActivityEvent objects
        """
        query = "SELECT id, timestamp, event_type, source, details, severity FROM activity_logs"
        params: List = []
        conditions = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date.strftime(TIMESTAMP_FORMAT))

        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date.strftime(TIMESTAMP_FORMAT))

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        try:
            return [
                ActivityEvent(
                    id=row[0],
                    timestamp=_parse_timestamp(row[1]),
                    event_type=row[2],
                    source=row[3],
                    details=row[4],
                    severity=row[5]
                )
                for row in self._query(query, params)
            ]
        except sqlite3.Error as e:
            logger.error(f"Failed to get events: {e}")
            return []

    def get_events_by_type(self, event_type: str, limit: int = 50) -> List[ActivityEvent]:
        """Get events filtered by type."""
        return self.get_events(event_type=event_type, limit=limit)

    def get_recent_events(self, hours: int = 24, limit: int = 100) -> List[ActivityEvent]:
        """Get events from the last N hours."""
        start_date = datetime.now() - timedelta(hours=hours)
        return self.get_events(start_date=start_date, limit=limit)

    def get_event_count(self, event_type: Optional[str] = None) -> int:
        """Get total number of events."""
        try:
            if event_type:
                rows = self._query(
                    "SELECT COUNT(*) FROM activity_logs WHERE event_type = ?",
                    (event_type,)
                )
            else:
                rows = self._query("SELECT COUNT(*) FROM activity_logs")
            return rows[0][0] if rows else 0

        except sqlite3.Error as e:
            logger.error(f"Failed to count events: {e}")
            return 0

    def clear_events(self, older_than_days: Optional[int] = None) -> bool:
        """
        Clear events from the database.

        Args:
            older_than_days: Only clear events older than N days (None = clear all)

        Returns:
            True if successful, False otherwise
        """
        try:
            with self._lock:
                if self._conn is None:
                    return False
                if older_than_days:
                    cutoff = datetime.now() - timedelta(days=older_than_days)
                    self._conn.execute(
                        "DELETE FROM activity_logs WHERE timestamp < ?",
                        (cutoff.strftime(TIMESTAMP_FORMAT),)
                    )
                else:
                    self._conn.execute("DELETE FROM activity_logs")
                self._conn.commit()

            logger.info(f"Cleared events (older than {older_than_days} days)")
            return True

        except sqlite3.Error as e:
            logger.error(f"Failed to clear events: {e}")
            return False

    def prune(self, days: Optional[int] = None) -> int:
        """
        Delete events older than the retention window.

        Called once at startup so the log cannot grow without bound.

        Args:
            days: Retention window in days (default: config.LOG_RETENTION_DAYS)

        Returns:
            Number of rows deleted
        """
        days = days if days is not None else config.LOG_RETENTION_DAYS
        try:
            cutoff = datetime.now() - timedelta(days=days)
            with self._lock:
                if self._conn is None:
                    return 0
                cursor = self._conn.execute(
                    "DELETE FROM activity_logs WHERE timestamp < ?",
                    (cutoff.strftime(TIMESTAMP_FORMAT),)
                )
                deleted = cursor.rowcount or 0
                self._conn.commit()

            if deleted:
                logger.info(f"Pruned {deleted} activity log row(s) older than {days} days")
            return deleted

        except sqlite3.Error as e:
            logger.error(f"Failed to prune events: {e}")
            return 0

    def export_events_csv(self, file_path: Path) -> bool:
        """
        Export events to CSV file.

        Args:
            file_path: Path to CSV file

        Returns:
            True if successful, False otherwise
        """
        try:
            events = self.get_events(limit=10000)  # Get all events

            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Event Type", "Source", "Details", "Severity"])

                for event in events:
                    writer.writerow([
                        event.timestamp.isoformat(),
                        event.event_type,
                        event.source,
                        event.details,
                        event.severity
                    ])

            logger.info(f"Exported events to {file_path}")
            return True

        except OSError as e:
            logger.error(f"Failed to export events: {e}")
            return False

    # Convenience methods for logging common events

    def log_device_discovered(self, ip: str, mac: str, hostname: str):
        """Log a device discovery event."""
        self.log(
            event_type="DEVICE_DISCOVERY",
            source="ARP Scanner",
            details=f"Device discovered: {ip} ({mac}) - {hostname}"
        )

    def log_devices_discovered(self, devices: Sequence[dict]):
        """Log a batch of discovered devices in one transaction."""
        self.log_many([
            (
                "DEVICE_DISCOVERY",
                "ARP Scanner",
                f"Device discovered: {d.get('ip', '')} ({d.get('mac', '')}) - {d.get('hostname', '')}",
                self.SEVERITY_INFO,
            )
            for d in devices
        ])

    def log_scan_started(self, target: str, scan_type: str):
        """Log a scan start event."""
        self.log(
            event_type="PORT_SCAN",
            source="Port Scanner",
            details=f"Scan started: {target} ({scan_type})"
        )

    def log_scan_completed(self, target: str, ports_found: int):
        """Log a scan completion event."""
        self.log(
            event_type="PORT_SCAN",
            source="Port Scanner",
            details=f"Scan completed: {target} - {ports_found} ports found"
        )

    def log_firewall_rule_added(self, rule_name: str, action: str, port: str):
        """Log a firewall rule addition."""
        self.log(
            event_type="FIREWALL",
            source="Rule Manager",
            details=f"Rule added: {rule_name} - {action} port {port}"
        )

    def log_firewall_rule_deleted(self, rule_name: str):
        """Log a firewall rule deletion."""
        self.log(
            event_type="FIREWALL",
            source="Rule Manager",
            details=f"Rule deleted: {rule_name}"
        )

    def log_traffic_monitoring_started(self, interface: str):
        """Log traffic monitoring start."""
        self.log(
            event_type="TRAFFIC_MONITOR",
            source="Traffic Monitor",
            details=f"Monitoring started: {interface or 'all interfaces'}"
        )

    def log_traffic_monitoring_stopped(self):
        """Log traffic monitoring stop."""
        self.log(
            event_type="TRAFFIC_MONITOR",
            source="Traffic Monitor",
            details="Monitoring stopped"
        )

    def log_modem_status_loaded(self, modem_ip: str):
        """Log modem status load."""
        self.log(
            event_type="MODEM_STATUS",
            source="Modem Scraper",
            details=f"Modem status loaded: {modem_ip}"
        )
