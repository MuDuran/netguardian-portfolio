"""Tests for the SQLite activity logger."""

import sqlite3
import threading
from datetime import datetime, timedelta

import pytest

from core.activity_logger import ActivityLogger


class TestBasicLogging:
    def test_log_and_read_back(self, activity_logger):
        assert activity_logger.log("SYSTEM", "test", "hello") is True
        events = activity_logger.get_events()
        assert len(events) == 1
        assert events[0].details == "hello"
        assert events[0].severity == "Info"

    def test_log_many_in_one_transaction(self, activity_logger):
        rows = [("SYSTEM", "test", f"event {i}") for i in range(50)]
        assert activity_logger.log_many(rows) is True
        assert activity_logger.get_event_count() == 50

    def test_log_many_with_empty_input(self, activity_logger):
        assert activity_logger.log_many([]) is True
        assert activity_logger.get_event_count() == 0

    def test_severity_defaults_when_omitted(self, activity_logger):
        activity_logger.log_many([("SYSTEM", "test", "no severity given")])
        assert activity_logger.get_events()[0].severity == "Info"


class TestConnectionReuse:
    def test_single_connection_is_held(self, activity_logger):
        assert isinstance(activity_logger._conn, sqlite3.Connection)

    def test_wal_mode_enabled(self, activity_logger):
        mode = activity_logger._query("PRAGMA journal_mode")[0][0]
        assert mode.lower() == "wal"

    def test_writes_after_many_calls(self, activity_logger):
        # The old implementation opened a connection per call; this guards the
        # reused one staying usable.
        for i in range(200):
            activity_logger.log("SYSTEM", "test", f"event {i}")
        assert activity_logger.get_event_count() == 200

    def test_close_is_idempotent(self, activity_logger):
        activity_logger.close()
        activity_logger.close()
        assert activity_logger.log("SYSTEM", "test", "after close") is False


class TestThreadSafety:
    def test_concurrent_writers(self, activity_logger):
        def writer(n):
            for i in range(20):
                activity_logger.log("SYSTEM", f"thread-{n}", f"event {i}")

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert activity_logger.get_event_count() == 160


class TestFiltering:
    def test_filter_by_event_type(self, activity_logger):
        activity_logger.log_many([
            ("FIREWALL", "s", "a"),
            ("PORT_SCAN", "s", "b"),
            ("FIREWALL", "s", "c"),
        ])
        assert len(activity_logger.get_events(event_type="FIREWALL")) == 2

    def test_limit_is_respected(self, activity_logger):
        activity_logger.log_many([("SYSTEM", "s", str(i)) for i in range(30)])
        assert len(activity_logger.get_events(limit=10)) == 10

    def test_count_by_type(self, activity_logger):
        activity_logger.log_many([
            ("FIREWALL", "s", "a"),
            ("PORT_SCAN", "s", "b"),
        ])
        assert activity_logger.get_event_count("FIREWALL") == 1
        assert activity_logger.get_event_count() == 2


class TestPruning:
    def _insert_at(self, logger, when, details):
        with logger._lock:
            logger._conn.execute(
                "INSERT INTO activity_logs (timestamp, event_type, source, details, severity)"
                " VALUES (?, ?, ?, ?, ?)",
                (when.strftime("%Y-%m-%d %H:%M:%S"), "SYSTEM", "s", details, "Info"),
            )
            logger._conn.commit()

    def test_prunes_only_old_rows(self, activity_logger):
        now = datetime.now()
        self._insert_at(activity_logger, now - timedelta(days=90), "ancient")
        self._insert_at(activity_logger, now - timedelta(days=1), "recent")

        deleted = activity_logger.prune(days=30)

        assert deleted == 1
        remaining = activity_logger.get_events()
        assert len(remaining) == 1
        assert remaining[0].details == "recent"

    def test_prune_on_empty_db(self, activity_logger):
        assert activity_logger.prune(days=30) == 0


class TestExport:
    def test_csv_export(self, activity_logger, tmp_path):
        activity_logger.log_many([("SYSTEM", "s", "one"), ("SYSTEM", "s", "two")])
        out = tmp_path / "events.csv"

        assert activity_logger.export_events_csv(out) is True

        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3  # header + 2 rows
        assert lines[0].startswith("Timestamp,Event Type")


class TestSingleton:
    def test_instance_is_shared(self, monkeypatch, tmp_path):
        import config
        monkeypatch.setattr(config, "DB_PATH", tmp_path / "singleton.db")
        monkeypatch.setattr(ActivityLogger, "_instance", None)

        first = ActivityLogger.instance()
        try:
            assert ActivityLogger.instance() is first
        finally:
            first.close()
            ActivityLogger._instance = None
