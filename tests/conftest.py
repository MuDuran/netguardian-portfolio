"""Shared pytest fixtures."""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Point the activity logger at a throwaway database."""
    import config
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(config, "DB_PATH", db_path)
    return db_path


@pytest.fixture
def activity_logger(temp_db):
    """A fresh ActivityLogger backed by a temporary database."""
    from core.activity_logger import ActivityLogger
    logger = ActivityLogger(db_path=temp_db)
    yield logger
    logger.close()
