"""
Pytest configuration and global fixtures.
Ensures synthetic sandbox database is fresh and gateway sessions/emergency stop are clean.
"""

from pathlib import Path
import pytest
from app.tools.db_init import init_sandbox_db
from app.tools.controlled_tools import DB_SANDBOX_PATH


@pytest.fixture(autouse=True)
def ensure_fresh_sandbox_db():
    init_sandbox_db(DB_SANDBOX_PATH)
    from app.api.routes import gateway
    gateway.set_emergency_stop(False)
    gateway.sessions.clear()
    yield
    init_sandbox_db(DB_SANDBOX_PATH)
    gateway.set_emergency_stop(False)
    gateway.sessions.clear()
