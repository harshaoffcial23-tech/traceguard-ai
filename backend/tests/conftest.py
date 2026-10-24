"""
Pytest configuration and global fixtures.
Ensures synthetic sandbox database is fresh for every test module.
"""

from pathlib import Path
import pytest
from app.tools.db_init import init_sandbox_db
from app.tools.controlled_tools import DB_SANDBOX_PATH


@pytest.fixture(autouse=True)
def ensure_fresh_sandbox_db():
    init_sandbox_db(DB_SANDBOX_PATH)
    yield
    init_sandbox_db(DB_SANDBOX_PATH)
