"""
Pytest configuration and global fixtures.
Ensures synthetic sandbox database is fresh, rate limits are clean,
and handles authentication dependency overrides for legacy tests.
"""

from pathlib import Path
import pytest
from app.main import app
from app.tools.db_init import init_sandbox_db
from app.tools.controlled_tools import DB_SANDBOX_PATH
from app.gateway.auth import get_current_user
from app.models.schemas import User
from app.gateway.rate_limiter import rate_limiter

_test_admin_fixture = User(
    id="usr_test_fixture_admin",
    email="fixture_admin@traceguard.internal",
    full_name="Fixture Admin",
    role="admin",
    created_at="2026-01-01T00:00:00",
)


@pytest.fixture(autouse=True)
def ensure_fresh_sandbox_db(request):
    init_sandbox_db(DB_SANDBOX_PATH)
    rate_limiter.reset()
    from app.api.routes import gateway
    gateway.set_emergency_stop(False)
    gateway.sessions.clear()

    # Determine if current test file explicitly tests authentication & security rules
    test_path_str = str(getattr(request.node, "path", "")) or str(getattr(request, "path", ""))
    is_auth_or_sec_test = "test_auth" in test_path_str or "test_security" in test_path_str

    if is_auth_or_sec_test:
        # Auth tests must exercise real authentication without fixture bypasses
        app.dependency_overrides.pop(get_current_user, None)
    else:
        # Legacy non-auth test suites receive standard authorized admin fixture via FastAPI override
        app.dependency_overrides[get_current_user] = lambda: _test_admin_fixture

    yield

    app.dependency_overrides.pop(get_current_user, None)
    init_sandbox_db(DB_SANDBOX_PATH)
    gateway.set_emergency_stop(False)
    gateway.sessions.clear()
    rate_limiter.reset()
