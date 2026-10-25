"""
Authentication, password hashing, session tokens, and route protection for TraceGuard AI.
Uses standard library PBKDF2-HMAC-SHA256 (600,000 iterations), constant-time comparisons,
SHA-256 hashed session tokens, CSRF protection, and role-based access control.
"""

from __future__ import annotations
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional
from fastapi import Cookie, Depends, Header, HTTPException, Request

from app.models.schemas import User, UserRole
from app.db.storage import Storage

# OWASP Recommended Work Factor for PBKDF2-HMAC-SHA256
DEFAULT_PBKDF2_ITERATIONS = 600_000
LEGACY_PBKDF2_ITERATIONS = 120_000
SESSION_DURATION_DAYS = 7

# Pre-computed dummy salt and hash for timing attack equalization
DUMMY_SALT = "a" * 32
_dummy_pwd_bytes = b"dummy_password_for_timing_mitigation"
_dummy_salt_bytes = bytes.fromhex(DUMMY_SALT)
_precomputed_dummy_hash = hashlib.pbkdf2_hmac(
    "sha256", _dummy_pwd_bytes, _dummy_salt_bytes, DEFAULT_PBKDF2_ITERATIONS
).hex()
DUMMY_HASH = f"pbkdf2_sha256${DEFAULT_PBKDF2_ITERATIONS}${_precomputed_dummy_hash}"


def get_allowed_origins() -> List[str]:
    """Returns the list of allowed CORS and CSRF origins."""
    env_origins = os.getenv("ALLOWED_ORIGINS")
    if env_origins:
        return [o.strip() for o in env_origins.split(",") if o.strip()]
    # Default development origins
    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
    ]


def is_cookie_secure(request: Request) -> bool:
    """Environment-aware secure cookie flag."""
    env = os.getenv("TRACEGUARD_ENV", "development").lower()
    if env == "production":
        return True
    return request.url.scheme == "https"


def hash_password(password: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> tuple[str, str]:
    """
    Generates a secure PBKDF2-HMAC-SHA256 hash and a 16-byte random hex salt.
    Encodes iteration count in format: pbkdf2_sha256$<iterations>$<hash>
    """
    salt = secrets.token_bytes(16).hex()
    pwd_bytes = password.encode("utf-8")
    salt_bytes = bytes.fromhex(salt)
    raw_hash = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, iterations).hex()
    formatted_hash = f"pbkdf2_sha256${iterations}${raw_hash}"
    return formatted_hash, salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """
    Verifies a plain password against the stored hash using constant-time comparison.
    Supports both new pbkdf2_sha256$<iterations>$<hash> format and legacy 120k hashes.
    """
    try:
        pwd_bytes = password.encode("utf-8")
        salt_bytes = bytes.fromhex(salt)

        if password_hash.startswith("pbkdf2_sha256$"):
            parts = password_hash.split("$")
            iterations = int(parts[1])
            expected_raw_hash = parts[2]
            computed_raw_hash = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, iterations).hex()
            return secrets.compare_digest(computed_raw_hash, expected_raw_hash)
        else:
            # Legacy hash without prefix was hashed with 120,000 iterations
            computed_raw_hash = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, LEGACY_PBKDF2_ITERATIONS).hex()
            return secrets.compare_digest(computed_raw_hash, password_hash)
    except Exception:
        return False


def verify_dummy_password(password: str) -> bool:
    """
    Runs a full PBKDF2 calculation on a dummy hash to equalize login response timing
    for non-existent accounts, eliminating timing side-channels.
    """
    return verify_password(password, DUMMY_HASH, DUMMY_SALT)


def generate_session_token() -> tuple[str, str]:
    """
    Generates a high-entropy URL-safe session token and its SHA-256 database hash.
    The raw token is returned to the client; only the hash is persisted in the database.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    return raw_token, token_hash


def hash_token(raw_token: str) -> str:
    """SHA-256 hash of a bearer or session token for storage lookups."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """Generates a high-entropy CSRF protection token."""
    return secrets.token_urlsafe(32)


def calculate_session_expiry() -> str:
    """Returns ISO-8601 UTC timestamp for session expiration."""
    return (datetime.now(timezone.utc) + timedelta(days=SESSION_DURATION_DAYS)).isoformat()


def is_session_expired(expires_at_str: str) -> bool:
    """Checks whether an ISO timestamp has expired."""
    try:
        dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > dt
    except Exception:
        return True


def extract_token_from_request(request: Request) -> Optional[str]:
    """Extracts session token from Authorization: Bearer header or traceguard_session cookie."""
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if auth_header and auth_header.strip().lower().startswith("bearer "):
        return auth_header.strip()[7:].strip()

    cookie_token = request.cookies.get("traceguard_session")
    if cookie_token:
        return cookie_token.strip()

    return None


def get_current_user(request: Request) -> User:
    """
    FastAPI dependency that extracts, verifies, and resolves the current authenticated user.
    Fails closed: missing, revoked, or expired tokens reject with HTTP 401.
    Zero test-harness bypasses in production code.
    """
    storage = Storage()
    token = extract_token_from_request(request)

    if not token:
        raise HTTPException(status_code=401, detail="Authentication required to access this resource.")

    token_h = hash_token(token)
    session = storage.get_session(token_h)
    if not session or session.get("is_revoked"):
        raise HTTPException(status_code=401, detail="Invalid or revoked session token.")

    if is_session_expired(session.get("expires_at", "")):
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    user = storage.get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="User associated with session not found.")

    return user


def require_roles(allowed_roles: List[str]) -> Callable[[User], User]:
    """Dependency factory enforcing server-side role-based access control."""

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: role '{current_user.role}' lacks permission for this action.",
            )
        return current_user

    return role_checker


def verify_csrf_and_origin(request: Request) -> None:
    """
    Validates Origin and CSRF token for cookie-authenticated state-changing requests.
    Exempts safe methods (GET, HEAD, OPTIONS) and Bearer-authenticated API calls.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    # If authenticated via Authorization: Bearer header, CSRF is not applicable
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if auth_header and auth_header.strip().lower().startswith("bearer "):
        return

    # If the client is sending a session cookie, enforce strict Origin and CSRF checks
    cookie_session = request.cookies.get("traceguard_session")
    if not cookie_session:
        return

    # 1. Validate Origin header if present
    origin = request.headers.get("origin")
    allowed = get_allowed_origins()
    if origin:
        if origin not in allowed:
            raise HTTPException(status_code=403, detail="Cross-origin request forbidden.")

    # 2. Validate CSRF token
    csrf_cookie = request.cookies.get("traceguard_csrf")
    csrf_header = request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token")

    if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie.strip(), csrf_header.strip()):
        raise HTTPException(
            status_code=403,
            detail="CSRF validation failed: missing or invalid CSRF token.",
        )
