"""
Command-line interface for TraceGuard AI administration.
Allows secure bootstrapping and management of initial administrator accounts.
"""

from __future__ import annotations
import argparse
import secrets
import sys
from pathlib import Path

# Ensure backend root is in python path
_backend_dir = Path(__file__).resolve().parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from app.db.storage import Storage
from app.gateway.auth import hash_password


def create_admin(email: str, password: str, full_name: str) -> None:
    storage = Storage()
    email_clean = email.strip().lower()

    if len(password) < 8:
        print("Error: Password must be at least 8 characters long.", file=sys.stderr)
        sys.exit(1)

    existing = storage.get_user_by_email(email_clean)
    if existing:
        print(f"Error: User with email '{email_clean}' already exists.", file=sys.stderr)
        sys.exit(1)

    pwd_hash, salt = hash_password(password)
    user_id = f"usr_{secrets.token_hex(6)}"
    user = storage.create_user(
        user_id=user_id,
        email=email_clean,
        password_hash=pwd_hash,
        salt=salt,
        full_name=full_name.strip(),
        role="admin",
    )
    print(f"Successfully created Administrator account: {user.email} (ID: {user.id})")


def main():
    parser = argparse.ArgumentParser(description="TraceGuard AI Administrative CLI")
    subparsers = parser.add_subparsers(dest="command")

    admin_parser = subparsers.add_parser("create-admin", help="Bootstrap a new Administrator account")
    admin_parser.add_argument("--email", required=True, help="Administrator email address")
    admin_parser.add_argument("--password", required=True, help="Secure password (min 8 chars)")
    admin_parser.add_argument("--name", default="SecOps Admin", help="Full name of administrator")

    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(args.email, args.password, args.name)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
