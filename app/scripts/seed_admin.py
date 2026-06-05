"""Seed or update the bootstrap admin user.

Reads MMWSS_ADMIN_EMAIL, MMWSS_ADMIN_NAME, MMWSS_ADMIN_PASSWORD from env.
Idempotent — updates the row if the email already exists.

Run on VPS:
    docker compose run --rm app python scripts/seed_admin.py
"""
import os
import sys
from pathlib import Path

# Make src/ importable when run as `python scripts/seed_admin.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mmwss_app import auth, db  # noqa: E402


def main() -> int:
    email = (os.environ.get("MMWSS_ADMIN_EMAIL") or "").lower().strip()
    name = os.environ.get("MMWSS_ADMIN_NAME") or "Admin"
    password = os.environ.get("MMWSS_ADMIN_PASSWORD") or ""

    if not email or not password:
        print("ERROR: MMWSS_ADMIN_EMAIL and MMWSS_ADMIN_PASSWORD must be set", file=sys.stderr)
        return 2
    if len(password) < 12:
        print("ERROR: password must be at least 12 characters", file=sys.stderr)
        return 3

    h = auth.hash_password(password)
    existing = db.fetch_one("SELECT id FROM mmwss.users WHERE email = %s", (email,))
    if existing:
        db.execute(
            """
            UPDATE mmwss.users
            SET name = %s, password_hash = %s, role = 'admin', is_active = TRUE, updated_at = now()
            WHERE email = %s
            """,
            (name, h, email),
        )
        print(f"Updated admin user: {email}")
    else:
        db.execute(
            """
            INSERT INTO mmwss.users (email, name, password_hash, role, is_active)
            VALUES (%s, %s, %s, 'admin', TRUE)
            """,
            (email, name, h),
        )
        print(f"Created admin user: {email}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
