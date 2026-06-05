import logging
import re
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path("/app/migrations")


@contextmanager
def connect(database_url: str):
    """Yield a psycopg connection with dict rows and autocommit off."""
    with psycopg.connect(database_url, row_factory=dict_row) as conn:
        yield conn


def ensure_migrations_table(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute("CREATE SCHEMA IF NOT EXISTS mmwss")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS mmwss._migrations (
                filename TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    conn.commit()


def applied_migrations(conn: psycopg.Connection) -> set[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT filename FROM mmwss._migrations ORDER BY filename")
        return {row["filename"] for row in cur.fetchall()}


def apply_pending_migrations(conn: psycopg.Connection, directory: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply every *.sql file not yet in mmwss._migrations, in lexical order."""
    ensure_migrations_table(conn)
    done = applied_migrations(conn)
    pending = sorted(p for p in directory.glob("*.sql") if p.name not in done)
    applied: list[str] = []
    for path in pending:
        log.info("Applying migration %s", path.name)
        sql = path.read_text(encoding="utf-8")
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute("INSERT INTO mmwss._migrations (filename) VALUES (%s)", (path.name,))
        conn.commit()
        applied.append(path.name)
    if not applied:
        log.info("No pending migrations")
    return applied


# ───────── CF token helpers (encrypted via pgcrypto) ─────────


def upsert_cf_token(conn: psycopg.Connection, *, label: str, token: str, master_key: str) -> int:
    """Insert or update a CF token row (one per label). Returns the cf_tokens.id."""
    last_4 = token[-4:]
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO mmwss.cf_tokens (label, encrypted_token, last_4)
            VALUES (%s, pgp_sym_encrypt(%s, %s), %s)
            ON CONFLICT (label) DO UPDATE SET
                encrypted_token = EXCLUDED.encrypted_token,
                last_4 = EXCLUDED.last_4
            RETURNING id
            """,
            (label, token, master_key, last_4),
        )
        row = cur.fetchone()
        conn.commit()
        if row is None:
            raise RuntimeError("Failed to upsert CF token")
        return row["id"]


def get_active_cf_tokens(conn: psycopg.Connection, master_key: str) -> list[dict]:
    """Return [{id, label, token (plaintext), last_4}, ...]."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, label, last_4,
                   pgp_sym_decrypt(encrypted_token, %s) AS token
            FROM mmwss.cf_tokens
            ORDER BY id
            """,
            (master_key,),
        )
        return cur.fetchall()


# ───────── Zones ─────────

ZONE_NAME_RE = re.compile(r"^[a-z0-9.-]{1,253}$", re.IGNORECASE)


def upsert_zone(conn: psycopg.Connection, *, cf_zone_id: str, cf_token_id: int,
                name: str, plan: str | None, status: str | None,
                name_servers: list[str]) -> int:
    if not ZONE_NAME_RE.match(name):
        raise ValueError(f"Refusing to insert zone with suspicious name: {name!r}")
    import json
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO mmwss.zones
                (cf_zone_id, cf_token_id, name, plan, status, name_servers_json, last_synced_at)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, now())
            ON CONFLICT (cf_zone_id) DO UPDATE SET
                cf_token_id = EXCLUDED.cf_token_id,
                name = EXCLUDED.name,
                plan = EXCLUDED.plan,
                status = EXCLUDED.status,
                name_servers_json = EXCLUDED.name_servers_json,
                last_synced_at = now()
            RETURNING id
            """,
            (cf_zone_id, cf_token_id, name, plan, status, json.dumps(name_servers)),
        )
        row = cur.fetchone()
        conn.commit()
        return row["id"]
