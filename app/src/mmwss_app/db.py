"""Thread-pooled psycopg connection — sync, fine for the volume we expect."""
from __future__ import annotations

from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool  # type: ignore

from .config import get_settings

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        s = get_settings()
        _pool = ConnectionPool(
            s.database_url,
            min_size=1,
            max_size=8,
            kwargs={"row_factory": dict_row},
        )
    return _pool


@contextmanager
def conn():
    pool = get_pool()
    with pool.connection() as c:
        yield c


def fetch_all(sql: str, params: tuple = ()) -> list[dict]:
    with conn() as c:
        with c.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def fetch_one(sql: str, params: tuple = ()) -> dict | None:
    with conn() as c:
        with c.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()


def execute(sql: str, params: tuple = ()) -> None:
    with conn() as c:
        with c.cursor() as cur:
            cur.execute(sql, params)
        c.commit()
