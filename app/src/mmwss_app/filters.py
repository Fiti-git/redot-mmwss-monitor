"""Jinja filters — number formatting, byte sizes, time ago."""
from __future__ import annotations

from datetime import datetime, timezone


def human_bytes(n) -> str:
    if n is None:
        return "—"
    try:
        num = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} PB"


def fmt_int(n) -> str:
    if n is None:
        return "—"
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def fmt_pct(n, digits: int = 1) -> str:
    if n is None:
        return "—"
    return f"{float(n):.{digits}f}%"


def time_ago(dt) -> str:
    if not dt:
        return "—"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    s = int(delta.total_seconds())
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def date_only(dt) -> str:
    if not dt:
        return "—"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return dt
    return dt.strftime("%Y-%m-%d")


def datetime_str(dt) -> str:
    if not dt:
        return "—"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return dt
    return dt.strftime("%Y-%m-%d %H:%M")


def register(env) -> None:
    env.filters["human_bytes"] = human_bytes
    env.filters["fmt_int"] = fmt_int
    env.filters["fmt_pct"] = fmt_pct
    env.filters["time_ago"] = time_ago
    env.filters["date_only"] = date_only
    env.filters["datetime_str"] = datetime_str
