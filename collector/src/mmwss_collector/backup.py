"""Daily encrypted DB backup job.

What it does (runs in the collector scheduler):
  1. pg_dump → gzip → AES-256-GCM encrypt (key = mmwss_master_key)
  2. Write to /app/reports/backups/mmwss-{YYYY-MM-DD-HHMM}.sql.gz.enc
  3. Hash + size + status into mmwss.backup_runs
  4. Retain 30 days locally; older files deleted
  5. If BACKUP_S3_BUCKET is set, upload to S3 (best-effort)

Why AES-GCM with the existing master key:
  - Same key already used for pgcrypto column-level encryption
  - One key to rotate (and to lose)
  - GCM gives authenticated encryption — tamper detection on the backup

Restore procedure (documented in DR runbook):
  1. openssl enc -aes-256-gcm -d -K $MASTER_HEX -iv $IV ... (or use the
     companion `restore_backup` helper)
  2. gunzip → psql to a fresh database
"""
from __future__ import annotations

import gzip
import hashlib
import logging
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

BACKUP_DIR = Path(os.environ.get("MMWSS_BACKUPS_DIR", "/app/reports/backups"))
RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", "30"))


def _master_key_bytes(hex_key: str) -> bytes:
    """Master key is 64 hex chars = 32 bytes — exactly AES-256 size."""
    if len(hex_key) != 64:
        raise ValueError("MMWSS_MASTER_KEY must be 64 hex chars (32 bytes)")
    return bytes.fromhex(hex_key)


def _open_backup_run(conn) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO mmwss.backup_runs (status) VALUES ('running') RETURNING id"
        )
        rid = cur.fetchone()["id"]
    conn.commit()
    return rid


def _close_backup_run(conn, run_id: int, *, status: str, artifact_path: str | None,
                       artifact_size: int | None, sha256_hex: str | None,
                       encrypted: bool, error: str | None,
                       pushed_remote: bool = False, remote_url: str | None = None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE mmwss.backup_runs
               SET status = %s,
                   finished_at = now(),
                   duration_secs = GREATEST(0, EXTRACT(EPOCH FROM (now() - started_at))::int),
                   artifact_path = %s,
                   artifact_size = %s,
                   artifact_sha256 = %s,
                   encrypted = %s,
                   error_message = %s,
                   pushed_remote = %s,
                   remote_url = %s
             WHERE id = %s
            """,
            (status, artifact_path, artifact_size, sha256_hex, encrypted,
             (error or "")[:500] or None, pushed_remote, remote_url, run_id),
        )
    conn.commit()


def _parse_database_url(url: str) -> dict:
    """Naive parser; postgresql://user:pass@host:port/db"""
    rest = url.split("://", 1)[1]
    creds, hostpart = rest.split("@", 1)
    if ":" in creds:
        user, pwd = creds.split(":", 1)
    else:
        user, pwd = creds, ""
    if "/" in hostpart:
        hostport, dbname = hostpart.split("/", 1)
        # strip query string
        dbname = dbname.split("?", 1)[0]
    else:
        hostport, dbname = hostpart, ""
    if ":" in hostport:
        host, port = hostport.split(":", 1)
    else:
        host, port = hostport, "5432"
    return {"user": user, "password": pwd, "host": host, "port": port, "dbname": dbname}


def _retention_sweep() -> int:
    """Delete encrypted backups older than RETENTION_DAYS. Returns count deleted."""
    if not BACKUP_DIR.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    n = 0
    for p in BACKUP_DIR.glob("mmwss-*.sql.gz.enc"):
        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc)
            if mtime < cutoff:
                p.unlink()
                n += 1
        except Exception:
            log.exception("retention sweep failed on %s", p)
    if n:
        log.info("backup retention: deleted %d old artifacts", n)
    return n


def run_backup(settings, conn) -> dict:
    """Make a full encrypted backup. Returns {'ok', 'path', 'size'} summary."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    if not shutil.which("pg_dump"):
        log.error("pg_dump binary not in PATH — backup aborted")
        return {"ok": False, "error": "pg_dump missing"}

    run_id = _open_backup_run(conn)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M")
    out_path = BACKUP_DIR / f"mmwss-{stamp}.sql.gz.enc"
    tmp_dump = BACKUP_DIR / f".tmp-{stamp}.sql"
    tmp_gz   = BACKUP_DIR / f".tmp-{stamp}.sql.gz"

    try:
        params = _parse_database_url(settings.database_url)
        env = os.environ.copy()
        env["PGPASSWORD"] = params["password"]
        cmd = [
            "pg_dump",
            "-h", params["host"], "-p", params["port"],
            "-U", params["user"], "-d", params["dbname"],
            "--no-owner", "--no-privileges",
            "-f", str(tmp_dump),
        ]
        log.info("pg_dump → %s", tmp_dump)
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=900)
        if proc.returncode != 0:
            raise RuntimeError(f"pg_dump exit={proc.returncode} stderr={proc.stderr[:500]}")

        # gzip
        with tmp_dump.open("rb") as f_in, gzip.open(tmp_gz, "wb", compresslevel=6) as f_out:
            shutil.copyfileobj(f_in, f_out)
        tmp_dump.unlink()

        # AES-256-GCM encrypt with master key
        key = _master_key_bytes(settings.mmwss_master_key)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        plaintext = tmp_gz.read_bytes()
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=b"mmwss-backup-v1")
        # File layout: 4-byte magic + 1-byte version + 12-byte nonce + ciphertext
        out_path.write_bytes(b"MMWB" + b"\x01" + nonce + ciphertext)
        tmp_gz.unlink()

        size = out_path.stat().st_size
        sha = hashlib.sha256(out_path.read_bytes()).hexdigest()
        log.info("backup ok: %s (%d bytes, sha=%s)", out_path.name, size, sha[:16])

        # Retention sweep
        _retention_sweep()

        # S3 upload (best-effort if configured)
        pushed = False
        remote = None
        s3_bucket = os.environ.get("BACKUP_S3_BUCKET", "").strip()
        if s3_bucket:
            try:
                pushed, remote = _push_s3(out_path, s3_bucket)
            except Exception as e:
                log.warning("S3 upload failed (continuing): %s", e)

        _close_backup_run(
            conn, run_id, status="ok",
            artifact_path=str(out_path), artifact_size=size,
            sha256_hex=sha, encrypted=True, error=None,
            pushed_remote=pushed, remote_url=remote,
        )
        return {"ok": True, "path": str(out_path), "size": size,
                "sha256": sha, "pushed_remote": pushed}
    except Exception as e:
        log.exception("backup failed")
        # cleanup tmp
        for p in (tmp_dump, tmp_gz):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass
        _close_backup_run(
            conn, run_id, status="failed",
            artifact_path=None, artifact_size=None, sha256_hex=None,
            encrypted=False, error=str(e),
        )
        return {"ok": False, "error": str(e)}


def _push_s3(path: Path, bucket: str) -> tuple[bool, str | None]:
    """Try to upload via aws CLI (avoid boto3 dependency for now)."""
    if not shutil.which("aws"):
        log.info("aws CLI not in image — skipping S3 upload (install awscli to enable)")
        return False, None
    key = f"mmwss-backups/{path.name}"
    cmd = ["aws", "s3", "cp", str(path), f"s3://{bucket}/{key}", "--only-show-errors"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"aws s3 cp exit={proc.returncode}: {proc.stderr[:300]}")
    return True, f"s3://{bucket}/{key}"


def restore_backup(settings, encrypted_path: Path, target_db_url: str) -> None:
    """DR helper — decrypt, gunzip, psql restore.

    Usage from the host:
        docker compose exec collector python -c "
        from mmwss_collector.config import load
        from mmwss_collector.backup import restore_backup
        from pathlib import Path
        restore_backup(load(), Path('/app/reports/backups/mmwss-2026-06-06-1300.sql.gz.enc'),
                       'postgresql://mmwss:pwd@localhost:5434/mmwss_restored')
        "
    Assumes target DB exists and is empty.
    """
    blob = encrypted_path.read_bytes()
    if blob[:4] != b"MMWB" or blob[4] != 1:
        raise ValueError("Not a valid MMWSS backup file (bad magic/version)")
    nonce, ciphertext = blob[5:17], blob[17:]
    key = _master_key_bytes(settings.mmwss_master_key)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data=b"mmwss-backup-v1")
    tmp_gz = encrypted_path.with_suffix(".restore.gz")
    tmp_sql = encrypted_path.with_suffix(".restore.sql")
    tmp_gz.write_bytes(plaintext)
    with gzip.open(tmp_gz, "rb") as f_in, tmp_sql.open("wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    tmp_gz.unlink()
    params = _parse_database_url(target_db_url)
    env = os.environ.copy()
    env["PGPASSWORD"] = params["password"]
    cmd = ["psql", "-h", params["host"], "-p", params["port"],
           "-U", params["user"], "-d", params["dbname"], "-f", str(tmp_sql)]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=900)
    tmp_sql.unlink()
    if proc.returncode != 0:
        raise RuntimeError(f"psql restore failed: {proc.stderr[:500]}")
    log.info("Restored backup %s to %s", encrypted_path.name, params["dbname"])
