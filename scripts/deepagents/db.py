"""Postgres persistence for Dapper DeepAgents scans.

Enabled when ``DATABASE_URL`` is set in the environment (Railway provides this
automatically for Postgres add-ons). When the env var is missing, ``enabled()``
returns False and callers fall back to the disk-only behavior — this keeps
local development working without a Postgres instance.

Two tables, both created on first use via ``init()``:

- ``scans``         — one row per pentest run (metadata + lifecycle status)
- ``deliverables``  — file contents written by the agent, keyed by ``scan_id``

Storing the report bodies in Postgres lets historical scans survive ephemeral
container restarts (e.g. Railway redeploys) where the local ``audit-logs/``
directory would otherwise be wiped.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import uuid
from pathlib import Path
from typing import Any, Iterable, Optional

log = logging.getLogger(__name__)

try:
    import psycopg
    from psycopg_pool import ConnectionPool
except ImportError:  # pragma: no cover - optional dep
    psycopg = None  # type: ignore[assignment]
    ConnectionPool = None  # type: ignore[assignment]


_pool: Optional["ConnectionPool"] = None
_pool_lock = threading.Lock()
_initialized = False


def _database_url() -> Optional[str]:
    return os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")


def enabled() -> bool:
    return bool(_database_url()) and psycopg is not None


def init() -> bool:
    """Open the pool and create tables. Safe to call multiple times. Returns
    True if the DB is now ready, False if it's disabled or unreachable."""
    global _pool, _initialized
    if _initialized:
        return _pool is not None
    with _pool_lock:
        if _initialized:
            return _pool is not None
        _initialized = True
        url = _database_url()
        if not url or psycopg is None:
            return False
        try:
            _pool = ConnectionPool(conninfo=url, min_size=1, max_size=5, open=True, timeout=10)
            with _pool.connection() as conn, conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id            TEXT PRIMARY KEY,
                        scan_folder   TEXT UNIQUE,
                        url           TEXT NOT NULL,
                        repo          TEXT,
                        model         TEXT,
                        classes       JSONB,
                        skip_exploit  BOOLEAN DEFAULT FALSE,
                        config_path   TEXT,
                        status        TEXT,
                        error         TEXT,
                        started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        finished_at   TIMESTAMPTZ
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS deliverables (
                        scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        path        TEXT NOT NULL,
                        content     TEXT NOT NULL,
                        bytes       INTEGER NOT NULL,
                        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        PRIMARY KEY (scan_id, path)
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS scans_started_at_idx ON scans (started_at DESC);")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id           TEXT PRIMARY KEY,
                        key_hash     TEXT NOT NULL UNIQUE,
                        prefix       TEXT NOT NULL,
                        label        TEXT,
                        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        last_used_at TIMESTAMPTZ,
                        revoked_at   TIMESTAMPTZ
                    );
                """)
                conn.commit()
            log.info("Postgres DB initialized")
            return True
        except Exception as e:
            log.warning("DB init failed (%s); falling back to disk-only", e)
            _pool = None
            return False


def upsert_scan(
    scan_id: str,
    *,
    url: str,
    repo: Optional[str],
    model: Optional[str],
    classes: Optional[Iterable[str]],
    skip_exploit: bool,
    config_path: Optional[str],
    scan_folder: Optional[str],
    status: str = "pending",
) -> None:
    if not _pool:
        return
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (id, scan_folder, url, repo, model, classes,
                                   skip_exploit, config_path, status)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    url = EXCLUDED.url,
                    repo = EXCLUDED.repo,
                    model = EXCLUDED.model,
                    classes = EXCLUDED.classes,
                    skip_exploit = EXCLUDED.skip_exploit,
                    config_path = EXCLUDED.config_path,
                    status = EXCLUDED.status;
                """,
                (
                    scan_id, scan_folder, url, repo, model,
                    json.dumps(list(classes) if classes is not None else None),
                    skip_exploit, config_path, status,
                ),
            )
            conn.commit()
    except Exception as e:
        log.warning("upsert_scan failed for %s: %s", scan_id, e)


def update_status(scan_id: str, status: str, error: Optional[str] = None) -> None:
    if not _pool:
        return
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            terminal = status in ("error", "completed", "idle")
            cur.execute(
                """
                UPDATE scans
                SET status = %s,
                    error = COALESCE(%s, error),
                    finished_at = CASE WHEN %s THEN NOW() ELSE finished_at END
                WHERE id = %s;
                """,
                (status, error, terminal, scan_id),
            )
            conn.commit()
    except Exception as e:
        log.warning("update_status failed for %s: %s", scan_id, e)


def upsert_deliverable(scan_id: str, path: str, content: str) -> None:
    if not _pool:
        return
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO deliverables (scan_id, path, content, bytes, updated_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (scan_id, path) DO UPDATE SET
                    content = EXCLUDED.content,
                    bytes = EXCLUDED.bytes,
                    updated_at = NOW();
                """,
                (scan_id, path, content, len(content.encode("utf-8"))),
            )
            conn.commit()
    except Exception as e:
        log.warning("upsert_deliverable failed for %s/%s: %s", scan_id, path, e)


def sync_from_disk(scan_id: str, deliverables_dir: str) -> int:
    """Walk a deliverables directory and upsert every file into the DB. Returns
    the number of files synced. Cheap (a few small files per scan); called from
    the live-session refresh path so the DB never drifts from disk."""
    if not _pool:
        return 0
    base = Path(deliverables_dir)
    if not base.exists():
        return 0
    n = 0
    for f in base.glob("**/*"):
        if not f.is_file():
            continue
        try:
            content = f.read_text(errors="replace")
        except Exception:
            continue
        upsert_deliverable(scan_id, str(f.relative_to(base)), content)
        n += 1
    return n


def list_scans() -> list[dict[str, Any]]:
    if not _pool:
        return []
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT s.id, s.scan_folder, s.url, s.repo, s.status,
                       EXTRACT(EPOCH FROM s.started_at)::BIGINT AS started_at,
                       EXTRACT(EPOCH FROM s.finished_at)::BIGINT AS finished_at,
                       (SELECT COUNT(*) FROM deliverables d WHERE d.scan_id = s.id) AS file_count
                FROM scans s
                ORDER BY s.started_at DESC
                LIMIT 500;
            """)
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as e:
        log.warning("list_scans failed: %s", e)
        return []


def list_deliverables(scan_id: str) -> list[dict[str, Any]]:
    if not _pool:
        return []
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT path, bytes FROM deliverables WHERE scan_id = %s ORDER BY path;",
                (scan_id,),
            )
            return [{"path": p, "bytes": b} for p, b in cur.fetchall()]
    except Exception as e:
        log.warning("list_deliverables failed for %s: %s", scan_id, e)
        return []


def get_deliverable(scan_id: str, path: str) -> Optional[str]:
    if not _pool:
        return None
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT content FROM deliverables WHERE scan_id = %s AND path = %s;",
                (scan_id, path),
            )
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as e:
        log.warning("get_deliverable failed for %s/%s: %s", scan_id, path, e)
        return None


def scan_exists(scan_id: str) -> bool:
    if not _pool:
        return False
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM scans WHERE id = %s;", (scan_id,))
            return cur.fetchone() is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# API keys (for CI/CD callers hitting /api/scans with a Bearer token).
# Only sha256 hashes are stored — the plaintext is shown to the user exactly
# once at creation time and never persisted.
# ---------------------------------------------------------------------------

_KEY_PREFIX = "dpr_"


def _hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def create_api_key(label: Optional[str]) -> Optional[dict[str, Any]]:
    """Mint a new API key. Returns dict with `plaintext` shown once, plus
    metadata. Returns None if the DB isn't available."""
    if not _pool:
        return None
    plaintext = _KEY_PREFIX + secrets.token_urlsafe(32)
    key_id = str(uuid.uuid4())
    prefix = plaintext[: len(_KEY_PREFIX) + 8]  # e.g. "dpr_a1b2c3d4"
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO api_keys (id, key_hash, prefix, label) "
                "VALUES (%s, %s, %s, %s);",
                (key_id, _hash_key(plaintext), prefix, label),
            )
            conn.commit()
        return {
            "id": key_id,
            "plaintext": plaintext,
            "prefix": prefix,
            "label": label,
        }
    except Exception as e:
        log.warning("create_api_key failed: %s", e)
        return None


def list_api_keys() -> list[dict[str, Any]]:
    if not _pool:
        return []
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT id, prefix, label,
                       EXTRACT(EPOCH FROM created_at)::BIGINT  AS created_at,
                       EXTRACT(EPOCH FROM last_used_at)::BIGINT AS last_used_at,
                       EXTRACT(EPOCH FROM revoked_at)::BIGINT  AS revoked_at
                FROM api_keys
                ORDER BY created_at DESC;
            """)
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as e:
        log.warning("list_api_keys failed: %s", e)
        return []


def verify_api_key(plaintext: str) -> Optional[str]:
    """Return the key id if `plaintext` is a valid, non-revoked key.
    Bumps last_used_at on success. Returns None otherwise."""
    if not _pool or not plaintext:
        return None
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM api_keys "
                "WHERE key_hash = %s AND revoked_at IS NULL;",
                (_hash_key(plaintext),),
            )
            row = cur.fetchone()
            if not row:
                return None
            key_id = row[0]
            cur.execute(
                "UPDATE api_keys SET last_used_at = NOW() WHERE id = %s;",
                (key_id,),
            )
            conn.commit()
            return key_id
    except Exception as e:
        log.warning("verify_api_key failed: %s", e)
        return None


def revoke_api_key(key_id: str) -> bool:
    if not _pool:
        return False
    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET revoked_at = NOW() "
                "WHERE id = %s AND revoked_at IS NULL;",
                (key_id,),
            )
            updated = cur.rowcount
            conn.commit()
            return updated > 0
    except Exception as e:
        log.warning("revoke_api_key failed: %s", e)
        return False
