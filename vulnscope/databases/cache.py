import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vulnscope.config import CACHE_DB


def _get_conn(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or CACHE_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path | None = None) -> None:
    with _get_conn(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS osv_cache (
                purl TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nvd_cache (
                cve_id TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS kev_cache (
                id INTEGER PRIMARY KEY,
                catalog_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            );
        """)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_fresh(fetched_at_iso: str, ttl_hours: int) -> bool:
    try:
        fetched = datetime.fromisoformat(fetched_at_iso)
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - fetched < timedelta(hours=ttl_hours)
    except (ValueError, TypeError):
        return False


class CacheDB:
    def __init__(self, db_path: Path | None = None, ttl_hours: int = 24):
        self.db_path = db_path or CACHE_DB
        self.ttl_hours = ttl_hours
        init_db(self.db_path)

    def get_osv(self, purl: str) -> dict | None:
        with _get_conn(self.db_path) as conn:
            row = conn.execute(
                "SELECT response_json, fetched_at FROM osv_cache WHERE purl = ?", (purl,)
            ).fetchone()
        if row and _is_fresh(row["fetched_at"], self.ttl_hours):
            return json.loads(row["response_json"])
        return None

    def set_osv(self, purl: str, data: dict) -> None:
        with _get_conn(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO osv_cache (purl, response_json, fetched_at) VALUES (?, ?, ?)",
                (purl, json.dumps(data), _now_iso()),
            )

    def get_nvd(self, cve_id: str) -> dict | None:
        with _get_conn(self.db_path) as conn:
            row = conn.execute(
                "SELECT response_json, fetched_at FROM nvd_cache WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        if row and _is_fresh(row["fetched_at"], self.ttl_hours):
            return json.loads(row["response_json"])
        return None

    def set_nvd(self, cve_id: str, data: dict) -> None:
        with _get_conn(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO nvd_cache (cve_id, response_json, fetched_at) VALUES (?, ?, ?)",
                (cve_id, json.dumps(data), _now_iso()),
            )

    def get_kev(self) -> dict | None:
        with _get_conn(self.db_path) as conn:
            row = conn.execute(
                "SELECT catalog_json, fetched_at FROM kev_cache ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row and _is_fresh(row["fetched_at"], self.ttl_hours):
            return json.loads(row["catalog_json"])
        return None

    def set_kev(self, data: dict) -> None:
        with _get_conn(self.db_path) as conn:
            conn.execute(
                "INSERT INTO kev_cache (catalog_json, fetched_at) VALUES (?, ?)",
                (json.dumps(data), _now_iso()),
            )
