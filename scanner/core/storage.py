"""SQLite-backed scan history.

Persists each :class:`ScanResult` as a summary row plus a JSON blob so past
scans can be listed, reopened, exported, and compared. Every call opens its own
short-lived connection, which keeps it safe to use from Flask request threads
and background scan threads alike.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB_PATH = os.path.join(_PROJECT_ROOT, "reports", "wvs_history.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT    NOT NULL,
    risk_score     INTEGER NOT NULL,
    findings_count INTEGER NOT NULL,
    critical       INTEGER NOT NULL DEFAULT 0,
    high           INTEGER NOT NULL DEFAULT 0,
    medium         INTEGER NOT NULL DEFAULT 0,
    low            INTEGER NOT NULL DEFAULT 0,
    info           INTEGER NOT NULL DEFAULT 0,
    pages_crawled  INTEGER NOT NULL DEFAULT 0,
    modules        TEXT    NOT NULL DEFAULT '',
    started_at     TEXT,
    finished_at    TEXT,
    created_at     TEXT,
    data           TEXT    NOT NULL
);
"""

_SUMMARY_COLS = (
    "id, target, risk_score, findings_count, critical, high, medium, low, info, "
    "pages_crawled, modules, started_at, finished_at, created_at"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _connect(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as conn:
        conn.executescript(_SCHEMA)


def save_scan(result, modules: str = "", db_path: str = DEFAULT_DB_PATH) -> int:
    """Persist a ScanResult (or its to_dict()) and return the new scan id."""
    data = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    data["modules"] = modules
    counts = data.get("counts_by_severity", {})
    init_db(db_path)
    with _connect(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (target, risk_score, findings_count, critical, high,
                medium, low, info, pages_crawled, modules, started_at, finished_at,
                created_at, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.get("target", ""),
                data.get("risk_score", 0),
                len(data.get("findings", [])),
                counts.get("critical", 0), counts.get("high", 0),
                counts.get("medium", 0), counts.get("low", 0), counts.get("info", 0),
                data.get("pages_crawled", 0),
                modules,
                data.get("started_at", ""),
                data.get("finished_at", ""),
                _now_iso(),
                json.dumps(data),
            ),
        )
        return int(cur.lastrowid)


def list_scans(db_path: str = DEFAULT_DB_PATH, limit: int = 200) -> list:
    init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT {_SUMMARY_COLS} FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int, db_path: str = DEFAULT_DB_PATH) -> dict | None:
    """Return the full scan dict (parsed data + id/created_at), or None."""
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, created_at, modules, data FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    data = json.loads(row["data"])
    data["id"] = row["id"]
    data["created_at"] = row["created_at"]
    data.setdefault("modules", row["modules"])
    return data


def delete_scan(scan_id: int, db_path: str = DEFAULT_DB_PATH) -> bool:
    init_db(db_path)
    with _connect(db_path) as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def _finding_key(f: dict) -> tuple:
    return (f.get("type", ""), f.get("endpoint", ""), f.get("parameter", ""))


def compare(id_a: int, id_b: int, db_path: str = DEFAULT_DB_PATH) -> dict | None:
    """Diff two scans. 'a' is the baseline, 'b' the newer run.

    Returns added (new in b), removed (fixed since a), and unchanged findings.
    """
    a = get_scan(id_a, db_path)
    b = get_scan(id_b, db_path)
    if a is None or b is None:
        return None

    a_map = {_finding_key(f): f for f in a.get("findings", [])}
    b_map = {_finding_key(f): f for f in b.get("findings", [])}

    added = [f for k, f in b_map.items() if k not in a_map]
    removed = [f for k, f in a_map.items() if k not in b_map]
    unchanged = [f for k, f in b_map.items() if k in a_map]

    return {
        "a": a, "b": b,
        "added": added, "removed": removed, "unchanged": unchanged,
    }
