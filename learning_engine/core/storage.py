"""SQLite storage layer: connection, WAL, row mapping, transactions."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import get_config
from .schema import apply_schema

PHASE6_SCHEMA = """
CREATE TABLE IF NOT EXISTS triage_metadata (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    triage_id         INTEGER NOT NULL,
    finding_id        TEXT NOT NULL,
    lifecycle_outcome TEXT,
    confidence        REAL,
    run_id            TEXT,
    evidence_ids      TEXT DEFAULT '[]',
    metadata          TEXT DEFAULT '{}',
    created_at        TEXT NOT NULL,
    FOREIGN KEY (triage_id) REFERENCES triage (id)
);

CREATE TABLE IF NOT EXISTS outcome_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    finding_id   TEXT,
    target       TEXT NOT NULL,
    vuln_class   TEXT,
    outcome_kind TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    confidence   REAL NOT NULL DEFAULT 0.5,
    strategy     TEXT,
    run_id       TEXT,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    metadata     TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tech_fingerprints (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    technology   TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    category     TEXT NOT NULL DEFAULT '',
    confidence   REAL NOT NULL DEFAULT 1.0,
    run_id       TEXT,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    metadata     TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS skill_telemetry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    telemetry_id    TEXT NOT NULL UNIQUE,
    target          TEXT NOT NULL,
    skill_id        TEXT NOT NULL,
    vuln_class      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'completed',
    duration_ms     REAL NOT NULL DEFAULT 0.0,
    cost_usd        REAL NOT NULL DEFAULT 0.0,
    tokens_used     INTEGER NOT NULL DEFAULT 0,
    findings_count  INTEGER NOT NULL DEFAULT 0,
    confirmed_count INTEGER NOT NULL DEFAULT 0,
    tech_stack      TEXT NOT NULL DEFAULT '[]',
    run_id          TEXT,
    evidence_ids    TEXT NOT NULL DEFAULT '[]',
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_paths (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    path_id         TEXT NOT NULL UNIQUE,
    target          TEXT NOT NULL,
    title           TEXT NOT NULL,
    steps           TEXT NOT NULL DEFAULT '[]',
    finding_ids     TEXT NOT NULL DEFAULT '[]',
    path_severity   TEXT NOT NULL DEFAULT 'medium',
    path_risk_score REAL NOT NULL DEFAULT 0.0,
    verified        INTEGER NOT NULL DEFAULT 0,
    reviewed_by     TEXT,
    review_status   TEXT NOT NULL DEFAULT 'reviewed',
    run_id          TEXT,
    evidence_ids    TEXT NOT NULL DEFAULT '[]',
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_triage_meta_finding ON triage_metadata (finding_id);
CREATE INDEX IF NOT EXISTS idx_outcome_target      ON outcome_events (target);
CREATE INDEX IF NOT EXISTS idx_outcome_finding     ON outcome_events (finding_id);
CREATE INDEX IF NOT EXISTS idx_outcome_kind        ON outcome_events (outcome_kind, outcome);
CREATE INDEX IF NOT EXISTS idx_tech_target         ON tech_fingerprints (target);
CREATE INDEX IF NOT EXISTS idx_tech_name           ON tech_fingerprints (technology);
CREATE INDEX IF NOT EXISTS idx_telemetry_skill     ON skill_telemetry (skill_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_target    ON skill_telemetry (target);
CREATE INDEX IF NOT EXISTS idx_attack_paths_target ON attack_paths (target);
"""


class Database:
    """Thin sqlite3 wrapper with WAL mode and dict rows."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else get_config().db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def init_schema(self) -> None:
        apply_schema(self.conn)
        self.conn.executescript(PHASE6_SCHEMA)
        self.conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, seq: list[tuple]) -> sqlite3.Cursor:
        return self.conn.executemany(sql, seq)

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def rows(self, sql: str, params: tuple = ()) -> list[dict]:
        cur = self.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def one(self, sql: str, params: tuple = ()) -> dict | None:
        cur = self.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()