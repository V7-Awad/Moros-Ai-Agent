"""Schema DDL and migrations for the learning engine SQLite database."""

from __future__ import annotations

import sqlite3

from .config import SCHEMA_VERSION

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL UNIQUE,
    target      TEXT NOT NULL,
    vuln_class  TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    confidence  REAL NOT NULL DEFAULT 0.5,
    evidence    TEXT,
    signals     TEXT,
    source      TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS triage (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    reason      TEXT,
    reviewer    TEXT,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings (finding_id)
);

CREATE TABLE IF NOT EXISTS lessons (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_class  TEXT NOT NULL,
    lesson      TEXT NOT NULL,
    source      TEXT,
    support     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS patterns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern     TEXT NOT NULL,
    description TEXT,
    fp_rate     REAL NOT NULL DEFAULT 0.0,
    sample_size INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signals_meta (
    key         TEXT PRIMARY KEY,
    weight      REAL NOT NULL,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings (target);
CREATE INDEX IF NOT EXISTS idx_findings_class    ON findings (vuln_class);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_triage_finding    ON triage (finding_id);
CREATE INDEX IF NOT EXISTS idx_lessons_class     ON lessons (vuln_class);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5 (
    title, target, vuln_class, signals
);
CREATE VIRTUAL TABLE IF NOT EXISTS lessons_fts USING fts5 (
    lesson, vuln_class
);
CREATE TRIGGER IF NOT EXISTS findings_fts_ai AFTER INSERT ON findings BEGIN
    INSERT INTO findings_fts (rowid, title, target, vuln_class, signals)
    VALUES (new.id, new.title, new.target, new.vuln_class, new.signals);
END;
CREATE TRIGGER IF NOT EXISTS lessons_fts_ai AFTER INSERT ON lessons BEGIN
    INSERT INTO lessons_fts (rowid, lesson, vuln_class)
    VALUES (new.id, new.lesson, new.vuln_class);
END;
"""

SCHEMA = BASE_SCHEMA + FTS_SCHEMA

FTS_PRELUDE = """
DROP TRIGGER IF EXISTS findings_fts_ai;
DROP TRIGGER IF EXISTS lessons_fts_ai;
DROP TABLE IF EXISTS findings_fts;
DROP TABLE IF EXISTS lessons_fts;
"""

MIGRATIONS: dict[str, list[str]] = {
    "1.0.0": [],
}


def _fts_objects_present(conn) -> bool:
    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE (type = 'table' AND name IN ('findings_fts', 'lessons_fts')) "
        "   OR (type = 'trigger' AND name IN ('findings_fts_ai', 'lessons_fts_ai'))"
    ).fetchall()
    return len(rows) == 4


def _backfill_fts(conn) -> None:
    conn.execute("DELETE FROM findings_fts")
    conn.execute("DELETE FROM lessons_fts")
    for row in conn.execute("SELECT id, title, target, vuln_class, signals FROM findings"):
        conn.execute(
            "INSERT INTO findings_fts (rowid, title, target, vuln_class, signals) VALUES (?, ?, ?, ?, ?)",
            tuple(row),
        )
    for row in conn.execute("SELECT id, lesson, vuln_class FROM lessons"):
        conn.execute(
            "INSERT INTO lessons_fts (rowid, lesson, vuln_class) VALUES (?, ?, ?)",
            tuple(row),
        )


def apply_schema(conn) -> None:
    """Apply full schema; idempotent. Record schema version in meta."""
    conn.executescript(BASE_SCHEMA)

    ver_row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    current_version = ver_row[0] if ver_row else None
    fts_ready = _fts_objects_present(conn)

    if current_version != SCHEMA_VERSION or not fts_ready:
        try:
            if current_version is not None and current_version != SCHEMA_VERSION:
                conn.executescript(FTS_PRELUDE)
            conn.executescript(FTS_SCHEMA)
            _backfill_fts(conn)
        except sqlite3.OperationalError:
            # SQLite build without FTS5; retrieval falls back to LIKE queries.
            pass

    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
        (SCHEMA_VERSION,),
    )
    conn.commit()