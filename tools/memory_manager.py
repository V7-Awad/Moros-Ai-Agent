#!/usr/bin/env python3
"""
memory_manager.py — Tiered Memory System for Moros.

Three memory tiers:
  - Episodic: concrete scan events (tool calls, findings, errors).
  - Semantic: persistent facts about targets (tech stack, WAF, known vulns).
  - Procedural: methodology steps that worked or failed.

Also provides scan checkpoint/resume anchors for interrupted sessions,
and cross-session recall so the agent improves on repeat targets.
"""

from contextlib import contextmanager
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memory-manager")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MemoryManager:
    """
    Persistent tiered memory backed by SQLite.

    One database per target (stored in targets/<target>/memory.db).
    Also supports a global memory store for cross-target patterns.
    """

    def __init__(self, target_dir: Path, global_db_path: Path = None):
        self._target_dir = Path(target_dir)
        self._target_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._target_dir / "memory.db"
        self._global_db = global_db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Create the memory tables if they don't exist."""
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS episodic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    run_id TEXT,
                    skill TEXT,
                    event_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    details TEXT DEFAULT '{}',
                    relevance REAL DEFAULT 1.0
                );

                CREATE TABLE IF NOT EXISTS semantic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL UNIQUE,
                    value TEXT NOT NULL,
                    category TEXT DEFAULT 'general',
                    confidence REAL DEFAULT 1.0,
                    source TEXT DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS procedural (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    technique TEXT NOT NULL,
                    target_context TEXT DEFAULT '',
                    outcome TEXT NOT NULL,
                    success INTEGER DEFAULT 0,
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    skill TEXT NOT NULL,
                    step INTEGER DEFAULT 0,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(run_id, skill)
                );

                CREATE INDEX IF NOT EXISTS idx_episodic_skill ON episodic(skill);
                CREATE INDEX IF NOT EXISTS idx_semantic_category ON semantic(category);
                CREATE INDEX IF NOT EXISTS idx_procedural_technique ON procedural(technique);
                CREATE INDEX IF NOT EXISTS idx_checkpoints_run ON checkpoints(run_id);
            """)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connect(self):
        """Open a SQLite connection, run transaction, and ensure close()."""
        conn = self._get_conn()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # ── Episodic Memory ──────────────────────────────────────────

    def record_event(self, event_type: str, summary: str, skill: str = "",
                     run_id: str = "", details: Dict = None,
                     relevance: float = 1.0):
        """Store a scan event in episodic memory."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO episodic (timestamp, run_id, skill, event_type, summary, details, relevance) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (_now_iso(), run_id, skill, event_type, summary,
                     json.dumps(details or {}, ensure_ascii=False), relevance)
                )

    def recall_events(self, skill: str = None, event_type: str = None,
                      limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent episodic memories, optionally filtered."""
        query = "SELECT * FROM episodic WHERE 1=1"
        params: list = []
        if skill:
            query += " AND skill = ?"
            params.append(skill)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ── Semantic Memory ──────────────────────────────────────────

    def store_fact(self, key: str, value: str, category: str = "general",
                   confidence: float = 1.0, source: str = ""):
        """Store or update a persistent fact about the target."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO semantic (key, value, category, confidence, source, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "category=excluded.category, confidence=excluded.confidence, "
                    "source=excluded.source, updated_at=excluded.updated_at",
                    (key, value, category, confidence, source, _now_iso())
                )

    def recall_facts(self, category: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve stored facts, optionally filtered by category."""
        query = "SELECT * FROM semantic WHERE 1=1"
        params: list = []
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_fact(self, key: str) -> Optional[str]:
        """Get a single fact by key."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM semantic WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    # ── Procedural Memory ────────────────────────────────────────

    def record_technique(self, technique: str, outcome: str, success: bool,
                         target_context: str = "", notes: str = ""):
        """Record whether a methodology step worked or failed."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO procedural (technique, target_context, outcome, success, notes, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (technique, target_context, outcome, 1 if success else 0, notes, _now_iso())
                )

    def recall_techniques(self, technique: str = None, success_only: bool = False,
                          limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve methodology records."""
        query = "SELECT * FROM procedural WHERE 1=1"
        params: list = []
        if technique:
            query += " AND technique = ?"
            params.append(technique)
        if success_only:
            query += " AND success = 1"
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ── Checkpoints (Resume Anchors) ─────────────────────────────

    def save_checkpoint(self, run_id: str, skill: str, step: int, state: Dict[str, Any]):
        """Save a checkpoint for scan resume."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO checkpoints (run_id, skill, step, state, created_at) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(run_id, skill) DO UPDATE SET step=excluded.step, "
                    "state=excluded.state, created_at=excluded.created_at",
                    (run_id, skill, step, json.dumps(state, ensure_ascii=False), _now_iso())
                )

    def load_checkpoint(self, run_id: str, skill: str) -> Optional[Dict[str, Any]]:
        """Load the last checkpoint for a skill in a run."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT step, state, created_at FROM checkpoints "
                "WHERE run_id = ? AND skill = ?",
                (run_id, skill)
            ).fetchone()
        if not row:
            return None
        return {
            "step": row["step"],
            "state": json.loads(row["state"]),
            "created_at": row["created_at"],
        }

    def clear_checkpoints(self, run_id: str):
        """Remove all checkpoints for a completed run."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM checkpoints WHERE run_id = ?", (run_id,))

    # ── Cross-session target recall ──────────────────────────────

    def build_target_context(self) -> str:
        """
        Build a compact text summary of everything known about this target
        for injection into the LLM system prompt.
        """
        facts = self.recall_facts(limit=30)
        techniques = self.recall_techniques(success_only=True, limit=15)

        lines = []
        if facts:
            lines.append("## Known Target Facts")
            for f in facts:
                lines.append(f"- [{f.get('category', '')}] {f.get('key', '')}: {f.get('value', '')}")

        if techniques:
            lines.append("\n## Techniques That Worked Previously")
            for t in techniques:
                lines.append(f"- {t.get('technique', '')}: {t.get('outcome', '')}")

        return "\n".join(lines) if lines else ""

    def get_stats(self) -> Dict[str, int]:
        """Return counts for each memory tier."""
        with self._connect() as conn:
            ep = conn.execute("SELECT COUNT(*) as c FROM episodic").fetchone()["c"]
            sem = conn.execute("SELECT COUNT(*) as c FROM semantic").fetchone()["c"]
            proc = conn.execute("SELECT COUNT(*) as c FROM procedural").fetchone()["c"]
            ckpt = conn.execute("SELECT COUNT(*) as c FROM checkpoints").fetchone()["c"]
        return {
            "episodic_events": ep,
            "semantic_facts": sem,
            "procedural_steps": proc,
            "active_checkpoints": ckpt,
        }
