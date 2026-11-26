"""Core configuration for the learning engine."""

from __future__ import annotations

import os
from pathlib import Path

SCHEMA_VERSION = "1.0.0"

DEFAULT_DB_PATH = "learning_engine/memory/learning.db"

SEVERITIES = ("info", "low", "medium", "high", "critical")
VERDICTS = ("confirmed", "false_positive", "unverified")

# Extended lifecycle outcomes (additive alongside VERDICTS)
VALIDATION_OUTCOMES = ("confirmed", "false_positive", "inconclusive", "unverified")
REMEDIATION_OUTCOMES = ("proposed", "tested_pass", "tested_fail", "approved", "rejected", "applied")
RETEST_OUTCOMES = ("fixed", "still_vulnerable", "regression_detected", "inconclusive")
OUTCOME_KINDS = ("validation", "remediation", "retest")

LIFECYCLE_VERDICT_MAP = {
    "confirmed": "confirmed",
    "validated": "confirmed",
    "false_positive": "false_positive",
    "inconclusive": "unverified",
    "unverified": "unverified",
    "fixed": "confirmed",
    "still_vulnerable": "confirmed",
    "regression_detected": "confirmed",
}

# Hard bounds for signal weights (kept in scoring/signals.json)
MAX_SIGNAL_WEIGHT = 0.50
MAX_SIGNAL_KEYS = 200

# Retrieval limits
DEFAULT_RECALL_LIMIT = 10


class Config:
    """Paths and limits. Root defaults to the workspace root (parent of scripts/)."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root else Path(__file__).resolve().parent.parent.parent
        db_rel = os.environ.get("LEARNING_DB", DEFAULT_DB_PATH)
        self.db_path = Path(db_rel) if Path(db_rel).is_absolute() else self.root / db_rel
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"Config(root={self.root}, db={self.db_path})"


_default: Config | None = None


def get_config() -> Config:
    global _default
    if _default is None:
        _default = Config()
    return _default