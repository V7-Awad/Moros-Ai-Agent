"""Triage & lifecycle outcome ingestion: record verdicts, validation, remediation, and retest outcomes."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from ..core.config import OUTCOME_KINDS
from ..core.storage import Database
from ..core.validation import (
    map_outcome_to_verdict,
    normalize_finding_id,
    normalize_target,
    normalize_vuln_class,
    parse_json_dict,
    parse_json_list,
    validate_confidence,
    validate_evidence_ids,
    validate_metadata,
    validate_remediation_outcome,
    validate_retest_outcome,
    validate_validation_outcome,
    validate_verdict,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_event_id() -> str:
    return f"oe-{uuid.uuid4().hex[:12]}"


def persist_triage(
    db: Database,
    *,
    finding_id: str,
    verdict: str,
    reason: str | None = None,
    reviewer: str | None = None,
    lifecycle_outcome: str | None = None,
    confidence: float | None = None,
    run_id: str | None = None,
    evidence_ids: list[str] | tuple[str, ...] | None = None,
    metadata: dict | None = None,
) -> dict:
    fid = normalize_finding_id(finding_id)
    v = validate_verdict(verdict)

    existing = db.one("SELECT finding_id FROM findings WHERE finding_id = ?", (fid,))
    if not existing:
        raise ValueError(f"unknown finding_id: {fid} (ingest the finding first)")

    now = _now()
    cur = db.execute(
        """
        INSERT INTO triage (finding_id, verdict, reason, reviewer, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (fid, v, reason, reviewer, now),
    )

    has_meta = any(
        x is not None for x in (lifecycle_outcome, confidence, run_id, evidence_ids, metadata)
    )
    ev_list = validate_evidence_ids(evidence_ids)
    meta_dict = validate_metadata(metadata)
    conf_val = validate_confidence(confidence) if confidence is not None else None
    clean_outcome = str(lifecycle_outcome).strip().lower() if lifecycle_outcome else None

    if has_meta:
        db.execute(
            """
            INSERT INTO triage_metadata
                (triage_id, finding_id, lifecycle_outcome, confidence, run_id, evidence_ids, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cur.lastrowid,
                fid,
                clean_outcome,
                conf_val,
                str(run_id).strip() if run_id else None,
                json.dumps(ev_list),
                json.dumps(meta_dict),
                now,
            ),
        )

    db.commit()
    res = {"finding_id": fid, "verdict": v, "reason": reason, "reviewer": reviewer}
    if has_meta:
        res.update(
            {
                "lifecycle_outcome": clean_outcome,
                "confidence": conf_val,
                "run_id": str(run_id).strip() if run_id else None,
                "evidence_ids": ev_list,
                "metadata": meta_dict,
                "created_at": now,
            }
        )
    return res


def persist_outcome_event(
    db: Database,
    *,
    target: str,
    outcome_kind: str,
    outcome: str,
    finding_id: str | None = None,
    vuln_class: str | None = None,
    confidence: float = 0.5,
    strategy: str | None = None,
    run_id: str | None = None,
    evidence_ids: list[str] | tuple[str, ...] | None = None,
    metadata: dict | None = None,
    event_id: str | None = None,
) -> dict:
    """Persist an extended validation, remediation, or retest outcome with provenance."""
    kind = str(outcome_kind or "").strip().lower()
    if kind not in OUTCOME_KINDS:
        raise ValueError(f"outcome_kind must be one of {OUTCOME_KINDS}, got {kind!r}")

    if kind == "validation":
        clean_outcome = validate_validation_outcome(outcome)
    elif kind == "remediation":
        clean_outcome = validate_remediation_outcome(outcome)
    else:
        clean_outcome = validate_retest_outcome(outcome)

    norm_target = normalize_target(target)
    fid = normalize_finding_id(finding_id) if finding_id else None
    vclass = normalize_vuln_class(vuln_class) if vuln_class else None
    conf = validate_confidence(confidence)
    ev_list = validate_evidence_ids(evidence_ids)
    meta_dict = validate_metadata(metadata)
    clean_run_id = str(run_id).strip() if run_id else None
    clean_strategy = str(strategy).strip() if strategy else None
    eid = str(event_id or _new_event_id()).strip()
    now = _now()

    db.execute(
        """
        INSERT INTO outcome_events
            (event_id, finding_id, target, vuln_class, outcome_kind, outcome,
             confidence, strategy, run_id, evidence_ids, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            eid,
            fid,
            norm_target,
            vclass,
            kind,
            clean_outcome,
            conf,
            clean_strategy,
            clean_run_id,
            json.dumps(ev_list),
            json.dumps(meta_dict),
            now,
        ),
    )

    # Bridge validation outcome into triage/triage_metadata when finding exists in findings table
    if kind == "validation" and fid:
        existing = db.one("SELECT finding_id FROM findings WHERE finding_id = ?", (fid,))
        if existing:
            mapped_verdict = map_outcome_to_verdict(clean_outcome)
            reviewer = f"validator:{clean_strategy}" if clean_strategy else "validator:auto"
            t_cur = db.execute(
                """
                INSERT INTO triage (finding_id, verdict, reason, reviewer, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    fid,
                    mapped_verdict,
                    f"Validation outcome={clean_outcome} (strategy={clean_strategy or 'default'})",
                    reviewer,
                    now,
                ),
            )
            db.execute(
                """
                INSERT INTO triage_metadata
                    (triage_id, finding_id, lifecycle_outcome, confidence, run_id, evidence_ids, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    t_cur.lastrowid,
                    fid,
                    clean_outcome,
                    conf,
                    clean_run_id,
                    json.dumps(ev_list),
                    json.dumps(meta_dict),
                    now,
                ),
            )

    db.commit()
    return {
        "event_id": eid,
        "finding_id": fid,
        "target": norm_target,
        "vuln_class": vclass,
        "outcome_kind": kind,
        "outcome": clean_outcome,
        "confidence": conf,
        "strategy": clean_strategy,
        "run_id": clean_run_id,
        "evidence_ids": ev_list,
        "metadata": meta_dict,
        "created_at": now,
    }


def persist_validation_outcome(db: Database, **kwargs) -> dict:
    return persist_outcome_event(db, outcome_kind="validation", **kwargs)


def persist_remediation_outcome(db: Database, **kwargs) -> dict:
    return persist_outcome_event(db, outcome_kind="remediation", **kwargs)


def persist_retest_outcome(db: Database, **kwargs) -> dict:
    return persist_outcome_event(db, outcome_kind="retest", **kwargs)


def latest_verdict(db: Database, finding_id: str) -> dict | None:
    return db.one(
        """
        SELECT verdict, reason, reviewer, created_at
        FROM triage WHERE finding_id = ?
        ORDER BY id DESC LIMIT 1
        """,
        (finding_id,),
    )


def _hydrate_outcome_row(row: dict) -> dict:
    return {
        **row,
        "evidence_ids": parse_json_list(row.get("evidence_ids")),
        "metadata": parse_json_dict(row.get("metadata")),
    }


def latest_outcome(
    db: Database, finding_id: str, outcome_kind: str | None = None
) -> dict | None:
    fid = normalize_finding_id(finding_id)
    if outcome_kind:
        row = db.one(
            """
            SELECT * FROM outcome_events
            WHERE finding_id = ? AND outcome_kind = ?
            ORDER BY id DESC LIMIT 1
            """,
            (fid, str(outcome_kind).strip().lower()),
        )
    else:
        row = db.one(
            """
            SELECT * FROM outcome_events
            WHERE finding_id = ?
            ORDER BY id DESC LIMIT 1
            """,
            (fid,),
        )
    return _hydrate_outcome_row(row) if row else None


def list_outcomes(
    db: Database,
    *,
    target: str | None = None,
    finding_id: str | None = None,
    outcome_kind: str | None = None,
    limit: int = 100,
) -> list[dict]:
    sql = "SELECT * FROM outcome_events WHERE 1=1"
    params: list = []
    if target:
        sql += " AND target = ?"
        params.append(normalize_target(target))
    if finding_id:
        sql += " AND finding_id = ?"
        params.append(normalize_finding_id(finding_id))
    if outcome_kind:
        sql += " AND outcome_kind = ?"
        params.append(str(outcome_kind).strip().lower())
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, int(limit)))
    return [_hydrate_outcome_row(r) for r in db.rows(sql, tuple(params))]