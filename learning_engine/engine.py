"""engine.py — public API of the learning engine (5 hooks).

Hooks:
  1. record_finding(...)  — ingest a finding
  2. record_triage(...)   — ingest a triage verdict (incl. false positives)
  3. recall(query, ...)   — retrieve relevant lessons/findings
  4. distill(...)         — aggregate analytics into lessons + patterns
  5. score(signals)       — bounded signal scoring

Session lifecycle hooks (documented public API, used by the briefing):
  before_recon(target, techs)         — recon context + recalled lessons
  during_testing(signals)             — bounded signal score for live testing
  after_finding(target, endpoint, vulnerability_class, signals,
                validation_state, source_provenance) — persist a finding
  before_summary(findings)            — rank findings for the summary
  after_triage(finding_id, feedback_type, notes, provenance) — persist triage

Module-level helpers mirror the hooks using a default engine rooted at the
workspace root, so pipelines can do:

    from learning_engine import engine
    engine.record_finding(target=..., vuln_class=..., title=...)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .analytics.patterns import (
    duplicate_heavy_patterns,
    estimate_scan_value_and_cost as _estimate_scan_value_and_cost,
    fp_pattern_candidates,
    get_advisory_patterns as _get_advisory_patterns,
    highest_signal_surfaces,
    per_class_stats,
    recommend_regression_tests as _recommend_regression_tests,
    recommend_skills_for_tech as _recommend_skills_for_tech,
    recommend_validation_strategies as _recommend_validation_strategies,
    signal_heatmap,
    target_summary,
)
from .core.config import Config, DEFAULT_RECALL_LIMIT, get_config
from .core.storage import Database
from .core.validation import (
    normalize_finding_id,
    normalize_target,
    normalize_tech_name,
    normalize_vuln_class,
    validate_confidence,
    validate_evidence_ids,
    validate_metadata,
    validate_severity,
)
from .graph.builder import build_graph
from .ingestion.finding import normalize_finding, persist_finding
from .ingestion.triage import (
    latest_outcome,
    list_outcomes,
    persist_remediation_outcome,
    persist_retest_outcome,
    persist_triage,
    persist_validation_outcome,
)
from .retrieval.search import search_findings, search_lessons
from .scoring.engine import score as _score


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LearningEngine:
    """SQLite-backed memory with five public hooks."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.config: Config = Config(root=root) if root else get_config()
        self.db_path = self.config.db_path
        self.db: Database | None = None

    def init_db(self) -> Database:
        if self.db is not None:
            self.db.close()
        self.db = Database(self.db_path)
        self.db.init_schema()
        return self.db

    def close(self) -> None:
        db = self.db
        self.db = None
        if db is not None:
            db.close()

    def __enter__(self) -> "LearningEngine":
        self._db()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _db(self) -> Database:
        if self.db is None:
            self.init_db()
        return self.db

    # ---- Hook 1: ingest a finding -------------------------------------
    def record_finding(
        self,
        *,
        target: str,
        vuln_class: str,
        title: str,
        severity: str = "medium",
        confidence: float = 0.5,
        evidence: str | None = None,
        signals: dict | None = None,
        source: str | None = None,
        finding_id: str | None = None,
    ) -> dict:
        doc = normalize_finding(
            target=target,
            vuln_class=vuln_class,
            title=title,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            signals=signals,
            source=source,
            finding_id=finding_id,
        )
        return persist_finding(self._db(), doc)

    # ---- Hook 2: ingest a triage verdict ------------------------------
    def record_triage(
        self,
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
        return persist_triage(
            self._db(),
            finding_id=finding_id,
            verdict=verdict,
            reason=reason,
            reviewer=reviewer,
            lifecycle_outcome=lifecycle_outcome,
            confidence=confidence,
            run_id=run_id,
            evidence_ids=evidence_ids,
            metadata=metadata,
        )

    # ---- Additive Phase 6 ingestion hooks -----------------------------
    def record_validation_outcome(
        self,
        *,
        target: str,
        outcome: str,
        finding_id: str | None = None,
        vuln_class: str | None = None,
        confidence: float = 0.5,
        strategy: str | None = None,
        run_id: str | None = None,
        evidence_ids: list[str] | tuple[str, ...] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Record an exploit validation outcome (confirmed, false_positive, inconclusive, unverified)."""
        return persist_validation_outcome(
            self._db(),
            target=target,
            outcome=outcome,
            finding_id=finding_id,
            vuln_class=vuln_class,
            confidence=confidence,
            strategy=strategy,
            run_id=run_id,
            evidence_ids=evidence_ids,
            metadata=metadata,
        )

    def record_remediation_outcome(
        self,
        *,
        target: str,
        outcome: str,
        finding_id: str | None = None,
        vuln_class: str | None = None,
        confidence: float = 0.5,
        strategy: str | None = None,
        run_id: str | None = None,
        evidence_ids: list[str] | tuple[str, ...] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Record a remediation lifecycle outcome (proposed, tested_pass, tested_fail, approved, rejected, applied)."""
        return persist_remediation_outcome(
            self._db(),
            target=target,
            outcome=outcome,
            finding_id=finding_id,
            vuln_class=vuln_class,
            confidence=confidence,
            strategy=strategy,
            run_id=run_id,
            evidence_ids=evidence_ids,
            metadata=metadata,
        )

    def record_retest_outcome(
        self,
        *,
        target: str,
        outcome: str,
        finding_id: str | None = None,
        vuln_class: str | None = None,
        confidence: float = 0.5,
        strategy: str | None = None,
        run_id: str | None = None,
        evidence_ids: list[str] | tuple[str, ...] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Record a retest outcome (fixed, still_vulnerable, regression_detected, inconclusive)."""
        return persist_retest_outcome(
            self._db(),
            target=target,
            outcome=outcome,
            finding_id=finding_id,
            vuln_class=vuln_class,
            confidence=confidence,
            strategy=strategy,
            run_id=run_id,
            evidence_ids=evidence_ids,
            metadata=metadata,
        )

    def record_tech_fingerprint(
        self,
        *,
        target: str,
        technology: str,
        version: str = "",
        category: str = "",
        confidence: float = 1.0,
        run_id: str | None = None,
        evidence_ids: list[str] | tuple[str, ...] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Persist a detected technology fingerprint with provenance."""
        norm_target = normalize_target(target)
        norm_tech = normalize_tech_name(technology)
        conf = validate_confidence(confidence)
        ev_list = validate_evidence_ids(evidence_ids)
        meta_dict = validate_metadata(metadata)
        clean_run_id = str(run_id).strip() if run_id else None
        now = _now()
        db = self._db()
        db.execute(
            """
            INSERT INTO tech_fingerprints
                (target, technology, version, category, confidence, run_id, evidence_ids, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                norm_target,
                norm_tech,
                str(version or "").strip(),
                str(category or "").strip(),
                conf,
                clean_run_id,
                json.dumps(ev_list),
                json.dumps(meta_dict),
                now,
            ),
        )
        db.commit()
        return {
            "target": norm_target,
            "technology": norm_tech,
            "version": str(version or "").strip(),
            "category": str(category or "").strip(),
            "confidence": conf,
            "run_id": clean_run_id,
            "evidence_ids": ev_list,
            "metadata": meta_dict,
            "created_at": now,
        }

    def record_skill_telemetry(
        self,
        *,
        target: str,
        skill_id: str,
        vuln_class: str = "",
        status: str = "completed",
        duration_ms: float = 0.0,
        cost_usd: float = 0.0,
        tokens_used: int = 0,
        findings_count: int = 0,
        confirmed_count: int = 0,
        tech_stack: list[str] | tuple[str, ...] | None = None,
        run_id: str | None = None,
        evidence_ids: list[str] | tuple[str, ...] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Persist skill execution duration, cost, yield, and tech context."""
        norm_target = normalize_target(target)
        clean_skill = str(skill_id or "").strip()
        if not clean_skill:
            raise ValueError("skill_id must be non-empty")
        vclass = normalize_vuln_class(vuln_class) if vuln_class else ""
        techs = [normalize_tech_name(t) for t in (tech_stack or []) if str(t or "").strip()]
        ev_list = validate_evidence_ids(evidence_ids)
        meta_dict = validate_metadata(metadata)
        clean_run_id = str(run_id).strip() if run_id else None
        tid = f"tel-{uuid.uuid4().hex[:12]}"
        now = _now()
        db = self._db()
        db.execute(
            """
            INSERT INTO skill_telemetry
                (telemetry_id, target, skill_id, vuln_class, status, duration_ms, cost_usd,
                 tokens_used, findings_count, confirmed_count, tech_stack, run_id,
                 evidence_ids, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tid,
                norm_target,
                clean_skill,
                vclass,
                str(status or "completed").strip().lower(),
                max(0.0, float(duration_ms or 0.0)),
                max(0.0, float(cost_usd or 0.0)),
                max(0, int(tokens_used or 0)),
                max(0, int(findings_count or 0)),
                max(0, int(confirmed_count or 0)),
                json.dumps(techs),
                clean_run_id,
                json.dumps(ev_list),
                json.dumps(meta_dict),
                now,
            ),
        )
        db.commit()
        return {
            "telemetry_id": tid,
            "target": norm_target,
            "skill_id": clean_skill,
            "vuln_class": vclass,
            "status": str(status or "completed").strip().lower(),
            "duration_ms": max(0.0, float(duration_ms or 0.0)),
            "cost_usd": max(0.0, float(cost_usd or 0.0)),
            "tokens_used": max(0, int(tokens_used or 0)),
            "findings_count": max(0, int(findings_count or 0)),
            "confirmed_count": max(0, int(confirmed_count or 0)),
            "tech_stack": techs,
            "run_id": clean_run_id,
            "evidence_ids": ev_list,
            "metadata": meta_dict,
            "created_at": now,
        }

    def record_attack_path(
        self,
        *,
        target: str,
        title: str,
        path_id: str | None = None,
        steps: list[dict] | None = None,
        finding_ids: list[str] | tuple[str, ...] | None = None,
        path_severity: str = "medium",
        path_risk_score: float = 0.0,
        verified: bool = False,
        reviewed_by: str | None = None,
        review_status: str = "reviewed",
        run_id: str | None = None,
        evidence_ids: list[str] | tuple[str, ...] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Persist a reviewed attack path with provenance."""
        norm_target = normalize_target(target)
        sev = validate_severity(path_severity)
        fids = [normalize_finding_id(f) for f in (finding_ids or []) if str(f or "").strip()]
        ev_list = validate_evidence_ids(evidence_ids)
        meta_dict = validate_metadata(metadata)
        clean_run_id = str(run_id).strip() if run_id else None
        pid = str(path_id or f"ap-{uuid.uuid4().hex[:12]}").strip()
        clean_steps = list(steps or [])
        now = _now()
        db = self._db()
        db.execute(
            """
            INSERT INTO attack_paths
                (path_id, target, title, steps, finding_ids, path_severity, path_risk_score,
                 verified, reviewed_by, review_status, run_id, evidence_ids, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path_id) DO UPDATE SET
                title = excluded.title,
                steps = excluded.steps,
                finding_ids = excluded.finding_ids,
                path_severity = excluded.path_severity,
                path_risk_score = excluded.path_risk_score,
                verified = excluded.verified,
                reviewed_by = excluded.reviewed_by,
                review_status = excluded.review_status,
                run_id = excluded.run_id,
                evidence_ids = excluded.evidence_ids,
                metadata = excluded.metadata
            """,
            (
                pid,
                norm_target,
                str(title).strip() or "attack path",
                json.dumps(clean_steps),
                json.dumps(fids),
                sev,
                float(path_risk_score or 0.0),
                1 if verified else 0,
                str(reviewed_by).strip() if reviewed_by else None,
                str(review_status or "reviewed").strip().lower(),
                clean_run_id,
                json.dumps(ev_list),
                json.dumps(meta_dict),
                now,
            ),
        )
        db.commit()
        return {
            "path_id": pid,
            "target": norm_target,
            "title": str(title).strip() or "attack path",
            "steps": clean_steps,
            "finding_ids": fids,
            "path_severity": sev,
            "path_risk_score": float(path_risk_score or 0.0),
            "verified": bool(verified),
            "reviewed_by": str(reviewed_by).strip() if reviewed_by else None,
            "review_status": str(review_status or "reviewed").strip().lower(),
            "run_id": clean_run_id,
            "evidence_ids": ev_list,
            "metadata": meta_dict,
            "created_at": now,
        }

    def get_outcomes(
        self,
        *,
        target: str | None = None,
        finding_id: str | None = None,
        outcome_kind: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """List stored outcome events."""
        return list_outcomes(
            self._db(),
            target=target,
            finding_id=finding_id,
            outcome_kind=outcome_kind,
            limit=limit,
        )

    def latest_outcome(
        self, finding_id: str, outcome_kind: str | None = None
    ) -> dict | None:
        """Fetch latest outcome event for a finding."""
        return latest_outcome(self._db(), finding_id, outcome_kind=outcome_kind)

    # ---- Advisory recommendation helpers (strictly advisory=True) ----
    def recommend_skills_for_tech(
        self,
        techs: list[str] | None = None,
        target: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        return _recommend_skills_for_tech(self._db(), techs=techs, target=target, limit=limit)

    def recommend_validation_strategies(
        self,
        vuln_class: str | None = None,
        target: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        return _recommend_validation_strategies(
            self._db(), vuln_class=vuln_class, target=target, limit=limit
        )

    def estimate_scan_value_and_cost(
        self,
        skills: list[str] | None = None,
        techs: list[str] | None = None,
        target: str | None = None,
    ) -> dict:
        return _estimate_scan_value_and_cost(
            self._db(), skills=skills, techs=techs, target=target
        )

    def recommend_regression_tests(
        self,
        target: str | None = None,
        vuln_class: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        return _recommend_regression_tests(
            self._db(), target=target, vuln_class=vuln_class, limit=limit
        )

    def get_advisory_patterns(
        self,
        target: str | None = None,
        vuln_class: str | None = None,
        min_support: int = 1,
        limit: int = 20,
    ) -> list[dict]:
        return _get_advisory_patterns(
            self._db(), target=target, vuln_class=vuln_class, min_support=min_support, limit=limit
        )

    # ---- Hook 3: recall ------------------------------------------------
    def recall(
        self,
        query: str,
        limit: int = DEFAULT_RECALL_LIMIT,
        vuln_class: str | None = None,
        include_lessons: bool = True,
        include_findings: bool = True,
    ) -> list[dict]:
        db = self._db()
        out: list[dict] = []
        if include_lessons:
            for r in search_lessons(db, query, limit, vuln_class):
                out.append({"kind": "lesson", **r})
        if include_findings:
            for r in search_findings(db, query, limit, vuln_class):
                out.append({"kind": "finding", **r})
        return out[:limit]

    # ---- Hook 4: distill -----------------------------------------------
    def _persist_distilled(self, db: Database, classes: list[dict], fp_patterns: list[dict], now: str) -> None:
        """Persist distilled per-class lessons and patterns into SQLite via UPSERT."""
        class_fp_rates = {c["vuln_class"]: float(c.get("fp_rate") or 0.0) for c in classes}
        for c in classes:
            lesson_text = (c.get("lessons") or [""])[0]
            if not lesson_text:
                continue
            db.execute(
                """
                INSERT INTO lessons (vuln_class, lesson, source, support, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(vuln_class, source) DO UPDATE SET
                    lesson = excluded.lesson,
                    support = excluded.support,
                    created_at = excluded.created_at
                """,
                (c["vuln_class"], lesson_text, "distill", int(c["count"]), now),
            )
            signals_summary = ", ".join(c["top_signals"][:3]) or "none"
            targets_count = len(c.get("targets") or [])
            db.execute(
                """
                INSERT INTO patterns (pattern, description, fp_rate, sample_size, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(pattern) DO UPDATE SET
                    description = excluded.description,
                    fp_rate = excluded.fp_rate,
                    sample_size = excluded.sample_size,
                    updated_at = excluded.updated_at
                """,
                (
                    f"class:{c['vuln_class']}",
                    f"Vuln class {c['vuln_class']} across {targets_count} target(s); top signals: {signals_summary}",
                    float(c.get("fp_rate") or 0.0),
                    int(c["count"]),
                    now,
                ),
            )
        for fp in fp_patterns:
            db.execute(
                """
                INSERT INTO patterns (pattern, description, fp_rate, sample_size, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(pattern) DO UPDATE SET
                    description = excluded.description,
                    fp_rate = excluded.fp_rate,
                    sample_size = excluded.sample_size,
                    updated_at = excluded.updated_at
                """,
                (
                    f"fp:{fp['vuln_class']}:{fp['signal']}",
                    f"False-positive signal '{fp['signal']}' on {fp['vuln_class']}",
                    class_fp_rates.get(fp["vuln_class"], 1.0),
                    int(fp["occurrences"]),
                    now,
                ),
            )
        db.commit()

    def distill(self, min_support: int = 2) -> dict:
        db = self._db()
        classes = per_class_stats(db)
        fp_patterns = fp_pattern_candidates(db, min_occurrences=max(1, min_support))
        out_classes: list[dict] = []
        now = _now()
        for c in classes:
            targets_str = ", ".join(c.get("targets") or []) or "none"
            lesson = (
                f"On {c['vuln_class']} ({targets_str}): {c['confirmed']} confirmed / "
                f"{c['count']} total (fp_rate {c['fp_rate']:.0%}), "
                f"top signals: {', '.join(c['top_signals'][:3]) or 'none'}"
            )
            out_classes.append({**c, "lessons": [lesson]})
        self._persist_distilled(db, out_classes, fp_patterns, now)
        return {
            "summary": {
                "classes": len(out_classes),
                "findings": sum(c["count"] for c in out_classes),
                "fp_patterns": len(fp_patterns),
                "generated_at": now,
            },
            "classes": out_classes,
            "fp_patterns": fp_patterns,
        }

    # ---- Hook 5: bounded signal scoring --------------------------------
    def score(self, signals: dict | None) -> dict:
        return _score(signals)

    # ---- Session lifecycle hooks (documented public API) ----------------

    # Mapping of finding-state machine -> confidence for validation_state input.
    STATE_CONFIDENCE = {
        "observation": 0.10,
        "lead": 0.25,
        "high_confidence_lead": 0.50,
        "inconclusive": 0.25,
        "confirmed": 0.70,
        "validated": 0.90,
        "reportable": 0.95,
    }

    # Mapping of triage feedback_type -> verdict for after_triage.
    FEEDBACK_VERDICTS = {
        "accepted": "confirmed",
        "duplicate": "unverified",
        "false_positive": "false_positive",
        "inconclusive": "unverified",
        "informational": "unverified",
        "n/a": "unverified",
    }

    def before_recon(self, target: str, techs: list[str] | None = None) -> dict:
        """Call before recon. Returns context: recalled lessons for the stack.

        Shapes: in  target: str, techs: list[str]
                out {"target": str, "techs": list[str], "relevant_lessons": [dict],
                     "suggested_classes": [str], "ok": True}
        """
        techs = techs or []
        query = " ".join(techs) or target
        lessons = self.recall(query, limit=5, include_findings=False)
        if not lessons and techs and target:
            lessons = self.recall(target, limit=5, include_findings=False)
        if not lessons:
            db = self._db()
            rows = db.rows("SELECT * FROM lessons ORDER BY support DESC, id DESC LIMIT 5")
            lessons = [{"kind": "lesson", **r} for r in rows]
        classes = sorted({r.get("vuln_class") for r in lessons if r.get("vuln_class")})
        return {
            "target": target,
            "techs": techs,
            "relevant_lessons": lessons,
            "suggested_classes": classes,
            "ok": True,
        }

    def during_testing(self, signals: dict | None) -> dict:
        """Call to score live signals during testing. Bounded score in [0, 1].

        Shapes: in  signals: dict
                out dict with "score" (float 0-1) plus weight breakdown.
        """
        return _score(signals)

    def after_finding(
        self,
        target: str,
        endpoint: str,
        vulnerability_class: str,
        signals: dict | None = None,
        validation_state: str = "observation",
        source_provenance: str | None = None,
    ) -> dict:
        """Call after a finding passes its gates. Persists to SQLite.

        Shapes: in  target: str, endpoint: str, vulnerability_class: str,
                    signals: dict, validation_state: str, source_provenance: str
                out record_finding doc dict (with "finding_id", "status").
        """
        state = str(validation_state or "").strip().lower()
        confidence = self.STATE_CONFIDENCE.get(state, 0.5)
        return self.record_finding(
            target=target,
            vuln_class=vulnerability_class,
            title=f"{vulnerability_class} @ {endpoint}",
            confidence=confidence,
            signals=signals,
            source=source_provenance or f"session:{target}",
        )

    @staticmethod
    def _coerce_float(val) -> float:
        if val is None:
            return 0.0
        if isinstance(val, (int, float)):
            return float(val)
        label_map = {"critical": 0.95, "high": 0.85, "medium": 0.5, "low": 0.25, "info": 0.1}
        text = str(val).strip().lower()
        if text in label_map:
            return label_map[text]
        try:
            return float(text)
        except ValueError:
            return 0.0

    def before_summary(self, findings: list[dict] | None) -> dict:
        """Call before writing a summary. Ranks findings by severity, then
        confidence, then score. Never mutates the input list.

        Shapes: in  findings: list[dict]
                out {"ranked": [dict], "count": int}
        """
        findings = list(findings or [])
        rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
                "informational": 1}
        ranked = sorted(
            findings,
            key=lambda f: (
                rank.get(str(f.get("severity") or "medium").strip().lower(), 3),
                self._coerce_float(f.get("confidence")),
                self._coerce_float(f.get("score")),
            ),
            reverse=True,
        )
        return {"ranked": ranked, "count": len(ranked)}

    def after_triage(
        self,
        finding_id: str,
        feedback_type: str,
        notes: str | None = None,
        provenance: str | None = None,
        confidence: float | None = None,
        run_id: str | None = None,
        evidence_ids: list[str] | tuple[str, ...] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Call after triage feedback (accepted/duplicate/false_positive/inconclusive).
        Persists a triage verdict and optional lifecycle provenance.

        Shapes: in  finding_id: str, feedback_type: str, notes: str, provenance: str
                out record_triage doc dict (with "verdict", "finding_id").
        """
        fb = str(feedback_type or "").strip().lower()
        verdict = self.FEEDBACK_VERDICTS.get(fb, "unverified")
        lifecycle_outcome = "inconclusive" if fb == "inconclusive" else None
        return self.record_triage(
            finding_id=finding_id,
            verdict=verdict,
            reason=notes,
            reviewer=provenance or "session",
            lifecycle_outcome=lifecycle_outcome,
            confidence=confidence,
            run_id=run_id,
            evidence_ids=evidence_ids,
            metadata=metadata,
        )

    # ---- Convenience ----------------------------------------------------
    def stats(self) -> dict:
        db = self._db()
        return {
            "findings": db.one("SELECT count(*) AS n FROM findings")["n"],
            "triage": db.one("SELECT count(*) AS n FROM triage")["n"],
            "lessons": db.one("SELECT count(*) AS n FROM lessons")["n"],
            "patterns": db.one("SELECT count(*) AS n FROM patterns")["n"],
            "outcome_events": db.one("SELECT count(*) AS n FROM outcome_events")["n"],
            "tech_fingerprints": db.one("SELECT count(*) AS n FROM tech_fingerprints")["n"],
            "skill_telemetry": db.one("SELECT count(*) AS n FROM skill_telemetry")["n"],
            "attack_paths": db.one("SELECT count(*) AS n FROM attack_paths")["n"],
            "schema_version": db.one("SELECT value FROM meta WHERE key = 'schema_version'")["value"],
        }

    def export_graph(self) -> dict:
        return build_graph(self._db())

    # ---- Analytics convenience -------------------------------------------

    def get_statistics(self) -> dict:
        """Alias of stats(): counts per table + schema version."""
        return self.stats()

    def get_tuning(self) -> dict:
        """Signal weights + policy (learning_engine/scoring/signals.json)."""
        from .scoring.engine import load_policy, load_weights  # noqa: PLC0415
        return {"weights": load_weights(), "policy": load_policy()}

    def get_heatmap(self) -> dict:
        """Per-class signal occurrence counts."""
        return signal_heatmap(self._db())

    def get_chains(self) -> dict:
        """Chain candidates: classes with 2+ findings + FP patterns."""
        db = self._db()
        classes = [
            {k: c[k] for k in ("vuln_class", "count", "fp_rate", "top_signals")}
            for c in per_class_stats(db) if c["count"] >= 2
        ]
        return {
            "chain_candidates": classes,
            "fp_patterns": fp_pattern_candidates(db, min_occurrences=1),
        }

    def rebuild_graph(self) -> dict:
        """Alias of export_graph()."""
        return self.export_graph()

    @property
    def analytics(self):
        """Analytics helpers bound to this engine's database."""
        from types import SimpleNamespace  # noqa: PLC0415
        return SimpleNamespace(
            highest_signal_surfaces=lambda limit=10: highest_signal_surfaces(self._db(), limit=limit),
            duplicate_heavy_patterns=lambda min_occurrences=2: duplicate_heavy_patterns(self._db(), min_occurrences=min_occurrences),
            target_summary=lambda target: target_summary(self._db(), target),
            recommend_skills_for_tech=lambda techs=None, target=None, limit=10: _recommend_skills_for_tech(
                self._db(), techs=techs, target=target, limit=limit
            ),
            recommend_validation_strategies=lambda vuln_class=None, target=None, limit=10: _recommend_validation_strategies(
                self._db(), vuln_class=vuln_class, target=target, limit=limit
            ),
            estimate_scan_value_and_cost=lambda skills=None, techs=None, target=None: _estimate_scan_value_and_cost(
                self._db(), skills=skills, techs=techs, target=target
            ),
            recommend_regression_tests=lambda target=None, vuln_class=None, limit=10: _recommend_regression_tests(
                self._db(), target=target, vuln_class=vuln_class, limit=limit
            ),
            get_advisory_patterns=lambda target=None, vuln_class=None, min_support=1, limit=20: _get_advisory_patterns(
                self._db(), target=target, vuln_class=vuln_class, min_support=min_support, limit=limit
            ),
        )


# ---- Module-level defaults for pipelines --------------------------------

_engine: LearningEngine | None = None


def _default() -> LearningEngine:
    global _engine
    if _engine is None:
        _engine = LearningEngine()
        _engine.init_db()
    return _engine


def record_finding(**kwargs) -> dict:
    return _default().record_finding(**kwargs)


def record_triage(**kwargs) -> dict:
    return _default().record_triage(**kwargs)


def recall(**kwargs) -> list[dict]:
    return _default().recall(**kwargs)


def distill(min_support: int = 2) -> dict:
    return _default().distill(min_support=min_support)


def score(signals: dict | None = None) -> dict:
    return _default().score(signals)


def before_recon(target: str, techs: list[str] | None = None) -> dict:
    return _default().before_recon(target=target, techs=techs)


def during_testing(signals: dict | None = None) -> dict:
    return _default().during_testing(signals)


def after_finding(
    target: str,
    endpoint: str,
    vulnerability_class: str,
    signals: dict | None = None,
    validation_state: str = "observation",
    source_provenance: str | None = None,
) -> dict:
    return _default().after_finding(
        target=target, endpoint=endpoint, vulnerability_class=vulnerability_class,
        signals=signals, validation_state=validation_state,
        source_provenance=source_provenance,
    )


def before_summary(findings: list[dict] | None = None) -> dict:
    return _default().before_summary(findings)


def after_triage(
    finding_id: str,
    feedback_type: str,
    notes: str | None = None,
    provenance: str | None = None,
) -> dict:
    return _default().after_triage(
        finding_id=finding_id, feedback_type=feedback_type,
        notes=notes, provenance=provenance,
    )


def stats() -> dict:
    return _default().stats()


def record_validation_outcome(**kwargs) -> dict:
    return _default().record_validation_outcome(**kwargs)


def record_remediation_outcome(**kwargs) -> dict:
    return _default().record_remediation_outcome(**kwargs)


def record_retest_outcome(**kwargs) -> dict:
    return _default().record_retest_outcome(**kwargs)


def record_tech_fingerprint(**kwargs) -> dict:
    return _default().record_tech_fingerprint(**kwargs)


def record_skill_telemetry(**kwargs) -> dict:
    return _default().record_skill_telemetry(**kwargs)


def record_attack_path(**kwargs) -> dict:
    return _default().record_attack_path(**kwargs)


def recommend_skills_for_tech(
    techs: list[str] | None = None, target: str | None = None, limit: int = 10
) -> list[dict]:
    return _default().recommend_skills_for_tech(techs=techs, target=target, limit=limit)


def recommend_validation_strategies(
    vuln_class: str | None = None, target: str | None = None, limit: int = 10
) -> list[dict]:
    return _default().recommend_validation_strategies(
        vuln_class=vuln_class, target=target, limit=limit
    )


def estimate_scan_value_and_cost(
    skills: list[str] | None = None, techs: list[str] | None = None, target: str | None = None
) -> dict:
    return _default().estimate_scan_value_and_cost(skills=skills, techs=techs, target=target)


def recommend_regression_tests(
    target: str | None = None, vuln_class: str | None = None, limit: int = 10
) -> list[dict]:
    return _default().recommend_regression_tests(
        target=target, vuln_class=vuln_class, limit=limit
    )


def get_advisory_patterns(
    target: str | None = None,
    vuln_class: str | None = None,
    min_support: int = 1,
    limit: int = 20,
) -> list[dict]:
    return _default().get_advisory_patterns(
        target=target, vuln_class=vuln_class, min_support=min_support, limit=limit
    )