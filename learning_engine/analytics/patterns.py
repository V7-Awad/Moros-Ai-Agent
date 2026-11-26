"""Analytics: aggregate findings/triage into per-class patterns and lessons."""

from __future__ import annotations

from ..core.storage import Database
from ..core.validation import (
    normalize_target,
    normalize_tech_name,
    normalize_vuln_class,
    parse_json_dict,
    parse_json_list,
    parse_signals_json,
)
from ..scoring.engine import weight_for


def per_class_stats(db: Database) -> list[dict]:
    """Per-vuln-class aggregates: counts, fp_rate, top signals, lesson candidates."""
    findings = db.rows("SELECT * FROM findings ORDER BY id")
    verdicts: dict[str, list[str]] = {}
    for t in db.rows("SELECT finding_id, verdict FROM triage ORDER BY id"):
        verdicts.setdefault(t["finding_id"], []).append(t["verdict"])

    by_class: dict[str, dict] = {}
    signal_occurrence: dict[str, dict[str, int]] = {}
    for f in findings:
        c = f["vuln_class"]
        agg = by_class.setdefault(
            c,
            {
                "vuln_class": c,
                "count": 0,
                "confirmed": 0,
                "false_positive": 0,
                "unverified": 0,
                "avg_confidence": 0.0,
                "top_signals": [],
                "targets": set(),
                "lessons": [],
                "conf_sums": 0.0,
            },
        )
        agg["count"] += 1
        agg["conf_sums"] += float(f["confidence"] or 0.0)
        agg["targets"].add(f["target"])
        signals = parse_signals_json(f["signals"])
        for key in signals:
            signal_occurrence.setdefault(c, {}).setdefault(key, 0)
            signal_occurrence[c][key] += 1
        v = (verdicts.get(f["finding_id"]) or ["unverified"])[-1]
        agg.setdefault(v, 0)
        agg[v] += 1

    out: list[dict] = []
    for c, agg in by_class.items():
        n = max(1, agg["count"])
        agg["avg_confidence"] = round(agg["conf_sums"] / n, 3)
        fp = agg["false_positive"]
        agg["fp_rate"] = round(fp / n, 4)
        signals = signal_occurrence.get(c, {})
        agg["top_signals"] = sorted(signals, key=lambda k: (-signals[k], -weight_for(k)))[:10]
        agg["targets"] = sorted(agg["targets"])
        del agg["conf_sums"]
        out.append(agg)
    out.sort(key=lambda a: (-a["count"], a["vuln_class"]))
    return out


def fp_pattern_candidates(db: Database, min_occurrences: int = 2) -> list[dict]:
    """Signal keys co-occurring with false_positive verdicts, as FP patterns."""
    rows = db.rows(
        """
        SELECT f.vuln_class, f.signals, f.title
        FROM findings f
        JOIN triage t ON t.finding_id = f.finding_id
        WHERE t.verdict = 'false_positive'
        ORDER BY t.id
        """
    )
    signal_hits: dict[tuple[str, str], int] = {}
    for r in rows:
        for key in parse_signals_json(r["signals"]):
            signal_hits[(r["vuln_class"], key)] = signal_hits.get((r["vuln_class"], key), 0) + 1
    return [
        {"vuln_class": c, "signal": key, "occurrences": n}
        for (c, key), n in sorted(signal_hits.items(), key=lambda kv: -kv[1])
        if n >= min_occurrences
    ]


def signal_heatmap(db: Database) -> dict:
    """Per-class signal occurrence counts: {vuln_class: {signal: count}}."""
    out: dict[str, dict[str, int]] = {}
    for f in db.rows("SELECT vuln_class, signals FROM findings"):
        for key in parse_signals_json(f["signals"]):
            out.setdefault(f["vuln_class"], {}).setdefault(key, 0)
            out[f["vuln_class"]][key] += 1
    return {c: dict(sorted(sig.items(), key=lambda kv: -kv[1])) for c, sig in out.items()}


def highest_signal_surfaces(db: Database, limit: int = 10) -> list[dict]:
    """Top vuln-class surfaces by count, then avg confidence, then fp_rate."""
    classes = per_class_stats(db)
    ranked = sorted(
        classes,
        key=lambda c: (-c["count"], -c["avg_confidence"], c["fp_rate"]),
    )
    return ranked[:limit]


def duplicate_heavy_patterns(db: Database, min_occurrences: int = 2) -> list[dict]:
    """(vuln_class, signal) pairs whose latest triage verdict is unverified
    (duplicates/informative map to unverified) — pattern to avoid or refine."""
    rows = db.rows(
        """
        SELECT f.vuln_class, f.signals
        FROM findings f
        JOIN triage t ON t.finding_id = f.finding_id
        WHERE t.id = (SELECT max(t2.id) FROM triage t2 WHERE t2.finding_id = f.finding_id)
          AND t.verdict = 'unverified'
        """
    )
    hits: dict[tuple[str, str], int] = {}
    for r in rows:
        for key in parse_signals_json(r["signals"]):
            hits[(r["vuln_class"], key)] = hits.get((r["vuln_class"], key), 0) + 1
    return [
        {"vuln_class": c, "signal": key, "occurrences": n}
        for (c, key), n in sorted(hits.items(), key=lambda kv: -kv[1])
        if n >= min_occurrences
    ]


def target_summary(db: Database, target: str) -> dict:
    """Per-class findings + signals for one target."""
    norm_target = normalize_target(target)
    rows = db.rows(
        "SELECT * FROM findings WHERE target = ? ORDER BY id", (norm_target,)
    )
    by_class: dict[str, dict] = {}
    for f in rows:
        agg = by_class.setdefault(f["vuln_class"], {"count": 0, "findings": [], "signals": {}})
        agg["count"] += 1
        agg["findings"].append({"finding_id": f["finding_id"], "title": f["title"],
                                "severity": f["severity"], "confidence": f["confidence"]})
        for key in parse_signals_json(f["signals"]):
            agg["signals"][key] = agg["signals"].get(key, 0) + 1
    return {"target": norm_target, "classes": by_class,
            "total_findings": len(rows)}


def _build_provenance(
    *,
    run_ids: list[str] | set[str] | None = None,
    evidence_ids: list[str] | set[str] | None = None,
    timestamps: list[str] | set[str] | None = None,
    sample_size: int = 0,
    extra: dict | None = None,
) -> dict:
    def _clean(items) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items or ():
            val = str(item or "").strip()
            if val and val not in seen:
                seen.add(val)
                out.append(val)
        return sorted(out)

    prov = {
        "run_ids": _clean(run_ids),
        "evidence_ids": _clean(evidence_ids),
        "timestamps": _clean(timestamps),
        "sample_size": int(sample_size),
    }
    if extra:
        prov.update(extra)
    return prov


def recommend_skills_for_tech(
    db: Database,
    techs: list[str] | None = None,
    target: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """Advisory skill recommendations prioritized by tech stack match, confirmed yield, and cost."""
    req_techs = {normalize_tech_name(t) for t in (techs or []) if str(t or "").strip()}
    norm_target = normalize_target(target) if target else None

    # Gather target -> set of detected tech fingerprints
    target_techs: dict[str, set[str]] = {}
    tech_prov: dict[str, dict[str, set[str]]] = {}
    for row in db.rows("SELECT * FROM tech_fingerprints ORDER BY id"):
        t_name = row["target"]
        tech = str(row["technology"] or "").strip().lower()
        if not tech:
            continue
        target_techs.setdefault(t_name, set()).add(tech)
        bucket = tech_prov.setdefault(tech, {"run_ids": set(), "evidence_ids": set(), "timestamps": set()})
        if row.get("run_id"):
            bucket["run_ids"].add(row["run_id"])
        bucket["evidence_ids"].update(parse_json_list(row.get("evidence_ids")))
        if row.get("created_at"):
            bucket["timestamps"].add(row["created_at"])

    if norm_target and not req_techs:
        req_techs = set(target_techs.get(norm_target, set()))

    # Aggregate telemetry per skill_id
    telemetry_rows = db.rows("SELECT * FROM skill_telemetry ORDER BY id")
    skill_aggs: dict[str, dict] = {}
    for row in telemetry_rows:
        sid = row["skill_id"]
        row_techs = {str(x).strip().lower() for x in parse_json_list(row.get("tech_stack")) if str(x).strip()}
        row_techs.update(target_techs.get(row["target"], set()))
        matched = sorted(req_techs & row_techs) if req_techs else sorted(row_techs)
        if req_techs and not matched:
            continue

        agg = skill_aggs.setdefault(
            sid,
            {
                "skill_id": sid,
                "matched_techs": set(),
                "vuln_classes": set(),
                "runs": 0,
                "findings_total": 0,
                "confirmed_total": 0,
                "cost_total": 0.0,
                "duration_total": 0.0,
                "run_ids": set(),
                "evidence_ids": set(),
                "timestamps": set(),
                "targets": set(),
            },
        )
        agg["runs"] += 1
        agg["matched_techs"].update(matched)
        if row.get("vuln_class"):
            agg["vuln_classes"].add(row["vuln_class"])
        agg["findings_total"] += int(row.get("findings_count") or 0)
        agg["confirmed_total"] += int(row.get("confirmed_count") or 0)
        agg["cost_total"] += float(row.get("cost_usd") or 0.0)
        agg["duration_total"] += float(row.get("duration_ms") or 0.0)
        if row.get("run_id"):
            agg["run_ids"].add(row["run_id"])
        agg["evidence_ids"].update(parse_json_list(row.get("evidence_ids")))
        if row.get("created_at"):
            agg["timestamps"].add(row["created_at"])
        agg["targets"].add(row["target"])
        for t in matched:
            if t in tech_prov:
                agg["run_ids"].update(tech_prov[t]["run_ids"])
                agg["evidence_ids"].update(tech_prov[t]["evidence_ids"])
                agg["timestamps"].update(tech_prov[t]["timestamps"])

    # Fallback: if no telemetry matched, infer from findings on targets matching req_techs
    if not skill_aggs and req_techs:
        matching_targets = {t for t, ts in target_techs.items() if ts & req_techs}
        if matching_targets:
            triage_latest: dict[str, str] = {}
            for tr in db.rows("SELECT finding_id, verdict FROM triage ORDER BY id"):
                triage_latest[tr["finding_id"]] = tr["verdict"]
            for f in db.rows("SELECT * FROM findings ORDER BY id"):
                if f["target"] not in matching_targets:
                    continue
                skill_key = str(f.get("source") or f["vuln_class"]).strip() or f["vuln_class"]
                matched = sorted(req_techs & target_techs.get(f["target"], set()))
                agg = skill_aggs.setdefault(
                    skill_key,
                    {
                        "skill_id": skill_key,
                        "matched_techs": set(),
                        "vuln_classes": set(),
                        "runs": 0,
                        "findings_total": 0,
                        "confirmed_total": 0,
                        "cost_total": 0.0,
                        "duration_total": 0.0,
                        "run_ids": set(),
                        "evidence_ids": set(),
                        "timestamps": set(),
                        "targets": set(),
                    },
                )
                agg["runs"] += 1
                agg["matched_techs"].update(matched)
                agg["vuln_classes"].add(f["vuln_class"])
                agg["findings_total"] += 1
                if triage_latest.get(f["finding_id"]) == "confirmed":
                    agg["confirmed_total"] += 1
                if f.get("created_at"):
                    agg["timestamps"].add(f["created_at"])
                agg["targets"].add(f["target"])
                for t in matched:
                    if t in tech_prov:
                        agg["run_ids"].update(tech_prov[t]["run_ids"])
                        agg["evidence_ids"].update(tech_prov[t]["evidence_ids"])
                        agg["timestamps"].update(tech_prov[t]["timestamps"])

    recommendations: list[dict] = []
    for agg in skill_aggs.values():
        runs = max(1, agg["runs"])
        findings = agg["findings_total"]
        confirmed = agg["confirmed_total"]
        confirmed_rate = round(confirmed / max(1, findings), 4) if findings else 0.0
        avg_cost = round(agg["cost_total"] / runs, 4)
        avg_duration = round(agg["duration_total"] / runs, 2)
        tech_bonus = min(0.3, 0.1 * len(agg["matched_techs"]))
        cost_penalty = min(0.2, avg_cost * 0.05)
        priority_score = round(
            max(0.0, (confirmed * 0.5 + confirmed_rate * 0.3 + findings * 0.1 + tech_bonus) - cost_penalty),
            4,
        )
        recommendations.append(
            {
                "advisory": True,
                "skill_id": agg["skill_id"],
                "matched_techs": sorted(agg["matched_techs"]),
                "vuln_classes": sorted(agg["vuln_classes"]),
                "priority_score": priority_score,
                "confirmed_rate": confirmed_rate,
                "avg_cost_usd": avg_cost,
                "avg_duration_ms": avg_duration,
                "reason": (
                    f"Matched techs {sorted(agg['matched_techs']) or ['general']}: "
                    f"{confirmed} confirmed / {findings} findings across {runs} run(s)"
                ),
                "provenance": _build_provenance(
                    run_ids=agg["run_ids"],
                    evidence_ids=agg["evidence_ids"],
                    timestamps=agg["timestamps"],
                    sample_size=agg["runs"],
                    extra={"targets": sorted(agg["targets"])},
                ),
            }
        )

    recommendations.sort(key=lambda r: (-r["priority_score"], -r["confirmed_rate"], r["skill_id"]))
    return recommendations[: max(1, int(limit))]


def recommend_validation_strategies(
    db: Database,
    vuln_class: str | None = None,
    target: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """Advisory validation strategy recommendations derived from validation outcome history."""
    norm_vc = normalize_vuln_class(vuln_class) if vuln_class else None
    norm_target = normalize_target(target) if target else None

    sql = "SELECT * FROM outcome_events WHERE outcome_kind = 'validation'"
    params: list = []
    if norm_vc:
        sql += " AND vuln_class = ?"
        params.append(norm_vc)
    if norm_target:
        sql += " AND target = ?"
        params.append(norm_target)
    sql += " ORDER BY id"

    groups: dict[tuple[str, str], dict] = {}
    for row in db.rows(sql, tuple(params)):
        vc = row.get("vuln_class") or "general"
        strat = row.get("strategy") or "default"
        g = groups.setdefault(
            (vc, strat),
            {
                "vuln_class": vc,
                "strategy": strat,
                "total": 0,
                "confirmed": 0,
                "false_positive": 0,
                "inconclusive": 0,
                "unverified": 0,
                "conf_sum": 0.0,
                "run_ids": set(),
                "evidence_ids": set(),
                "timestamps": set(),
                "event_ids": [],
            },
        )
        g["total"] += 1
        outcome = row["outcome"]
        if outcome in g:
            g[outcome] += 1
        g["conf_sum"] += float(row.get("confidence") or 0.0)
        if row.get("run_id"):
            g["run_ids"].add(row["run_id"])
        g["evidence_ids"].update(parse_json_list(row.get("evidence_ids")))
        if row.get("created_at"):
            g["timestamps"].add(row["created_at"])
        g["event_ids"].append(row["event_id"])

    out: list[dict] = []
    for g in groups.values():
        n = max(1, g["total"])
        conf_rate = round(g["confirmed"] / n, 4)
        inconc_rate = round(g["inconclusive"] / n, 4)
        fp_rate = round(g["false_positive"] / n, 4)
        avg_conf = round(g["conf_sum"] / n, 4)
        if inconc_rate > 0.5 and conf_rate == 0.0:
            action = f"Escalate '{g['strategy']}' or pair with human review (high inconclusive rate {inconc_rate:.0%})"
        elif conf_rate >= 0.5:
            action = f"Prefer '{g['strategy']}' for {g['vuln_class']} ({conf_rate:.0%} confirmation rate)"
        else:
            action = f"Use '{g['strategy']}' cautiously with corroborating proof ({conf_rate:.0%} confirmed)"
        out.append(
            {
                "advisory": True,
                "vuln_class": g["vuln_class"],
                "strategy": g["strategy"],
                "confirmation_rate": conf_rate,
                "inconclusive_rate": inconc_rate,
                "fp_rate": fp_rate,
                "avg_confidence": avg_conf,
                "sample_size": g["total"],
                "recommended_action": action,
                "provenance": _build_provenance(
                    run_ids=g["run_ids"],
                    evidence_ids=g["evidence_ids"],
                    timestamps=g["timestamps"],
                    sample_size=g["total"],
                    extra={"event_ids": g["event_ids"]},
                ),
            }
        )

    out.sort(
        key=lambda r: (-r["confirmation_rate"], r["inconclusive_rate"], -r["sample_size"], r["strategy"])
    )
    return out[: max(1, int(limit))]


def estimate_scan_value_and_cost(
    db: Database,
    skills: list[str] | None = None,
    techs: list[str] | None = None,
    target: str | None = None,
) -> dict:
    """Advisory scan value and cost estimation from historical skill execution telemetry."""
    norm_target = normalize_target(target) if target else None
    norm_techs = sorted({normalize_tech_name(t) for t in (techs or []) if str(t or "").strip()})
    req_tech_set = set(norm_techs)

    all_rows = db.rows("SELECT * FROM skill_telemetry ORDER BY id")
    skill_list = [str(s).strip() for s in (skills or []) if str(s or "").strip()]
    if not skill_list:
        skill_list = sorted({r["skill_id"] for r in all_rows})

    per_skill: list[dict] = []
    total_cost = 0.0
    total_duration = 0.0
    total_tokens = 0
    total_findings = 0.0
    total_confirmed = 0.0
    all_runs: set[str] = set()
    all_evidence: set[str] = set()
    all_timestamps: set[str] = set()
    total_samples = 0

    for sid in skill_list:
        rows = [r for r in all_rows if r["skill_id"] == sid]
        if norm_target:
            target_rows = [r for r in rows if r["target"] == norm_target]
            if target_rows:
                rows = target_rows
        if req_tech_set:
            tech_rows = [
                r for r in rows
                if req_tech_set & {str(x).strip().lower() for x in parse_json_list(r.get("tech_stack"))}
            ]
            if tech_rows:
                rows = tech_rows

        n = len(rows)
        if n == 0:
            per_skill.append(
                {
                    "advisory": True,
                    "skill_id": sid,
                    "sample_size": 0,
                    "avg_cost_usd": 0.0,
                    "avg_duration_ms": 0.0,
                    "avg_tokens": 0,
                    "avg_findings": 0.0,
                    "avg_confirmed": 0.0,
                    "value_score": 0.0,
                    "provenance": _build_provenance(sample_size=0),
                }
            )
            continue

        avg_cost = round(sum(float(r["cost_usd"] or 0.0) for r in rows) / n, 4)
        avg_dur = round(sum(float(r["duration_ms"] or 0.0) for r in rows) / n, 2)
        avg_tok = int(round(sum(int(r["tokens_used"] or 0) for r in rows) / n))
        avg_find = round(sum(int(r["findings_count"] or 0) for r in rows) / n, 3)
        avg_conf = round(sum(int(r["confirmed_count"] or 0) for r in rows) / n, 3)
        val_score = round(avg_conf * 1.0 + avg_find * 0.25, 4)

        s_runs = {r["run_id"] for r in rows if r.get("run_id")}
        s_ev: set[str] = set()
        for r in rows:
            s_ev.update(parse_json_list(r.get("evidence_ids")))
        s_ts = {r["created_at"] for r in rows if r.get("created_at")}

        total_cost += avg_cost
        total_duration += avg_dur
        total_tokens += avg_tok
        total_findings += avg_find
        total_confirmed += avg_conf
        total_samples += n
        all_runs.update(s_runs)
        all_evidence.update(s_ev)
        all_timestamps.update(s_ts)

        per_skill.append(
            {
                "advisory": True,
                "skill_id": sid,
                "sample_size": n,
                "avg_cost_usd": avg_cost,
                "avg_duration_ms": avg_dur,
                "avg_tokens": avg_tok,
                "avg_findings": avg_find,
                "avg_confirmed": avg_conf,
                "value_score": val_score,
                "provenance": _build_provenance(
                    run_ids=s_runs,
                    evidence_ids=s_ev,
                    timestamps=s_ts,
                    sample_size=n,
                ),
            }
        )

    expected_value = round(total_confirmed * 1.0 + total_findings * 0.25, 4)
    value_per_dollar = round(expected_value / total_cost, 4) if total_cost > 0 else expected_value

    return {
        "advisory": True,
        "target": norm_target,
        "techs": norm_techs,
        "skills_evaluated": skill_list,
        "estimated_cost_usd": round(total_cost, 4),
        "estimated_duration_ms": round(total_duration, 2),
        "estimated_tokens": total_tokens,
        "expected_findings": round(total_findings, 3),
        "expected_confirmed": round(total_confirmed, 3),
        "expected_value_score": expected_value,
        "value_per_dollar": value_per_dollar,
        "per_skill": per_skill,
        "provenance": _build_provenance(
            run_ids=all_runs,
            evidence_ids=all_evidence,
            timestamps=all_timestamps,
            sample_size=total_samples,
        ),
    }


def recommend_regression_tests(
    db: Database,
    target: str | None = None,
    vuln_class: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """Advisory regression test recommendations from retest and remediation outcome history."""
    norm_target = normalize_target(target) if target else None
    norm_vc = normalize_vuln_class(vuln_class) if vuln_class else None

    sql = "SELECT * FROM outcome_events WHERE outcome_kind IN ('retest', 'remediation')"
    params: list = []
    if norm_target:
        sql += " AND target = ?"
        params.append(norm_target)
    if norm_vc:
        sql += " AND vuln_class = ?"
        params.append(norm_vc)
    sql += " ORDER BY id"

    outcome_weights = {
        "regression_detected": ("critical", 1.0),
        "still_vulnerable": ("high", 0.85),
        "tested_fail": ("high", 0.80),
        "inconclusive": ("medium", 0.60),
        "applied": ("medium", 0.55),
        "tested_pass": ("medium", 0.50),
        "fixed": ("low", 0.40),
        "proposed": ("low", 0.30),
        "approved": ("low", 0.35),
        "rejected": ("low", 0.20),
    }

    grouped: dict[tuple[str, str, str], dict] = {}
    for row in db.rows(sql, tuple(params)):
        fid = row.get("finding_id") or ""
        t_val = row["target"]
        vc = row.get("vuln_class") or "general"
        key = (fid or f"anon:{t_val}:{vc}", t_val, vc)
        bucket = grouped.setdefault(
            key,
            {
                "finding_id": fid or None,
                "target": t_val,
                "vuln_class": vc,
                "last_outcome": row["outcome"],
                "outcome_kind": row["outcome_kind"],
                "strategy": row.get("strategy") or "replay_validation",
                "run_ids": set(),
                "evidence_ids": set(),
                "timestamps": set(),
                "event_ids": [],
                "occurrences": 0,
            },
        )
        bucket["last_outcome"] = row["outcome"]
        bucket["outcome_kind"] = row["outcome_kind"]
        if row.get("strategy"):
            bucket["strategy"] = row["strategy"]
        if row.get("run_id"):
            bucket["run_ids"].add(row["run_id"])
        bucket["evidence_ids"].update(parse_json_list(row.get("evidence_ids")))
        if row.get("created_at"):
            bucket["timestamps"].add(row["created_at"])
        bucket["event_ids"].append(row["event_id"])
        bucket["occurrences"] += 1

    recs: list[dict] = []
    for b in grouped.values():
        prio_label, base_score = outcome_weights.get(b["last_outcome"], ("low", 0.25))
        score_val = round(min(1.0, base_score + min(0.1, 0.02 * (b["occurrences"] - 1))), 4)
        recs.append(
            {
                "advisory": True,
                "finding_id": b["finding_id"],
                "target": b["target"],
                "vuln_class": b["vuln_class"],
                "last_outcome": b["last_outcome"],
                "outcome_kind": b["outcome_kind"],
                "priority": prio_label,
                "priority_score": score_val,
                "strategy": b["strategy"],
                "reason": (
                    f"Latest {b['outcome_kind']} outcome is '{b['last_outcome']}' on "
                    f"{b['target']} ({b['vuln_class']}); schedule regression verification via {b['strategy']}"
                ),
                "provenance": _build_provenance(
                    run_ids=b["run_ids"],
                    evidence_ids=b["evidence_ids"],
                    timestamps=b["timestamps"],
                    sample_size=b["occurrences"],
                    extra={"event_ids": b["event_ids"]},
                ),
            }
        )

    recs.sort(key=lambda r: (-r["priority_score"], r["target"], r["vuln_class"]))
    return recs[: max(1, int(limit))]


def get_advisory_patterns(
    db: Database,
    target: str | None = None,
    vuln_class: str | None = None,
    min_support: int = 1,
    limit: int = 20,
) -> list[dict]:
    """Return advisory cross-signal patterns (FP signals, validation gaps, regressions, attack paths)."""
    norm_target = normalize_target(target) if target else None
    norm_vc = normalize_vuln_class(vuln_class) if vuln_class else None
    min_sup = max(1, int(min_support))
    results: list[dict] = []

    # 1. Reviewed attack paths
    ap_sql = "SELECT * FROM attack_paths WHERE 1=1"
    ap_params: list = []
    if norm_target:
        ap_sql += " AND target = ?"
        ap_params.append(norm_target)
    ap_sql += " ORDER BY path_risk_score DESC, id DESC"
    for ap in db.rows(ap_sql, tuple(ap_params)):
        fids = parse_json_list(ap.get("finding_ids"))
        steps = parse_json_list(ap.get("steps"))
        results.append(
            {
                "advisory": True,
                "pattern_type": "attack_path",
                "pattern": f"attack_path:{ap['path_id']}",
                "title": ap["title"],
                "target": ap["target"],
                "path_severity": ap["path_severity"],
                "path_risk_score": float(ap["path_risk_score"] or 0.0),
                "verified": bool(ap["verified"]),
                "review_status": ap["review_status"],
                "finding_ids": fids,
                "steps_count": len(steps),
                "support": max(1, len(fids)),
                "description": (
                    f"Reviewed attack path '{ap['title']}' ({ap['path_severity']}, "
                    f"risk={ap['path_risk_score']}, verified={bool(ap['verified'])})"
                ),
                "provenance": _build_provenance(
                    run_ids=[ap["run_id"]] if ap.get("run_id") else [],
                    evidence_ids=parse_json_list(ap.get("evidence_ids")),
                    timestamps=[ap["created_at"]] if ap.get("created_at") else [],
                    sample_size=max(1, len(fids)),
                    extra={"reviewed_by": ap.get("reviewed_by"), "path_id": ap["path_id"]},
                ),
            }
        )

    # 2. Validation/retest outcome trends (inconclusive hotspots & regressions)
    oe_sql = "SELECT * FROM outcome_events WHERE outcome IN ('inconclusive', 'regression_detected', 'still_vulnerable')"
    oe_params: list = []
    if norm_target:
        oe_sql += " AND target = ?"
        oe_params.append(norm_target)
    if norm_vc:
        oe_sql += " AND vuln_class = ?"
        params_vc = norm_vc
        oe_params.append(params_vc)
    oe_groups: dict[tuple[str, str], dict] = {}
    for row in db.rows(oe_sql, tuple(oe_params)):
        vc = row.get("vuln_class") or "general"
        outc = row["outcome"]
        g = oe_groups.setdefault(
            (vc, outc),
            {"count": 0, "run_ids": set(), "evidence_ids": set(), "timestamps": set()},
        )
        g["count"] += 1
        if row.get("run_id"):
            g["run_ids"].add(row["run_id"])
        g["evidence_ids"].update(parse_json_list(row.get("evidence_ids")))
        if row.get("created_at"):
            g["timestamps"].add(row["created_at"])

    for (vc, outc), g in oe_groups.items():
        if g["count"] < min_sup:
            continue
        ptype = "regression" if outc in ("regression_detected", "still_vulnerable") else "validation_gap"
        results.append(
            {
                "advisory": True,
                "pattern_type": ptype,
                "pattern": f"{ptype}:{vc}:{outc}",
                "vuln_class": vc,
                "outcome": outc,
                "support": g["count"],
                "description": f"{g['count']} '{outc}' outcome(s) observed for {vc}",
                "provenance": _build_provenance(
                    run_ids=g["run_ids"],
                    evidence_ids=g["evidence_ids"],
                    timestamps=g["timestamps"],
                    sample_size=g["count"],
                ),
            }
        )

    # 3. False-positive & vuln-class patterns with provenance from findings/triage
    for fp in fp_pattern_candidates(db, min_occurrences=min_sup):
        if norm_vc and fp["vuln_class"] != norm_vc:
            continue
        ts_rows = db.rows(
            "SELECT f.created_at FROM findings f JOIN triage t ON t.finding_id = f.finding_id "
            "WHERE f.vuln_class = ? AND t.verdict = 'false_positive'",
            (fp["vuln_class"],),
        )
        results.append(
            {
                "advisory": True,
                "pattern_type": "false_positive",
                "pattern": f"fp:{fp['vuln_class']}:{fp['signal']}",
                "vuln_class": fp["vuln_class"],
                "signal": fp["signal"],
                "support": fp["occurrences"],
                "description": f"Signal '{fp['signal']}' co-occurred with false_positive on {fp['vuln_class']}",
                "provenance": _build_provenance(
                    timestamps=[r["created_at"] for r in ts_rows if r.get("created_at")],
                    sample_size=fp["occurrences"],
                ),
            }
        )

    for c in per_class_stats(db):
        if norm_vc and c["vuln_class"] != norm_vc:
            continue
        if c["count"] < min_sup:
            continue
        f_rows = db.rows("SELECT created_at FROM findings WHERE vuln_class = ?", (c["vuln_class"],))
        results.append(
            {
                "advisory": True,
                "pattern_type": "vuln_class",
                "pattern": f"class:{c['vuln_class']}",
                "vuln_class": c["vuln_class"],
                "fp_rate": c["fp_rate"],
                "support": c["count"],
                "confirmed": c["confirmed"],
                "description": (
                    f"Vuln class {c['vuln_class']}: {c['confirmed']}/{c['count']} confirmed "
                    f"(fp_rate={c['fp_rate']:.0%})"
                ),
                "provenance": _build_provenance(
                    timestamps=[r["created_at"] for r in f_rows if r.get("created_at")],
                    sample_size=c["count"],
                ),
            }
        )

    results.sort(key=lambda r: (-int(r.get("support", 0)), r["pattern"]))
    return results[: max(1, int(limit))]