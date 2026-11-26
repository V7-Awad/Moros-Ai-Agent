#!/usr/bin/env python3
"""
skill_learner.py — Self-Improving Skill Proposal Engine for Moros AI (Phase 6).

Inspects `TraceLogger` execution spans and `MemoryManager` procedural successes to
draft candidate `SKILL.md` proposals stored under:
    targets/<target>/output/skill-proposals/<proposal_id>/

Governance & Safety Invariants:
- Drafted proposals ALWAYS carry `approved=False` (`status="pending"`, `enabled=False`).
- Proposals are NEVER auto-activated into `skills/` without an explicit
  operator confirmation call to `approve_proposal()`.
- Every proposal tracks versioning (`version`, `supersedes_proposal_id`) and
  provenance (`source_runs`, `source_evidence_ids`, `trace_span_ids`).
- Explicit `rollback_proposal()`, `disable_proposal()`, and `enable_proposal()`
  controls safely archive/remove from active `skills/` without touching `CORE_SKILLS`.
- Hard policy-immutability invariants ensure proposals/learning NEVER modify or
  weaken scope restrictions, tool permissions, budgets, or HITL approval requirements.
"""

import json
import logging
import re
import shutil
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from memory_manager import MemoryManager
    from skill_registry import CORE_SKILLS, SkillRegistry
    from trace_logger import TraceLogger
except ImportError:
    from tools.memory_manager import MemoryManager
    from tools.skill_registry import CORE_SKILLS, SkillRegistry
    from tools.trace_logger import TraceLogger

try:
    from agent_security import detect_injection as _detect_injection
except ImportError:
    try:
        from tools.agent_security import detect_injection as _detect_injection
    except ImportError:
        _detect_injection = None

logger = logging.getLogger("skill-learner")

PROJECT_ROOT = Path(__file__).parent.parent.resolve()

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s\"']+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s\"'&]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\n]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(token\s*[=:]\s*)[^\s\"'&]+"), r"\1<REDACTED>"),
]

# Policy-immutable keys that learned proposals/frontmatter/metadata may NEVER override.
IMMUTABLE_POLICY_KEYS = frozenset({
    "scope",
    "scope_restrictions",
    "allowed_targets",
    "denied_targets",
    "out_of_scope",
    "allow_out_of_scope",
    "expand_scope",
    "bypass_scope",
    "tool_permissions",
    "skill_tool_permissions",
    "enforce_permissions",
    "allowed_tools",
    "grant_tools",
    "allow_all_tools",
    "budget",
    "budgets",
    "action_budget",
    "cost_budget",
    "budget_usd",
    "max_actions",
    "max_steps",
    "unlimited_budget",
    "hitl",
    "hitl_approval",
    "require_approval",
    "checkpoint_required",
    "auto_approve",
    "bypass_hitl",
    "moros_allow_gated_post",
    "moros_hitl_blocking",
    "policy_overrides",
    "security_policy",
})

_POLICY_WEAKENING_PATTERNS = [
    (
        "scope_restriction",
        re.compile(
            r"(?i)\b(?:bypass|ignore|disable|weaken|relax|expand|override|skip|remove)"
            r"\b[^.\n]{0,48}\b(?:scope|scope[-_ ]restrictions?|allow[-_ ]?list|deny[-_ ]?list|target[-_ ]restrictions?)\b"
        ),
    ),
    (
        "scope_restriction",
        re.compile(r"(?i)\b(?:test|scan|attack|probe|target)\b[^.\n]{0,32}\bout[-_ ]of[-_ ]scope\b"),
    ),
    (
        "scope_restriction",
        re.compile(r"(?i)\ballow_out_of_scope\s*[:=]\s*true\b"),
    ),
    (
        "tool_permissions",
        re.compile(
            r"(?i)\b(?:bypass|ignore|disable|weaken|override|modify|escalate|relax|grant)"
            r"\b[^.\n]{0,48}\b(?:tool[-_ ]permissions?|SKILL_TOOL_PERMISSIONS|enforce_permissions|permission[-_ ]checks?)\b"
        ),
    ),
    (
        "tool_permissions",
        re.compile(r"(?i)\benforce_permissions\s*[:=]\s*false\b|\ballow_all_tools\s*[:=]\s*true\b"),
    ),
    (
        "budget_controls",
        re.compile(
            r"(?i)\b(?:bypass|ignore|disable|weaken|override|remove|increase|raise|exceed)"
            r"\b[^.\n]{0,48}\b(?:budget|action[-_ ]budget|cost[-_ ]budget|max_actions|max_steps|rate[-_ ]limit)\b"
        ),
    ),
    (
        "budget_controls",
        re.compile(r"(?i)\bunlimited[-_ ]budget\b|\bdisable[-_ ]budget\b"),
    ),
    (
        "hitl_approval",
        re.compile(
            r"(?i)\b(?:bypass|ignore|disable|weaken|override|skip|circumvent|auto[-_ ]?approve)"
            r"\b[^.\n]{0,48}\b(?:hitl|human[-_ ]in[-_ ]the[-_ ]loop|checkpoint|approval[-_ ]requirements?|operator[-_ ]approval|gated[-_ ]post)\b"
        ),
    ),
    (
        "hitl_approval",
        re.compile(
            r"(?i)\bauto_?approve\s*[:=]\s*true\b|"
            r"\bMOROS_ALLOW_GATED_POST\s*=\s*(?:1|true)\b|"
            r"\bMOROS_HITL_BLOCKING\s*=\s*(?:0|false)\b"
        ),
    ),
]


class PolicyInvariantViolation(ValueError):
    """Raised when a skill proposal attempts to modify or weaken immutable security policies."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_text(text: str) -> str:
    cleaned = str(text or "")
    for pattern, repl in _SECRET_PATTERNS:
        cleaned = pattern.sub(repl, cleaned)
    return cleaned.strip()


def _normalize_skill_id(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9-]+", "-", (name or "").strip().lower()).strip("-")
    if not slug:
        slug = f"learned-skill-{uuid.uuid4().hex[:6]}"
    return slug[:64]


def _clean_id_list(values: Any) -> List[str]:
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    seen = set()
    out: List[str] = []
    for item in values:
        val = _sanitize_text(str(item or ""))
        if val and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def _extract_frontmatter_keys(skill_md_text: str) -> Dict[str, str]:
    """Extract top-level YAML frontmatter key/value pairs without requiring PyYAML."""
    lines = skill_md_text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    kv: Dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" in line and not line.startswith((" ", "\t", "-")):
            key, val = line.split(":", 1)
            kv[key.strip().lower()] = val.strip()
    return kv


def validate_proposal_policy_invariants(
    payload: Optional[Dict[str, Any]] = None,
    skill_md_text: Optional[str] = None,
    *,
    is_draft: bool = False,
) -> None:
    """
    Hard invariant check: learned skills/proposals may NEVER modify or weaken
    scope restrictions, tool permissions, budgets, or HITL approval requirements.
    Raises PolicyInvariantViolation on any violation.
    """
    texts_to_scan: List[str] = []

    def _walk_dict(d: Any, path: str = "") -> None:
        if isinstance(d, dict):
            for k, v in d.items():
                key_l = str(k).strip().lower()
                if key_l in IMMUTABLE_POLICY_KEYS:
                    # Allow top-level metadata key `approved: False` only when not drafted with approved=True
                    if key_l == "approved" and not path and v is False and not is_draft:
                        continue
                    if key_l == "approved" and not path and v is True and not is_draft:
                        # Top-level approved=True is permitted only after explicit approve_proposal()
                        continue
                    raise PolicyInvariantViolation(
                        f"Proposal attempts to set/modify immutable security policy key '{k}'"
                    )
                if isinstance(v, (dict, list)):
                    _walk_dict(v, f"{path}.{key_l}" if path else key_l)
                elif isinstance(v, str):
                    texts_to_scan.append(v)
        elif isinstance(d, list):
            for item in d:
                if isinstance(item, (dict, list)):
                    _walk_dict(item, path)
                elif isinstance(item, str):
                    texts_to_scan.append(item)

    if payload is not None:
        _walk_dict(payload)
        if is_draft and payload.get("approved") is True:
            raise PolicyInvariantViolation("Drafted proposals must have approved=False")

    if skill_md_text:
        texts_to_scan.append(skill_md_text)
        fm = _extract_frontmatter_keys(skill_md_text)
        for k, v in fm.items():
            if k in IMMUTABLE_POLICY_KEYS:
                if k == "approved" and v.lower() in ("false", "no", "0"):
                    continue
                raise PolicyInvariantViolation(
                    f"SKILL.md frontmatter attempts to set immutable policy key '{k}'"
                )

    combined = "\n".join(texts_to_scan)
    for category, pattern in _POLICY_WEAKENING_PATTERNS:
        m = pattern.search(combined)
        if m:
            raise PolicyInvariantViolation(
                f"Proposal violates immutable {category} policy: '{m.group(0)[:120]}'"
            )

    if _detect_injection is not None and combined:
        detections = _detect_injection(combined)
        if detections:
            raise PolicyInvariantViolation(
                f"Proposal contains prompt-injection / policy-override text: '{detections[0].get('matched_text', '')[:80]}'"
            )


class SkillLearner:
    """
    Mines `TraceLogger` spans and `MemoryManager` procedural successes to draft
    human-reviewable `SKILL.md` proposals without auto-activating them.
    """

    def __init__(
        self,
        target_dir: Path,
        skills_dir: Optional[Path] = None,
        trace_logger: Optional[TraceLogger] = None,
        memory_manager: Optional[MemoryManager] = None,
    ):
        self.target_dir = Path(target_dir).resolve()
        self.proposals_dir = self.target_dir / "output" / "skill-proposals"
        self.proposals_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir = self.target_dir / "output" / "skill-proposals-archive"
        self.skills_dir = Path(skills_dir).resolve() if skills_dir else (PROJECT_ROOT / "skills")
        self.trace_logger = trace_logger
        self.memory_manager = memory_manager or MemoryManager(self.target_dir)

    @staticmethod
    def validate_policy_invariants(
        payload: Optional[Dict[str, Any]] = None,
        skill_md_text: Optional[str] = None,
        *,
        is_draft: bool = False,
    ) -> None:
        validate_proposal_policy_invariants(payload, skill_md_text, is_draft=is_draft)

    def _load_trace_spans(self) -> List[Dict[str, Any]]:
        """Collect spans from in-memory TraceLogger and exported trace JSON files."""
        spans: List[Dict[str, Any]] = []
        seen_ids = set()

        def _add_span(span: Dict[str, Any]) -> None:
            if not isinstance(span, dict):
                return
            sid = span.get("span_id")
            if sid and sid in seen_ids:
                return
            if sid:
                seen_ids.add(sid)
            spans.append(span)

        if self.trace_logger is not None:
            for trace_spans in self.trace_logger.get_all_traces().values():
                for s in trace_spans:
                    _add_span(s)

        traces_dir = self.target_dir / "output" / "traces"
        if traces_dir.is_dir():
            for path in sorted(traces_dir.glob("*.json")):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(data, list):
                    for s in data:
                        _add_span(s)
                elif isinstance(data, dict):
                    for trace_spans in data.values():
                        if isinstance(trace_spans, list):
                            for s in trace_spans:
                                _add_span(s)

        return spans

    def collect_evidence(self, min_success_count: int = 1) -> List[Dict[str, Any]]:
        """
        Inspect procedural successes and trace spans to aggregate candidate skill patterns
        with provenance (`source_runs`, `source_evidence_ids`, `trace_span_ids`).
        """
        techniques = self.memory_manager.recall_techniques(success_only=True, limit=250)
        if not techniques:
            return []

        spans = self._load_trace_spans()
        ok_tool_spans = [
            s for s in spans
            if s.get("type") == "tool" and s.get("status") == "ok"
        ]
        ok_skill_spans = [
            s for s in spans
            if s.get("type") == "skill" and s.get("status") == "ok"
        ]
        scan_runs = {
            str(s.get("trace_id") or "").strip(): str(s.get("name") or "").strip()
            for s in spans
            if s.get("type") == "scan" and s.get("trace_id")
        }

        grouped: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "technique": "",
            "success_count": 0,
            "outcomes": [],
            "contexts": [],
            "notes": [],
            "tools_observed": [],
            "trace_span_ids": [],
            "source_runs": [],
            "source_evidence_ids": [],
        })

        for row in techniques:
            tech = (row.get("technique") or "").strip()
            if not tech:
                continue
            key = _normalize_skill_id(tech)
            bucket = grouped[key]
            bucket["technique"] = tech
            bucket["success_count"] += 1
            outcome = _sanitize_text(row.get("outcome", ""))
            ctx = _sanitize_text(row.get("target_context", ""))
            note = _sanitize_text(row.get("notes", ""))
            if outcome and outcome not in bucket["outcomes"]:
                bucket["outcomes"].append(outcome)
            if ctx and ctx not in bucket["contexts"]:
                bucket["contexts"].append(ctx)
            if note and note not in bucket["notes"]:
                bucket["notes"].append(note)
            if row.get("run_id"):
                for rid in _clean_id_list([row.get("run_id")]):
                    if rid not in bucket["source_runs"]:
                        bucket["source_runs"].append(rid)
            for eid in _clean_id_list(row.get("evidence_ids")):
                if eid not in bucket["source_evidence_ids"]:
                    bucket["source_evidence_ids"].append(eid)

        # Correlate trace spans by skill name or tool attributes
        for key, bucket in grouped.items():
            tech_lower = bucket["technique"].lower()
            matching_skill_ids = set()
            for s in ok_skill_spans:
                span_name = str(s.get("name", "")).strip()
                span_slug = _normalize_skill_id(span_name)
                span_lower = span_name.lower()
                if (
                    key in span_slug
                    or (len(span_slug) >= 3 and span_slug in key)
                    or tech_lower in span_lower
                    or (len(span_lower) >= 3 and span_lower in tech_lower)
                ):
                    if s.get("span_id"):
                        matching_skill_ids.add(s["span_id"])
            for s in ok_skill_spans:
                if s.get("span_id") in matching_skill_ids and s.get("span_id"):
                    if s["span_id"] not in bucket["trace_span_ids"]:
                        bucket["trace_span_ids"].append(s["span_id"])
                    attrs = s.get("attributes") or {}
                    run_ref = attrs.get("run_id") or scan_runs.get(s.get("trace_id", "")) or s.get("trace_id")
                    for rid in _clean_id_list([run_ref]):
                        if rid not in bucket["source_runs"]:
                            bucket["source_runs"].append(rid)
                    for eid in _clean_id_list(attrs.get("evidence_ids") or attrs.get("evidence_id")):
                        if eid not in bucket["source_evidence_ids"]:
                            bucket["source_evidence_ids"].append(eid)

            for ts in ok_tool_spans:
                attrs = ts.get("attributes") or {}
                tool_name = str(attrs.get("tool.name") or ts.get("name", "")).strip()
                args_str = _sanitize_text(str(attrs.get("tool.args", "")))
                matches_parent = ts.get("parent_id") in matching_skill_ids
                matches_text = (
                    tech_lower in tool_name.lower()
                    or tech_lower in args_str.lower()
                    or key.replace("-", "_") in tech_lower
                )
                if matches_parent or matches_text or not matching_skill_ids:
                    if tool_name and tool_name not in bucket["tools_observed"]:
                        bucket["tools_observed"].append(tool_name)
                    if ts.get("span_id") and ts["span_id"] not in bucket["trace_span_ids"]:
                        bucket["trace_span_ids"].append(ts["span_id"])
                    run_ref = attrs.get("run_id") or scan_runs.get(ts.get("trace_id", "")) or ts.get("trace_id")
                    for rid in _clean_id_list([run_ref]):
                        if rid not in bucket["source_runs"]:
                            bucket["source_runs"].append(rid)
                    for eid in _clean_id_list(attrs.get("evidence_ids") or attrs.get("evidence_id")):
                        if eid not in bucket["source_evidence_ids"]:
                            bucket["source_evidence_ids"].append(eid)

        evidence_list = [
            {"skill_id": key, **data}
            for key, data in grouped.items()
            if data["success_count"] >= max(1, int(min_success_count))
        ]
        evidence_list.sort(key=lambda item: item["success_count"], reverse=True)
        return evidence_list

    def _render_skill_md(
        self,
        skill_id: str,
        title: str,
        category: str,
        description: str,
        checklist: List[str],
        evidence: Dict[str, Any],
        version: int = 1,
        supersedes_proposal_id: Optional[str] = None,
    ) -> str:
        checklist_lines = "\n".join(f"- [ ] {item}" for item in checklist)
        outcomes_md = "\n".join(f"- {o}" for o in evidence.get("outcomes", [])[:5]) or "- Verified procedural success."
        tools_md = ", ".join(f"`{t}`" for t in evidence.get("tools_observed", [])[:8]) or "`http_get`"
        contexts_md = ", ".join(evidence.get("contexts", [])[:5]) or "Authorized web target"
        runs_md = ", ".join(_clean_id_list(evidence.get("source_runs"))[:5]) or "none"
        ev_ids_md = ", ".join(_clean_id_list(evidence.get("source_evidence_ids"))[:5]) or "none"

        return (
            f"---\n"
            f"name: {skill_id}\n"
            f"category: {category}\n"
            f"version: {version}\n"
            f"description: >\n"
            f"  {description}\n"
            f"---\n\n"
            f"# {title} (`{skill_id}`)\n\n"
            f"**Category:** {category}  \n"
            f"**Version:** {version}"
            + (f" (supersedes `{supersedes_proposal_id}`)" if supersedes_proposal_id else "")
            + "  \n"
            f"**Status:** Proposed (Requires explicit human approval before activation)  \n"
            f"**Observed Successes:** {evidence.get('success_count', 1)}  \n\n"
            f"## Description\n"
            f"{description}\n\n"
            f"## Observed Context & Tools\n"
            f"- **Contexts:** {contexts_md}\n"
            f"- **Tools Used:** {tools_md}\n"
            f"- **Source Runs:** {runs_md}\n"
            f"- **Source Evidence IDs:** {ev_ids_md}\n\n"
            f"## Proven Outcomes\n"
            f"{outcomes_md}\n\n"
            f"## Verification Checklist\n"
            f"{checklist_lines}\n\n"
            f"## Safety & Scope Constraints\n"
            f"- Strict scope adherence: only assess targets explicitly authorized in scope.\n"
            f"- Never auto-activate learned proposals without explicit operator review.\n"
        )

    def _latest_proposal_for_skill(self, skill_id: str) -> Optional[Dict[str, Any]]:
        matches = [
            p for p in self.list_proposals()
            if p.get("skill_id") == skill_id
        ]
        if not matches:
            return None
        matches.sort(key=lambda p: (int(p.get("version", 1)), str(p.get("created_at", ""))))
        return matches[-1]

    def draft_proposal(
        self,
        evidence: Dict[str, Any],
        category: str = "Learned Security Pattern",
        supersedes_proposal_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Draft and persist a single candidate SKILL.md proposal with `approved=False`.
        Never writes to `self.skills_dir`. Enforces policy-immutability invariants.
        """
        if not isinstance(evidence, dict):
            raise TypeError("evidence must be a dict")

        # Hard invariant check before any file creation
        validate_proposal_policy_invariants(evidence, is_draft=True)

        technique = _sanitize_text(evidence.get("technique") or evidence.get("skill_id") or "learned-pattern")
        base_slug = _normalize_skill_id(evidence.get("skill_id") or technique)
        # Avoid colliding with built-in core skills
        skill_id = f"learned-{base_slug}" if base_slug in CORE_SKILLS else base_slug
        title = technique.replace("_", " ").replace("-", " ").title()

        # Versioning & superseding resolution
        if supersedes_proposal_id is not None:
            prev = self.get_proposal(supersedes_proposal_id)
            if not prev:
                raise KeyError(f"Superseded proposal not found: {supersedes_proposal_id}")
            version = int(prev.get("version", 1)) + 1
            resolved_supersedes = prev["proposal_id"]
        else:
            prev = self._latest_proposal_for_skill(skill_id)
            if prev:
                version = int(prev.get("version", 1)) + 1
                resolved_supersedes = prev["proposal_id"]
            else:
                version = 1
                resolved_supersedes = None

        outcomes = [_sanitize_text(o) for o in (evidence.get("outcomes") or []) if _sanitize_text(o)]
        tools_used = [_sanitize_text(t) for t in (evidence.get("tools_observed") or []) if _sanitize_text(t)]
        contexts = [_sanitize_text(c) for c in (evidence.get("contexts") or []) if _sanitize_text(c)]

        prov_dict = evidence.get("provenance") if isinstance(evidence.get("provenance"), dict) else {}
        source_runs = _clean_id_list(
            list(evidence.get("source_runs") or []) + list(prov_dict.get("source_runs") or [])
        )
        source_evidence_ids = _clean_id_list(
            list(evidence.get("source_evidence_ids") or []) + list(prov_dict.get("source_evidence_ids") or [])
        )
        trace_span_ids = _clean_id_list(
            list(evidence.get("trace_span_ids") or []) + list(prov_dict.get("trace_span_ids") or [])
        )

        description = (
            f"Candidate security skill synthesized from {evidence.get('success_count', 1)} "
            f"successful procedural execution(s) of '{technique}'."
        )

        checklist: List[str] = [
            f"Verify target authorization before executing {skill_id} checks",
        ]
        if tools_used:
            checklist.append(f"Replay validated tool sequence using: {', '.join(tools_used[:4])}")
        for out in outcomes[:3]:
            checklist.append(f"Confirm reproducible signal matching: {out[:120]}")
        checklist.append("Document verified PoC and tag severity as AI-proposed pending human review")

        sanitized_evidence = {
            **evidence,
            "outcomes": outcomes,
            "tools_observed": tools_used,
            "contexts": contexts,
            "source_runs": source_runs,
            "source_evidence_ids": source_evidence_ids,
            "trace_span_ids": trace_span_ids,
        }

        skill_md = self._render_skill_md(
            skill_id=skill_id,
            title=title,
            category=category,
            description=description,
            checklist=checklist,
            evidence=sanitized_evidence,
            version=version,
            supersedes_proposal_id=resolved_supersedes,
        )

        # Re-validate rendered SKILL.md against policy invariants prior to persisting
        validate_proposal_policy_invariants(sanitized_evidence, skill_md, is_draft=True)

        proposal_id = f"prop-{skill_id}-v{version}-{uuid.uuid4().hex[:6]}"
        prop_dir = self.proposals_dir / proposal_id
        prop_dir.mkdir(parents=True, exist_ok=True)

        skill_md_path = prop_dir / "SKILL.md"
        skill_md_path.write_text(skill_md, encoding="utf-8")

        created_at = _now_iso()
        proposal_meta: Dict[str, Any] = {
            "proposal_id": proposal_id,
            "skill_id": skill_id,
            "version": version,
            "supersedes_proposal_id": resolved_supersedes,
            "title": title,
            "category": category,
            "description": description,
            "approved": False,
            "enabled": False,
            "status": "pending",
            "created_at": created_at,
            "approved_at": None,
            "approved_by": None,
            "activated_path": None,
            "archived_path": None,
            "skill_md_path": str(skill_md_path),
            "provenance": {
                "source_runs": source_runs,
                "source_evidence_ids": source_evidence_ids,
                "trace_span_ids": trace_span_ids,
                "created_at": created_at,
            },
            "source_evidence": {
                "technique": technique,
                "success_count": int(evidence.get("success_count", 1)),
                "outcomes": outcomes,
                "contexts": contexts,
                "tools_observed": tools_used,
                "source_runs": source_runs,
                "source_evidence_ids": source_evidence_ids,
                "trace_span_ids": trace_span_ids,
            },
            "history": [
                {
                    "event": "drafted",
                    "timestamp": created_at,
                    "version": version,
                    "supersedes_proposal_id": resolved_supersedes,
                }
            ],
        }
        (prop_dir / "proposal.json").write_text(
            json.dumps(proposal_meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Drafted unapproved skill proposal %s (v%d) -> %s", proposal_id, version, skill_md_path)
        return proposal_meta

    def propose_skills(
        self,
        min_success_count: int = 1,
        max_proposals: int = 10,
        category: str = "Learned Security Pattern",
    ) -> List[Dict[str, Any]]:
        """
        Inspect TraceLogger spans and MemoryManager procedural successes and generate
        candidate SKILL.md proposals under `targets/<target>/output/skill-proposals/`.
        """
        evidence_items = self.collect_evidence(min_success_count=min_success_count)
        proposals: List[Dict[str, Any]] = []
        for item in evidence_items[: max(0, int(max_proposals))]:
            proposals.append(self.draft_proposal(item, category=category))
        return proposals

    def list_proposals(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all persisted proposals under `skill-proposals/`."""
        results: List[Dict[str, Any]] = []
        if not self.proposals_dir.is_dir():
            return results
        for prop_dir in sorted(self.proposals_dir.iterdir()):
            meta_file = prop_dir / "proposal.json"
            if not meta_file.is_file():
                continue
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if status and meta.get("status") != status:
                continue
            results.append(meta)
        return results

    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single proposal metadata dict by proposal_id."""
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "", proposal_id or "")
        if not safe_id:
            return None
        meta_file = self.proposals_dir / safe_id / "proposal.json"
        if not meta_file.is_file():
            return None
        try:
            return json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _save_meta(self, meta: Dict[str, Any]) -> None:
        prop_dir = self.proposals_dir / meta["proposal_id"]
        (prop_dir / "proposal.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _validate_skill_target_safe(self, raw_skill_id: str) -> str:
        skill_id = _normalize_skill_id(raw_skill_id)
        if skill_id in CORE_SKILLS:
            raise ValueError(f"Refusing to modify built-in core skill '{skill_id}'")
        dest_dir = (self.skills_dir / skill_id).resolve()
        if not dest_dir.is_relative_to(self.skills_dir):
            raise PolicyInvariantViolation(f"Unsafe skill path outside skills_dir: {skill_id}")
        return skill_id

    def _activate_skill_files(self, meta: Dict[str, Any], skill_id: str, actor: str, timestamp: str) -> Path:
        prop_dir = self.proposals_dir / meta["proposal_id"]
        skill_md_path = prop_dir / "SKILL.md"
        if not skill_md_path.is_file():
            raise FileNotFoundError(f"Proposal SKILL.md missing: {skill_md_path}")
        skill_md_text = skill_md_path.read_text(encoding="utf-8")
        validate_proposal_policy_invariants(meta, skill_md_text, is_draft=False)

        registry = SkillRegistry(skills_dir=self.skills_dir)
        dest_dir = (registry.skills_dir / skill_id).resolve()
        if not dest_dir.is_relative_to(registry.skills_dir.resolve()):
            raise PolicyInvariantViolation(f"Unsafe destination outside skills_dir: {dest_dir}")
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "SKILL.md").write_text(skill_md_text, encoding="utf-8")
        manifest = {
            "id": skill_id,
            "title": meta.get("title", skill_id),
            "category": meta.get("category", "Learned Security Pattern"),
            "description": meta.get("description", ""),
            "version": int(meta.get("version", 1)),
            "supersedes_proposal_id": meta.get("supersedes_proposal_id"),
            "is_custom": True,
            "approved_by": meta.get("approved_by") or actor,
            "learned_from_proposal": meta["proposal_id"],
            "provenance": meta.get("provenance", {}),
            "activated_at": timestamp,
        }
        (dest_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return dest_dir

    def _archive_and_remove_active_skill(self, meta: Dict[str, Any], skill_id: str, reason_tag: str) -> Optional[Path]:
        if skill_id in CORE_SKILLS:
            raise ValueError(f"Refusing to remove or archive built-in core skill '{skill_id}'")
        active_dir = (self.skills_dir / skill_id).resolve()
        if not active_dir.is_relative_to(self.skills_dir):
            raise PolicyInvariantViolation(f"Unsafe skill path outside skills_dir: {skill_id}")
        if not active_dir.is_dir():
            return None

        self.archive_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive_dest = self.archive_dir / f"{meta['proposal_id']}-{reason_tag}-{stamp}"
        shutil.copytree(active_dir, archive_dest, dirs_exist_ok=True)
        shutil.rmtree(active_dir)
        return archive_dest

    def approve_proposal(
        self,
        proposal_id: str,
        approved_by: str = "operator",
        activate: bool = True,
    ) -> Dict[str, Any]:
        """
        Explicitly approve a candidate skill proposal and optionally activate it
        into `skills/<skill_id>/SKILL.md`.
        """
        meta = self.get_proposal(proposal_id)
        if not meta:
            raise KeyError(f"Skill proposal not found: {proposal_id}")
        if meta.get("status") == "rejected":
            raise ValueError(f"Cannot approve rejected proposal '{proposal_id}'")

        skill_id = self._validate_skill_target_safe(meta["skill_id"])

        prop_dir = self.proposals_dir / meta["proposal_id"]
        skill_md_path = prop_dir / "SKILL.md"
        if not skill_md_path.is_file():
            raise FileNotFoundError(f"Proposal SKILL.md missing: {skill_md_path}")
        skill_md_text = skill_md_path.read_text(encoding="utf-8")
        validate_proposal_policy_invariants(meta, skill_md_text, is_draft=False)

        now = _now_iso()
        meta["approved"] = True
        meta["status"] = "approved"
        meta["approved_by"] = approved_by
        meta["approved_at"] = now
        meta["enabled"] = bool(activate)

        if activate:
            dest_dir = self._activate_skill_files(meta, skill_id, approved_by, now)
            meta["activated_path"] = str(dest_dir)
        else:
            meta["activated_path"] = None

        meta.setdefault("history", []).append(
            {
                "event": "approved",
                "timestamp": now,
                "actor": approved_by,
                "activated": bool(activate),
            }
        )
        self._save_meta(meta)
        logger.info("Approved skill proposal %s (activated=%s)", proposal_id, activate)
        return meta

    def disable_proposal(
        self,
        proposal_id: str,
        reason: str = "",
        disabled_by: str = "operator",
    ) -> Dict[str, Any]:
        """
        Safely disable an approved/active proposal by archiving and removing its files
        from active `skills/` without touching `CORE_SKILLS`.
        """
        meta = self.get_proposal(proposal_id)
        if not meta:
            raise KeyError(f"Skill proposal not found: {proposal_id}")

        skill_id = self._validate_skill_target_safe(meta["skill_id"])
        archived = self._archive_and_remove_active_skill(meta, skill_id, "disabled")

        now = _now_iso()
        meta["enabled"] = False
        meta["status"] = "disabled"
        meta["disabled_at"] = now
        meta["disabled_by"] = disabled_by
        meta["disable_reason"] = reason
        meta["activated_path"] = None
        if archived is not None:
            meta["archived_path"] = str(archived)
        meta.setdefault("history", []).append(
            {
                "event": "disabled",
                "timestamp": now,
                "actor": disabled_by,
                "reason": reason,
                "archived_path": str(archived) if archived else None,
            }
        )
        self._save_meta(meta)
        logger.info("Disabled skill proposal %s", proposal_id)
        return meta

    def enable_proposal(
        self,
        proposal_id: str,
        enabled_by: str = "operator",
    ) -> Dict[str, Any]:
        """
        Re-enable a previously approved and disabled skill proposal into active `skills/`.
        Refuses unapproved, pending, rejected, or rolled-back proposals.
        """
        meta = self.get_proposal(proposal_id)
        if not meta:
            raise KeyError(f"Skill proposal not found: {proposal_id}")
        if not meta.get("approved"):
            raise ValueError(f"Cannot enable unapproved proposal '{proposal_id}' (approve_proposal required)")
        if meta.get("status") in ("pending", "rejected", "rolled_back"):
            raise ValueError(f"Cannot enable proposal '{proposal_id}' with status '{meta.get('status')}'")

        skill_id = self._validate_skill_target_safe(meta["skill_id"])
        now = _now_iso()
        dest_dir = self._activate_skill_files(meta, skill_id, enabled_by, now)

        meta["enabled"] = True
        meta["status"] = "approved"
        meta["enabled_at"] = now
        meta["enabled_by"] = enabled_by
        meta["activated_path"] = str(dest_dir)
        meta.setdefault("history", []).append(
            {
                "event": "enabled",
                "timestamp": now,
                "actor": enabled_by,
            }
        )
        self._save_meta(meta)
        logger.info("Enabled skill proposal %s", proposal_id)
        return meta

    def rollback_proposal(
        self,
        proposal_id: str,
        reason: str = "",
        rolled_back_by: str = "operator",
        restore_previous: bool = False,
    ) -> Dict[str, Any]:
        """
        Roll back a skill proposal: revoke approval/enabled state, archive and remove
        from active `skills/` safely without touching `CORE_SKILLS`, and optionally
        restore a previously approved superseded version.
        """
        meta = self.get_proposal(proposal_id)
        if not meta:
            raise KeyError(f"Skill proposal not found: {proposal_id}")

        skill_id = self._validate_skill_target_safe(meta["skill_id"])
        archived = self._archive_and_remove_active_skill(meta, skill_id, "rollback")

        now = _now_iso()
        meta["approved"] = False
        meta["enabled"] = False
        meta["status"] = "rolled_back"
        meta["rolled_back_at"] = now
        meta["rolled_back_by"] = rolled_back_by
        meta["rollback_reason"] = reason
        meta["activated_path"] = None
        if archived is not None:
            meta["archived_path"] = str(archived)

        restored_id: Optional[str] = None
        if restore_previous and meta.get("supersedes_proposal_id"):
            prev = self.get_proposal(meta["supersedes_proposal_id"])
            if (
                prev
                and prev.get("approved") is True
                and prev.get("status") not in ("rejected", "rolled_back")
            ):
                prev_skill_id = self._validate_skill_target_safe(prev["skill_id"])
                dest_dir = self._activate_skill_files(prev, prev_skill_id, rolled_back_by, now)
                prev["enabled"] = True
                prev["status"] = "approved"
                prev["activated_path"] = str(dest_dir)
                prev.setdefault("history", []).append(
                    {
                        "event": "restored_by_rollback",
                        "timestamp": now,
                        "actor": rolled_back_by,
                        "from_proposal_id": meta["proposal_id"],
                    }
                )
                self._save_meta(prev)
                restored_id = prev["proposal_id"]
                meta["restored_proposal_id"] = restored_id

        meta.setdefault("history", []).append(
            {
                "event": "rolled_back",
                "timestamp": now,
                "actor": rolled_back_by,
                "reason": reason,
                "archived_path": str(archived) if archived else None,
                "restored_proposal_id": restored_id,
            }
        )
        self._save_meta(meta)
        logger.info("Rolled back skill proposal %s (restored=%s)", proposal_id, restored_id)
        return meta

    def reject_proposal(
        self,
        proposal_id: str,
        reason: str = "",
        rejected_by: str = "operator",
    ) -> Dict[str, Any]:
        """Reject a skill proposal so it remains inactive."""
        meta = self.get_proposal(proposal_id)
        if not meta:
            raise KeyError(f"Skill proposal not found: {proposal_id}")
        skill_id = self._validate_skill_target_safe(meta["skill_id"])
        archived = self._archive_and_remove_active_skill(meta, skill_id, "rejected")

        now = _now_iso()
        meta["approved"] = False
        meta["enabled"] = False
        meta["status"] = "rejected"
        meta["rejection_reason"] = reason
        meta["rejected_at"] = now
        meta["rejected_by"] = rejected_by
        meta["activated_path"] = None
        if archived is not None:
            meta["archived_path"] = str(archived)
        meta.setdefault("history", []).append(
            {
                "event": "rejected",
                "timestamp": now,
                "actor": rejected_by,
                "reason": reason,
            }
        )
        self._save_meta(meta)
        return meta
