#!/usr/bin/env python3
"""
skill_learner.py — Self-Improving Skill Proposal Engine for Moros AI (P3-1).

Inspects `TraceLogger` execution spans and `MemoryManager` procedural successes to
draft candidate `SKILL.md` proposals stored under:
    targets/<target>/output/skill-proposals/<proposal_id>/

Safety invariant:
- Drafted proposals ALWAYS carry `approved=False` (`status="pending"`).
- Proposals are NEVER auto-activated into `skills/` without an explicit
  operator confirmation call to `approve_proposal()`.
"""

import json
import logging
import re
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

logger = logging.getLogger("skill-learner")

PROJECT_ROOT = Path(__file__).parent.parent.resolve()

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s\"']+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s\"'&]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\n]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(token\s*[=:]\s*)[^\s\"'&]+"), r"\1<REDACTED>"),
]


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
        self.skills_dir = Path(skills_dir).resolve() if skills_dir else (PROJECT_ROOT / "skills")
        self.trace_logger = trace_logger
        self.memory_manager = memory_manager or MemoryManager(self.target_dir)

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
        Inspect procedural successes and trace spans to aggregate candidate skill patterns.
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

        grouped: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "technique": "",
            "success_count": 0,
            "outcomes": [],
            "contexts": [],
            "notes": [],
            "tools_observed": [],
            "trace_span_ids": [],
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

        # Correlate trace spans by skill name or tool attributes
        for key, bucket in grouped.items():
            tech_lower = bucket["technique"].lower()
            matching_skill_ids = {
                s.get("span_id")
                for s in ok_skill_spans
                if key in _normalize_skill_id(s.get("name", ""))
                or tech_lower in str(s.get("name", "")).lower()
            }
            for s in ok_skill_spans:
                if s.get("span_id") in matching_skill_ids and s.get("span_id"):
                    bucket["trace_span_ids"].append(s["span_id"])

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
    ) -> str:
        checklist_lines = "\n".join(f"- [ ] {item}" for item in checklist)
        outcomes_md = "\n".join(f"- {o}" for o in evidence.get("outcomes", [])[:5]) or "- Verified procedural success."
        tools_md = ", ".join(f"`{t}`" for t in evidence.get("tools_observed", [])[:8]) or "`http_get`"
        contexts_md = ", ".join(evidence.get("contexts", [])[:5]) or "Authorized web target"

        return (
            f"---\n"
            f"name: {skill_id}\n"
            f"category: {category}\n"
            f"description: >\n"
            f"  {description}\n"
            f"---\n\n"
            f"# {title} (`{skill_id}`)\n\n"
            f"**Category:** {category}  \n"
            f"**Status:** Proposed (Requires explicit human approval before activation)  \n"
            f"**Observed Successes:** {evidence.get('success_count', 1)}  \n\n"
            f"## Description\n"
            f"{description}\n\n"
            f"## Observed Context & Tools\n"
            f"- **Contexts:** {contexts_md}\n"
            f"- **Tools Used:** {tools_md}\n\n"
            f"## Proven Outcomes\n"
            f"{outcomes_md}\n\n"
            f"## Verification Checklist\n"
            f"{checklist_lines}\n\n"
            f"## Safety & Scope Constraints\n"
            f"- Strict scope adherence: only assess targets explicitly authorized in scope.\n"
            f"- Never auto-activate learned proposals without explicit operator review.\n"
        )

    def draft_proposal(
        self,
        evidence: Dict[str, Any],
        category: str = "Learned Security Pattern",
    ) -> Dict[str, Any]:
        """
        Draft and persist a single candidate SKILL.md proposal with `approved=False`.
        Never writes to `self.skills_dir`.
        """
        technique = _sanitize_text(evidence.get("technique") or evidence.get("skill_id") or "learned-pattern")
        base_slug = _normalize_skill_id(evidence.get("skill_id") or technique)
        # Avoid colliding with built-in core skills
        skill_id = f"learned-{base_slug}" if base_slug in CORE_SKILLS else base_slug
        title = technique.replace("_", " ").replace("-", " ").title()

        outcomes = evidence.get("outcomes") or []
        tools_used = evidence.get("tools_observed") or []
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

        proposal_id = f"prop-{skill_id}-{uuid.uuid4().hex[:6]}"
        prop_dir = self.proposals_dir / proposal_id
        prop_dir.mkdir(parents=True, exist_ok=True)

        skill_md = self._render_skill_md(
            skill_id=skill_id,
            title=title,
            category=category,
            description=description,
            checklist=checklist,
            evidence=evidence,
        )
        skill_md_path = prop_dir / "SKILL.md"
        skill_md_path.write_text(skill_md, encoding="utf-8")

        proposal_meta: Dict[str, Any] = {
            "proposal_id": proposal_id,
            "skill_id": skill_id,
            "title": title,
            "category": category,
            "description": description,
            "approved": False,
            "status": "pending",
            "created_at": _now_iso(),
            "approved_at": None,
            "approved_by": None,
            "activated_path": None,
            "skill_md_path": str(skill_md_path),
            "source_evidence": {
                "technique": technique,
                "success_count": int(evidence.get("success_count", 1)),
                "outcomes": outcomes,
                "contexts": evidence.get("contexts", []),
                "tools_observed": tools_used,
                "trace_span_ids": evidence.get("trace_span_ids", []),
            },
        }
        (prop_dir / "proposal.json").write_text(
            json.dumps(proposal_meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Drafted unapproved skill proposal %s -> %s", proposal_id, skill_md_path)
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

        skill_id = _normalize_skill_id(meta["skill_id"])
        if skill_id in CORE_SKILLS:
            raise ValueError(f"Refusing to overwrite built-in core skill '{skill_id}'")

        prop_dir = self.proposals_dir / meta["proposal_id"]
        skill_md_path = prop_dir / "SKILL.md"
        if not skill_md_path.is_file():
            raise FileNotFoundError(f"Proposal SKILL.md missing: {skill_md_path}")

        meta["approved"] = True
        meta["status"] = "approved"
        meta["approved_by"] = approved_by
        meta["approved_at"] = _now_iso()

        if activate:
            registry = SkillRegistry(skills_dir=self.skills_dir)
            dest_dir = registry.skills_dir / skill_id
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_skill_md = dest_dir / "SKILL.md"
            dest_skill_md.write_text(skill_md_path.read_text(encoding="utf-8"), encoding="utf-8")
            manifest = {
                "id": skill_id,
                "title": meta.get("title", skill_id),
                "category": meta.get("category", "Learned Security Pattern"),
                "description": meta.get("description", ""),
                "is_custom": True,
                "approved_by": approved_by,
                "learned_from_proposal": meta["proposal_id"],
                "activated_at": meta["approved_at"],
            }
            (dest_dir / "manifest.json").write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            meta["activated_path"] = str(dest_dir)

        (prop_dir / "proposal.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Approved skill proposal %s (activated=%s)", proposal_id, activate)
        return meta

    def reject_proposal(self, proposal_id: str, reason: str = "") -> Dict[str, Any]:
        """Reject a skill proposal so it remains inactive."""
        meta = self.get_proposal(proposal_id)
        if not meta:
            raise KeyError(f"Skill proposal not found: {proposal_id}")
        meta["approved"] = False
        meta["status"] = "rejected"
        meta["rejection_reason"] = reason
        meta["rejected_at"] = _now_iso()
        prop_dir = self.proposals_dir / meta["proposal_id"]
        (prop_dir / "proposal.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return meta
