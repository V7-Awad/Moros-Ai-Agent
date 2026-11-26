#!/usr/bin/env python3
"""
attack_graph.py — Directed Attack Graph & Surface Path Modeler for Moros AI.

Constructs comprehensive attack path graphs linking Assets, Services,
Endpoints, Parameters, Identities, Evidence, and Vulnerability Findings,
integrating Phase 2 AttackChainEngine correlation and scoring.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

try:
    from tools.attack_chain import AttackChainEngine, load_target_artifacts
except ImportError:
    from attack_chain import AttackChainEngine, load_target_artifacts


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mermaid_safe_id(node_id: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", node_id)


def _mermaid_safe_label(text: str, max_len: int = 48) -> str:
    clean = re.sub(r"[\r\n\t]+", " ", str(text or "")).strip()
    clean = clean.replace('"', "'").replace("[", "(").replace("]", ")")
    if len(clean) > max_len:
        clean = clean[: max_len - 3] + "..."
    return clean or "node"


class AttackGraphBuilder:
    """Builds and serializes directed attack surface graphs with correlated attack chains."""

    def __init__(self, target: str, target_dir: Path):
        self.target = target
        self.target_dir = Path(target_dir)
        self.output_dir = self.target_dir / "output"
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self._seen_nodes: Set[str] = set()
        self._seen_edges: Set[Tuple[str, str, str]] = set()

    def add_node(self, node_id: str, label: str, node_type: str, metadata: Dict[str, Any] = None):
        if node_id not in self._seen_nodes:
            self._seen_nodes.add(node_id)
            self.nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {},
            })

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        evidence_ids: Optional[Sequence[str]] = None,
        confidence: float = 0.7,
        verified: bool = True,
        inferred: Optional[bool] = None,
        explanation: str = "",
        created_at: Optional[str] = None,
        source_component: str = "AttackGraphBuilder",
    ):
        is_verified = bool(verified)
        is_inferred = (not is_verified) if inferred is None else bool(inferred)
        if is_verified and is_inferred:
            is_inferred = False
        edge_key = (source, target, relation)
        if edge_key in self._seen_edges:
            return
        self._seen_edges.add(edge_key)
        self.edges.append({
            "source": source,
            "target": target,
            "relation": relation,
            "evidence_ids": list(evidence_ids or []),
            "confidence": round(max(0.0, min(1.0, float(confidence))), 4),
            "verified": is_verified,
            "inferred": is_inferred,
            "explanation": explanation or f"{source} {relation} {target}",
            "created_at": created_at or _utc_now(),
            "source_component": source_component,
        })

    def build_graph(self) -> Dict[str, Any]:
        """Synthesize SkillRunner + legacy discovery artifacts, findings, and attack chains."""
        self.nodes = []
        self.edges = []
        self._seen_nodes = set()
        self._seen_edges = set()

        artifacts = load_target_artifacts(self.target_dir)

        # 1. Root Target Node
        root_id = f"target:{self.target}"
        self.add_node(root_id, self.target, "root_domain")

        # 2. Subdomains (recon/subdomains-all.txt + legacy recon/subdomains.txt + passive)
        for sub in artifacts["subdomains"]:
            sub_id = f"sub:{sub}"
            self.add_node(sub_id, sub, "subdomain")
            self.add_edge(
                root_id,
                sub_id,
                "HOSTS",
                confidence=0.95,
                verified=True,
                inferred=False,
                explanation=f"Discovered subdomain {sub} under {self.target}",
            )

        # 3. Discovered Endpoints & JS Parameters
        #    (js/endpoints.json, js/parameters.json, api/endpoints.json,
        #     api/openapi-endpoints.json, recon/endpoints.txt, content/discovered-endpoints.txt)
        param_map: Dict[str, List[str]] = {}
        for p in artifacts["parameters"]:
            pname = str(p.get("name", "")).strip()
            if not pname:
                continue
            for ep_ref in p.get("found_in_endpoints", []) or []:
                param_map.setdefault(str(ep_ref), []).append(pname)

        for ep in artifacts["endpoints"][:60]:
            ep_url = str(ep.get("url", "")).strip()
            if not ep_url:
                continue
            ep_id = f"ep:{ep_url[:80]}"
            ep_params = list(ep.get("parameters", []) or [])
            for pname in param_map.get(ep_url, []):
                if pname not in ep_params:
                    ep_params.append(pname)
            self.add_node(
                ep_id,
                ep_url[:50],
                "endpoint",
                {
                    "method": ep.get("method", "GET"),
                    "parameters": ep_params,
                    "source": ep.get("source", ""),
                },
            )
            self.add_edge(
                root_id,
                ep_id,
                "EXPOSES",
                confidence=0.9,
                verified=True,
                inferred=False,
                explanation=f"Discovered endpoint {ep_url}",
            )

        # 4. Findings & Vulnerability Sinks
        for f in artifacts["findings"]:
            title = str(f.get("title", "Vulnerability"))
            f_id = f"vuln:{title[:50]}"
            is_confirmed = str(f.get("status", "")).lower() in {"confirmed", "validated"} or str(
                f.get("validation_status", "")
            ).lower() in {"confirmed", "validated"}
            ev_ids = list(f.get("evidence_ids", []) or []) if isinstance(f.get("evidence_ids"), list) else []
            self.add_node(
                f_id,
                title[:40],
                "vulnerability",
                {
                    "severity": f.get("severity", "MEDIUM"),
                    "cwe": f.get("cwe", "CWE-200"),
                    "status": f.get("status", "candidate"),
                    "evidence_ids": ev_ids,
                },
            )
            affected_url = str(f.get("url", f.get("endpoint", ""))).strip()
            source_id = f"ep:{affected_url[:80]}" if affected_url else root_id
            if source_id not in self._seen_nodes:
                self.add_node(source_id, affected_url[:50] or self.target, "endpoint")
            self.add_edge(
                source_id,
                f_id,
                "VULNERABLE_TO",
                evidence_ids=ev_ids,
                confidence=0.9 if is_confirmed else 0.55,
                verified=is_confirmed and bool(ev_ids),
                explanation=f"Endpoint {affected_url or self.target} linked to finding '{title}'",
            )

        # 5. Phase 2 Correlated Attack Chain Engine
        engine = AttackChainEngine(self.target)
        chain_report = engine.build_from_inputs(
            findings=artifacts["findings"],
            assets=artifacts["subdomains"],
            endpoints=artifacts["endpoints"],
            parameters=artifacts["parameters"],
            evidence_records=artifacts["evidence_records"],
        )

        # Merge enriched attack-chain nodes & typed correlation edges without duplicating surface nodes
        for node in chain_report["graph"]["nodes"]:
            self.add_node(node["id"], node["label"], node["type"], node.get("metadata"))
        for edge in chain_report["graph"]["edges"]:
            self.add_edge(
                source=edge["source"],
                target=edge["target"],
                relation=edge["relation"],
                evidence_ids=edge.get("evidence_ids"),
                confidence=edge.get("confidence", 0.5),
                verified=edge.get("verified", False),
                inferred=edge.get("inferred"),
                explanation=edge.get("explanation", ""),
                created_at=edge.get("created_at"),
                source_component=edge.get("source_component", "AttackChainEngine"),
            )

        graph_data = {
            "target": self.target,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": self.nodes,
            "edges": self.edges,
            "attack_chains": chain_report["attack_chains"],
            "chain_summary": chain_report["chain_summary"],
            "trust_boundaries": chain_report["graph"].get("trust_boundaries", []),
            "chain_mermaid": chain_report["mermaid"],
            "mermaid": self.to_mermaid(),
        }

        report_dir = self.output_dir / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "attack-graph.json").write_text(json.dumps(graph_data, indent=2), encoding="utf-8")
        engine.export_report(report_dir / "attack-chains.json", chain_report)
        return graph_data

    def to_mermaid(self) -> str:
        """Render graph into Mermaid diagram syntax, distinguishing verified vs inferred edges."""
        lines = ["graph TD"]
        included: Set[str] = set()
        for node in self.nodes[:50]:
            included.add(node["id"])
            safe_id = _mermaid_safe_id(node["id"])
            safe_label = _mermaid_safe_label(node["label"])
            lines.append(f'    {safe_id}["{safe_label}"]')

        emitted = 0
        for edge in self.edges:
            if emitted >= 60:
                break
            if edge["source"] not in included or edge["target"] not in included:
                continue
            s = _mermaid_safe_id(edge["source"])
            t = _mermaid_safe_id(edge["target"])
            rel = _mermaid_safe_label(edge["relation"], max_len=32)
            if edge.get("verified", True):
                lines.append(f"    {s} -->|{rel}| {t}")
            else:
                lines.append(f"    {s} -.->|{rel} [inferred]| {t}")
            emitted += 1
        return "\n".join(lines)
