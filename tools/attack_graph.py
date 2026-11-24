#!/usr/bin/env python3
"""
attack_graph.py — Directed Attack Graph & Surface Path Modeler for Moros AI.

Constructs comprehensive attack path graphs linking Assets, Services,
Endpoints, Parameters, and Vulnerability Sinks for visual situational awareness.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Set


class AttackGraphBuilder:
    """Builds and serializes directed attack surface graphs."""

    def __init__(self, target: str, target_dir: Path):
        self.target = target
        self.target_dir = Path(target_dir)
        self.output_dir = self.target_dir / "output"
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, str]] = []
        self._seen_nodes: Set[str] = set()

    def add_node(self, node_id: str, label: str, node_type: str, metadata: Dict[str, Any] = None):
        if node_id not in self._seen_nodes:
            self._seen_nodes.add(node_id)
            self.nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {},
            })

    def add_edge(self, source: str, target: str, relation: str):
        self.edges.append({
            "source": source,
            "target": target,
            "relation": relation,
        })

    def build_graph(self) -> Dict[str, Any]:
        """Synthesize discovery artifacts and findings into a coherent attack graph."""
        # 1. Root Target Node
        root_id = f"target:{self.target}"
        self.add_node(root_id, self.target, "root_domain")

        # 2. Subdomains
        sub_file = self.output_dir / "recon" / "subdomains.txt"
        if sub_file.is_file():
            try:
                for line in sub_file.read_text(encoding="utf-8").splitlines():
                    sub = line.strip()
                    if sub:
                        sub_id = f"sub:{sub}"
                        self.add_node(sub_id, sub, "subdomain")
                        self.add_edge(root_id, sub_id, "HOSTS")
            except Exception:
                pass

        # 3. Discovered Endpoints
        for ep_file_rel in ["recon/endpoints.txt", "content/discovered-endpoints.txt", "api/openapi-endpoints.json"]:
            ep_file = self.output_dir / ep_file_rel
            if ep_file.is_file():
                try:
                    if ep_file.suffix == ".json":
                        raw_data = json.loads(ep_file.read_text(encoding="utf-8"))
                        eps = [str(item.get("path", item)) for item in raw_data] if isinstance(raw_data, list) else list(raw_data.keys())
                    else:
                        eps = [l.strip() for l in ep_file.read_text(encoding="utf-8").splitlines() if l.strip()]

                    for ep in eps[:30]:  # Cap for clean visualization
                        ep_id = f"ep:{ep[:50]}"
                        self.add_node(ep_id, ep[:40], "endpoint")
                        self.add_edge(root_id, ep_id, "EXPOSES")
                except Exception:
                    pass

        # 4. Findings & Vulnerability Sinks
        findings_dir = self.output_dir / "findings"
        if findings_dir.is_dir():
            for f_file in findings_dir.rglob("candidates-*.json"):
                try:
                    data = json.loads(f_file.read_text(encoding="utf-8"))
                    findings = data if isinstance(data, list) else data.get("findings", [])
                    for f in findings:
                        f_id = f"vuln:{f.get('title', 'finding')[:40]}"
                        self.add_node(
                            f_id,
                            f.get("title", "Vulnerability")[:40],
                            "vulnerability",
                            {"severity": f.get("severity", "MEDIUM"), "cwe": f.get("cwe", "CWE-200")}
                        )
                        affected_url = f.get("url", "")
                        source_id = f"ep:{affected_url[:50]}" if affected_url else root_id
                        if source_id not in self._seen_nodes:
                            self.add_node(source_id, affected_url[:40] or self.target, "endpoint")
                        self.add_edge(source_id, f_id, "VULNERABLE_TO")
                except Exception:
                    pass

        # Export to JSON
        graph_data = {
            "target": self.target,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": self.nodes,
            "edges": self.edges,
            "mermaid": self.to_mermaid(),
        }

        report_dir = self.output_dir / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "attack-graph.json").write_text(json.dumps(graph_data, indent=2), encoding="utf-8")
        return graph_data

    def to_mermaid(self) -> str:
        """Render graph into Mermaid diagram syntax."""
        lines = ["graph TD"]
        for node in self.nodes[:40]:  # Limit size for rendering readability
            safe_label = node["label"].replace('"', "'")
            lines.append(f'    {node["id"].replace(":", "_").replace("-", "_")}["{safe_label}"]')
        for edge in self.edges[:40]:
            s = edge["source"].replace(":", "_").replace("-", "_")
            t = edge["target"].replace(":", "_").replace("-", "_")
            lines.append(f'    {s} -->|{edge["relation"]}| {t}')
        return "\n".join(lines)
