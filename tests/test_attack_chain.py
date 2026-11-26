import json
from pathlib import Path

from tools.attack_chain import (
    NODE_TYPES,
    AttackChainEngine,
    AttackPathAnalyzer,
    AttackPathScorer,
    FindingRelationshipGraph,
)
from tools.attack_graph import AttackGraphBuilder


REQUIRED_EDGE_KEYS = {
    "source",
    "target",
    "relation",
    "evidence_ids",
    "confidence",
    "verified",
    "inferred",
    "explanation",
    "created_at",
    "source_component",
}


def _assert_valid_edge_schema(edge: dict) -> None:
    assert REQUIRED_EDGE_KEYS.issubset(edge.keys())
    assert isinstance(edge["evidence_ids"], list)
    assert isinstance(edge["confidence"], float)
    assert 0.0 <= edge["confidence"] <= 1.0
    assert isinstance(edge["verified"], bool)
    assert isinstance(edge["inferred"], bool)
    assert edge["verified"] != edge["inferred"] or (not edge["verified"] and edge["inferred"])
    assert isinstance(edge["explanation"], str) and edge["explanation"]
    assert isinstance(edge["created_at"], str) and edge["created_at"]
    assert isinstance(edge["source_component"], str) and edge["source_component"]


def test_known_verified_multistep_attack_chain_in_controlled_lab():
    findings = [
        {
            "finding_id": "f-secret-1",
            "title": "Exposed JWT Signing Secret in Client Bundle",
            "type": "Secret Exposure",
            "cwe": "CWE-798",
            "url": "https://app.lab.local/static/app.js",
            "severity": "MEDIUM",
            "status": "confirmed",
            "validation_status": "confirmed",
            "confidence": 0.95,
            "evidence_ids": ["ev-secret-001"],
            "remediation": "Remove signing secret from client bundle and rotate keys.",
            "metadata": {"applies_to_hosts": ["api.lab.local"]},
        },
        {
            "finding_id": "f-auth-2",
            "title": "JWT Authentication Bypass via Forged Token",
            "type": "Auth Bypass",
            "cwe": "CWE-287",
            "url": "https://api.lab.local/api/v1/auth/session",
            "severity": "HIGH",
            "status": "confirmed",
            "validation_status": "validated",
            "confidence": 0.92,
            "evidence_ids": ["ev-auth-002"],
            "identity": "authenticated_user",
        },
        {
            "finding_id": "f-idor-3",
            "title": "IDOR on User Account Export",
            "type": "IDOR",
            "cwe": "CWE-639",
            "url": "https://api.lab.local/api/v1/users/export?user_id=42",
            "parameter": "user_id",
            "severity": "HIGH",
            "status": "confirmed",
            "confidence": 0.90,
            "evidence_ids": ["ev-idor-003"],
            "identity": "authenticated_user",
        },
    ]

    engine = AttackChainEngine(target="lab.local")
    report = engine.build_from_inputs(
        findings=findings,
        assets=["app.lab.local", "api.lab.local"],
        trust_boundaries=[{"name": "external_internet"}, {"name": "authenticated_user"}],
    )

    graph = report["graph"]
    node_types = {n["type"] for n in graph["nodes"]}
    assert node_types.issubset(set(NODE_TYPES))
    assert {"asset", "endpoint", "identity", "finding", "evidence", "attack_step", "remediation"}.issubset(node_types)

    for edge in graph["edges"]:
        _assert_valid_edge_schema(edge)

    chains = report["attack_chains"]
    assert len(chains) >= 1
    top = chains[0]
    assert top["step_count"] == 3
    assert [s["finding_id"] for s in top["steps"]] == ["f-secret-1", "f-auth-2", "f-idor-3"]
    assert top["verified"] is True
    assert top["inferred"] is False
    assert top["missing_prerequisites"] == []
    assert all(e["verified"] is True and e["inferred"] is False for e in top["edges"])
    assert report["chain_summary"]["verified_chains"] >= 1
    assert report["chain_summary"]["max_path_risk_score"] >= 7.0


def test_open_redirect_to_oauth_token_theft_and_cors_data_exfil():
    findings = [
        {
            "finding_id": "f-redir",
            "title": "Open Redirect on Login Callback",
            "type": "Open Redirect",
            "cwe": "CWE-601",
            "url": "https://auth.lab.local/login?next=https://example.net",
            "parameter": "next",
            "severity": "LOW",
            "status": "confirmed",
            "evidence_ids": ["ev-redir-1"],
        },
        {
            "finding_id": "f-oauth",
            "title": "OAuth Token Theft via Permissive Redirect URI",
            "type": "OAuth Token Theft",
            "url": "https://auth.lab.local/oauth/authorize?redirect_uri=https://auth.lab.local/login",
            "parameter": "redirect_uri",
            "severity": "HIGH",
            "status": "confirmed",
            "evidence_ids": ["ev-oauth-2"],
        },
        {
            "finding_id": "f-cors",
            "title": "Permissive CORS Origin Reflection",
            "type": "CORS Misconfiguration",
            "cwe": "CWE-942",
            "url": "https://api.lab.local/api/profile",
            "severity": "MEDIUM",
            "status": "confirmed",
            "evidence_ids": ["ev-cors-3"],
            "notes": "Response includes Access-Control-Allow-Credentials: true for reflected Origin",
        },
        {
            "finding_id": "f-exfil",
            "title": "Sensitive Profile Data Exposure",
            "type": "Data Exfil",
            "primitive": "data_exfil",
            "url": "https://api.lab.local/api/profile",
            "severity": "HIGH",
            "status": "confirmed",
            "evidence_ids": ["ev-exfil-4"],
        },
    ]

    report = AttackChainEngine("lab.local").build_from_inputs(findings=findings)
    chain_names = [c["name"] for c in report["attack_chains"]]
    assert any("Open Redirect on Login Callback -> OAuth Token Theft" in name for name in chain_names)
    assert any("Permissive CORS Origin Reflection -> Sensitive Profile Data Exposure" in name for name in chain_names)


def test_unrelated_findings_must_not_be_connected():
    findings = [
        {
            "finding_id": "f-unrel-1",
            "title": "Potential Vulnerability in Search Module",
            "type": "Reflected XSS",
            "cwe": "CWE-79",
            "url": "https://alpha.example.com/search?q=test",
            "parameter": "q",
            "severity": "MEDIUM",
            "status": "confirmed",
            "evidence_ids": ["ev-1"],
        },
        {
            "finding_id": "f-unrel-2",
            "title": "Potential Vulnerability in Search Module",
            "type": "Reflected XSS",
            "cwe": "CWE-79",
            "url": "https://beta.othercorp.org/feedback?msg=hello",
            "parameter": "msg",
            "severity": "MEDIUM",
            "status": "confirmed",
            "evidence_ids": ["ev-2"],
        },
        {
            "finding_id": "f-unrel-3",
            "title": "IDOR in Orders",
            "type": "IDOR",
            "cwe": "CWE-639",
            "url": "https://gamma.thirdparty.net/orders/1",
            "severity": "HIGH",
            "status": "confirmed",
            "evidence_ids": ["ev-3"],
        },
    ]

    report = AttackChainEngine("alpha.example.com").build_from_inputs(findings=findings)
    assert report["attack_chains"] == []
    assert report["chain_summary"]["total_chains"] == 0
    assert report["chain_summary"]["uncorrelated_findings"] == 3

    # Also verify two findings on the SAME host with matching title/category (XSS + XSS) do not self-chain
    same_host_unrelated = [
        findings[0],
        {
            "finding_id": "f-samehost-xss2",
            "title": "Potential Vulnerability in Search Module",
            "type": "Reflected XSS",
            "cwe": "CWE-79",
            "url": "https://alpha.example.com/comments?text=hi",
            "parameter": "text",
            "severity": "MEDIUM",
            "status": "confirmed",
            "evidence_ids": ["ev-4"],
        },
    ]
    report_same = AttackChainEngine("alpha.example.com").build_from_inputs(findings=same_host_unrelated)
    assert report_same["attack_chains"] == []


def test_inferred_edge_and_missing_prerequisites_uncertainty_reporting():
    findings = [
        {
            "finding_id": "f-xss-verified",
            "title": "Stored XSS in Profile Bio",
            "type": "XSS",
            "cwe": "CWE-79",
            "url": "https://portal.lab.local/profile",
            "severity": "MEDIUM",
            "status": "confirmed",
            "evidence_ids": ["ev-xss-100"],
        },
        {
            "finding_id": "f-admin-cand",
            "title": "Admin Panel Session Takeover",
            "type": "Admin Access",
            "primitive": "admin_access",
            "url": "https://admin.lab.local/admin/users",
            "severity": "CRITICAL",
            "status": "candidate",
            "validation_status": "unverified",
            # Deliberately missing evidence_ids + unconfirmed + cross-subdomain
        },
        {
            "finding_id": "f-cors-nocreds",
            "title": "Wildcard CORS Header on Billing API",
            "type": "CORS",
            "cwe": "CWE-942",
            "url": "https://billing.lab.local/api/invoices",
            "severity": "LOW",
            "status": "confirmed",
            "evidence_ids": ["ev-cors-200"],
            # Deliberately omits allow_credentials=True
        },
        {
            "finding_id": "f-billing-exfil",
            "title": "Invoice Data Exfiltration",
            "type": "Data Exfil",
            "primitive": "data_exfil",
            "url": "https://billing.lab.local/api/invoices",
            "severity": "HIGH",
            "status": "confirmed",
            "evidence_ids": ["ev-inv-201"],
        },
    ]

    report = AttackChainEngine("lab.local").build_from_inputs(findings=findings)
    chains = report["attack_chains"]
    assert len(chains) == 2

    xss_chain = next(c for c in chains if "Stored XSS" in c["name"])
    assert xss_chain["verified"] is False
    assert xss_chain["inferred"] is True
    assert xss_chain["edges"][0]["inferred"] is True
    assert xss_chain["edges"][0]["verified"] is False
    assert any("unverified" in u.lower() or "candidate" in m.lower() for u, m in zip(xss_chain["uncertainty"], xss_chain["missing_prerequisites"]))
    assert any("evidence_ids" in m for m in xss_chain["missing_prerequisites"])
    assert any("cross-host" in u.lower() for u in xss_chain["uncertainty"])

    cors_chain = next(c for c in chains if "Wildcard CORS" in c["name"])
    assert cors_chain["verified"] is False
    assert cors_chain["inferred"] is True
    assert any("Access-Control-Allow-Credentials" in m for m in cors_chain["missing_prerequisites"])
    assert any("allow-credentials" in u.lower() for u in cors_chain["uncertainty"])


def test_duplicate_finding_handling_collapses_and_merges_evidence():
    findings = [
        {
            "finding_id": "f-dup-a",
            "title": "IDOR on User Profile",
            "type": "IDOR",
            "url": "https://api.lab.local/api/users/1",
            "parameter": "id",
            "severity": "HIGH",
            "status": "candidate",
            "evidence_ids": ["ev-dup-1"],
        },
        {
            "finding_id": "f-dup-b",
            "title": "IDOR on User Profile",
            "type": "IDOR",
            "url": "https://api.lab.local/api/users/1",
            "parameter": "id",
            "severity": "HIGH",
            "status": "confirmed",
            "evidence_ids": ["ev-dup-2"],
        },
        {
            "finding_id": "f-auth",
            "title": "Auth Bypass on API Gateway",
            "type": "Auth Bypass",
            "url": "https://api.lab.local/api/login",
            "severity": "HIGH",
            "status": "confirmed",
            "evidence_ids": ["ev-auth-1"],
        },
    ]

    graph = FindingRelationshipGraph("lab.local")
    ingested_ids = graph.ingest_findings(findings)
    assert len(ingested_ids) == 2
    assert graph.duplicate_findings_collapsed == 1

    finding_nodes = [n for n in graph.nodes if n["type"] == "finding"]
    assert len(finding_nodes) == 2
    idor_node = next(n for n in finding_nodes if "IDOR" in n["label"])
    assert idor_node["metadata"]["confirmed"] is True
    assert sorted(idor_node["metadata"]["evidence_ids"]) == ["ev-dup-1", "ev-dup-2"]


def test_finding_severity_kept_separate_from_path_risk_score():
    f1 = {
        "finding_id": "f-low-redir",
        "title": "Open Redirect in Auth Portal",
        "type": "Open Redirect",
        "cwe": "CWE-601",
        "url": "https://auth.lab.local/redirect?next=https://x.test",
        "parameter": "next",
        "severity": "LOW",
        "status": "confirmed",
        "confidence": 0.95,
        "evidence_ids": ["ev-10"],
    }
    f2 = {
        "finding_id": "f-med-oauth",
        "title": "OAuth Token Leakage via Redirect",
        "type": "OAuth Token Theft",
        "url": "https://auth.lab.local/oauth/callback",
        "severity": "MEDIUM",
        "status": "confirmed",
        "confidence": 0.92,
        "evidence_ids": ["ev-11"],
    }
    f3 = {
        "finding_id": "f-med-admin",
        "title": "Admin Console Access via Stolen Token",
        "type": "Admin Access",
        "primitive": "admin_access",
        "url": "https://auth.lab.local/admin/dashboard",
        "severity": "MEDIUM",
        "status": "confirmed",
        "confidence": 0.90,
        "evidence_ids": ["ev-12"],
    }

    report = AttackChainEngine("lab.local").build_from_inputs(findings=[f1, f2, f3])
    # Caller dicts must never be mutated
    assert f1["severity"] == "LOW"
    assert f2["severity"] == "MEDIUM"
    assert f3["severity"] == "MEDIUM"

    top = report["attack_chains"][0]
    assert top["path_risk_score"] >= 8.5
    assert top["path_severity"] in {"HIGH", "CRITICAL"}
    assert top["original_finding_severities"] == {
        "f-low-redir": "LOW",
        "f-med-oauth": "MEDIUM",
        "f-med-admin": "MEDIUM",
    }
    for step in top["steps"]:
        assert step["original_severity"] in {"LOW", "MEDIUM"}


def test_inactive_findings_are_excluded_from_active_chains():
    findings = [
        {
            "finding_id": "f-fp",
            "title": "False Positive Secret Leak",
            "type": "Secret Exposure",
            "url": "https://app.lab.local/app.js",
            "status": "false_positive",
            "evidence_ids": ["ev-fp"],
        },
        {
            "finding_id": "f-fixed",
            "title": "Fixed Auth Bypass",
            "type": "Auth Bypass",
            "url": "https://app.lab.local/login",
            "status": "fixed",
            "evidence_ids": ["ev-fix"],
        },
    ]
    report = AttackChainEngine("lab.local").build_from_inputs(findings=findings)
    assert report["attack_chains"] == []


def test_serialization_mermaid_and_attack_graph_builder_phase0_paths(tmp_path):
    target_dir = tmp_path / "targets" / "shop.local"
    out = target_dir / "output"
    (out / "recon").mkdir(parents=True)
    (out / "js").mkdir(parents=True)
    (out / "api").mkdir(parents=True)
    (out / "findings" / "xss-stored").mkdir(parents=True)
    (out / "findings" / "auth").mkdir(parents=True)
    (out / "evidence").mkdir(parents=True)

    # Actual SkillRunner artifact paths
    (out / "recon" / "subdomains-all.txt").write_text("api.shop.local\nadmin.shop.local\n", encoding="utf-8")
    (out / "js" / "endpoints.json").write_text(json.dumps({
        "total_endpoints": 2,
        "endpoints": [
            {"url": "https://api.shop.local/api/profile", "method": "GET", "parameters": ["bio"]},
            {"url": "https://api.shop.local/admin/settings", "method": "POST", "parameters": ["role"]},
        ],
    }), encoding="utf-8")
    (out / "js" / "parameters.json").write_text(json.dumps({
        "total_parameters": 2,
        "parameters": [
            {"name": "bio", "found_in_endpoints": ["https://api.shop.local/api/profile"]},
            {"name": "role", "found_in_endpoints": ["https://api.shop.local/admin/settings"]},
        ],
    }), encoding="utf-8")
    (out / "api" / "endpoints.json").write_text(json.dumps({
        "total_endpoints": 1,
        "endpoints": [
            {"base_url": "https://api.shop.local", "path": "/api/v2/export", "method": "GET", "parameters": [{"name": "format"}]},
        ],
    }), encoding="utf-8")
    (out / "evidence" / "ledger.jsonl").write_text(
        json.dumps({"evidence_id": "ev-xss-1", "verification_status": "confirmed"}) + "\n",
        encoding="utf-8",
    )
    (out / "findings" / "xss-stored" / "confirmed-xss.json").write_text(json.dumps({
        "findings": [
            {
                "finding_id": "xss-1",
                "title": "Stored XSS in Profile Bio",
                "type": "XSS",
                "url": "https://api.shop.local/api/profile",
                "parameter": "bio",
                "severity": "MEDIUM",
                "status": "confirmed",
                "evidence_ids": ["ev-xss-1"],
            }
        ]
    }), encoding="utf-8")
    (out / "findings" / "auth" / "candidates-admin.json").write_text(json.dumps({
        "findings": [
            {
                "finding_id": "admin-2",
                "title": "Admin Settings Hijack",
                "type": "Admin Access",
                "primitive": "admin_access",
                "url": "https://api.shop.local/admin/settings",
                "severity": "HIGH",
                "status": "candidate",
            }
        ]
    }), encoding="utf-8")

    builder = AttackGraphBuilder("shop.local", target_dir)
    graph = builder.build_graph()

    # Backward-compatible top-level keys
    for key in ("target", "total_nodes", "total_edges", "nodes", "edges", "mermaid"):
        assert key in graph
    assert graph["target"] == "shop.local"
    assert graph["total_nodes"] >= 6
    assert graph["total_edges"] >= 5

    # Verify Phase 0 path fixes picked up subdomains-all.txt, js/endpoints.json, api/endpoints.json
    node_labels = " ".join(n["label"] for n in graph["nodes"])
    assert "api.shop.local" in node_labels
    assert "/api/v2/export" in node_labels
    assert "/api/profile" in node_labels

    # Verify AttackChainEngine integration + Mermaid verified/inferred markers
    assert "attack_chains" in graph and len(graph["attack_chains"]) == 1
    assert "chain_summary" in graph
    assert graph["chain_summary"]["inferred_chains"] == 1
    assert "graph TD" in graph["mermaid"]
    assert "-.->" in graph["mermaid"]

    for edge in graph["edges"]:
        _assert_valid_edge_schema(edge)

    graph_file = out / "report" / "attack-graph.json"
    chains_file = out / "report" / "attack-chains.json"
    assert graph_file.is_file()
    assert chains_file.is_file()
    parsed_chains = json.loads(chains_file.read_text(encoding="utf-8"))
    assert parsed_chains["target"] == "shop.local"
    assert len(parsed_chains["attack_chains"]) == 1
