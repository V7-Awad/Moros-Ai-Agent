import io
import json
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dashboard import server
from tools.exploit_validator import ProofRecorder, ValidationResult
from tools.retest_engine import RetestResult
from tools.skill_learner import SkillLearner


def _http_handler(method="GET", path="/", body=None, headers=None, client_ip="127.0.0.1", srv=None):
    handler = server.DashboardHandler.__new__(server.DashboardHandler)
    raw_headers = {"Host": "127.0.0.1:8080"}
    if headers:
        raw_headers.update(headers)
    body_bytes = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode("utf-8"))
    if body is not None and "Content-Length" not in raw_headers:
        raw_headers["Content-Length"] = str(len(body_bytes))
    handler.command = method
    handler.path = path
    handler.headers = raw_headers
    handler.client_address = (client_ip, 54321)
    handler.server = srv
    handler.rfile = io.BytesIO(body_bytes)
    handler.wfile = io.BytesIO()
    handler._status_code = None
    handler._resp_headers = []

    def send_response(code, message=None):
        handler._status_code = code

    def send_header(k, v):
        handler._resp_headers.append((k, v))

    def end_headers():
        pass

    handler.send_response = send_response
    handler.send_header = send_header
    handler.end_headers = end_headers
    return handler


def _response_json(handler):
    return json.loads(handler.wfile.getvalue().decode("utf-8"))


def _make_target(tmp_path, target_name="app.example.com"):
    target_dir = tmp_path / target_name
    (target_dir / "output" / "findings" / "xss").mkdir(parents=True)
    (target_dir / "output" / "report").mkdir(parents=True)
    (target_dir / "scope-of-work.md").write_text(
        f"# Scope\n## In Scope\n- `{target_name}`\n- `*.{target_name}`\n",
        encoding="utf-8",
    )
    return target_dir


class TestFindingLifecycleResolution:
    def test_recognizes_backed_additive_statuses_and_forces_unverified_to_candidate(self, tmp_path, monkeypatch):
        target_dir = _make_target(tmp_path)
        findings_file = target_dir / "output" / "findings" / "xss" / "validated-all.json"
        findings_file.write_text(
            json.dumps({
                "findings": [
                    {
                        "id": "f-unverified-claim",
                        "title": "Forged Confirmed Without Proof",
                        "type": "XSS",
                        "url": "https://app.example.com/forged",
                        "status": "confirmed",
                        "validation_status": "validated",
                    },
                    {
                        "id": "f-llm-only",
                        "title": "LLM Only Claim",
                        "type": "XSS",
                        "url": "https://app.example.com/llm",
                        "validation_result": {
                            "status": "confirmed",
                            "llm_only": True,
                            "deterministic": False,
                            "proof_artifact": "output/evidence/validation/v0.json",
                            "evidence_ids": ["ev-0"],
                        },
                    },
                    {
                        "id": "f-confirmed",
                        "title": "Confirmed Reflected XSS",
                        "type": "XSS",
                        "url": "https://app.example.com/search?q=1",
                        "validation_result": {
                            "status": "confirmed",
                            "proof_artifact": "output/evidence/validation/v1.json",
                            "evidence_ids": ["ev-1"],
                            "confidence": 0.95,
                        },
                    },
                    {
                        "id": "f-validating",
                        "title": "Validating SQLi",
                        "type": "SQLi",
                        "url": "https://app.example.com/items?id=1",
                        "validation_result": {"status": "validating"},
                    },
                    {
                        "id": "f-inconclusive",
                        "title": "Inconclusive SSRF",
                        "type": "SSRF",
                        "url": "https://app.example.com/fetch",
                        "validation_result": {"status": "inconclusive"},
                    },
                    {
                        "id": "f-false-pos",
                        "title": "False Positive XSS",
                        "type": "XSS",
                        "url": "https://app.example.com/fp",
                        "validation_result": {"status": "false_positive"},
                    },
                    {
                        "id": "f-fixed",
                        "title": "Fixed Open Redirect",
                        "type": "Open Redirect",
                        "url": "https://app.example.com/redir",
                        "validation_result": {
                            "status": "confirmed",
                            "proof_artifact": "output/evidence/validation/v2.json",
                            "evidence_ids": ["ev-2"],
                        },
                        "latest_retest": {
                            "retest_id": "rt-1",
                            "outcome": "fixed",
                            "retest_proof_artifact": "output/evidence/validation/v3.json",
                            "retest_evidence_id": "ev-3",
                        },
                    },
                    {
                        "id": "f-accepted",
                        "title": "Accepted Risk CORS",
                        "type": "CORS",
                        "url": "https://app.example.com/api",
                        "validation_record": {
                            "verified_by": "human:security-lead",
                            "outcome": "accepted_risk",
                            "method": "manual-review",
                            "evidence_ids": ["ev-4"],
                        },
                    },
                    {
                        "id": "f-validated-human",
                        "title": "Human Validated IDOR",
                        "type": "IDOR",
                        "url": "https://app.example.com/profile/1",
                        "validation_record": {
                            "verified_by": "human:operator",
                            "outcome": "reproduced",
                            "method": "curl-replay",
                            "evidence_ids": ["ev-5"],
                        },
                    },
                    {
                        "id": "f-human-reviewed",
                        "title": "Human Reviewed Info",
                        "type": "Info",
                        "url": "https://app.example.com/info",
                        "validation_record": {
                            "verified_by": "human:reviewer",
                            "outcome": "human_reviewed",
                            "notes": "Reviewed manually",
                        },
                    },
                ]
            }),
            encoding="utf-8",
        )
        monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
        handler = server.DashboardHandler.__new__(server.DashboardHandler)
        by_title = {f["title"]: f for f in handler.get_target_findings("app.example.com")}

        assert by_title["Forged Confirmed Without Proof"]["status"] == "candidate"
        assert by_title["Forged Confirmed Without Proof"]["validation_status"] == "unverified"
        assert by_title["LLM Only Claim"]["status"] == "candidate"
        assert by_title["LLM Only Claim"]["validation_status"] == "unverified"
        assert by_title["Confirmed Reflected XSS"]["status"] == "confirmed"
        assert by_title["Validating SQLi"]["status"] == "validating"
        assert by_title["Inconclusive SSRF"]["status"] == "inconclusive"
        assert by_title["False Positive XSS"]["status"] == "false_positive"
        assert by_title["Fixed Open Redirect"]["status"] == "fixed"
        assert by_title["Accepted Risk CORS"]["status"] == "accepted_risk"
        assert by_title["Human Validated IDOR"]["status"] == "validated"
        assert by_title["Human Reviewed Info"]["status"] == "human_reviewed"


class TestAttackGraphEndpoint:
    def test_get_attack_graph_returns_saved_and_generated_graph(self, tmp_path, monkeypatch):
        target_dir = _make_target(tmp_path)
        monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
        srv = types.SimpleNamespace(allow_remote=False, rate_limit_rpm=600)

        saved_payload = {
            "target": "app.example.com",
            "total_nodes": 2,
            "total_edges": 1,
            "nodes": [{"id": "n1", "label": "Secret Leak", "type": "finding"}],
            "edges": [{"source": "n1", "target": "n2", "relation": "ENABLES_AUTH_BYPASS", "verified": True}],
            "attack_chains": [{"chain_id": "chain-1", "name": "Secret -> Auth Bypass", "path_risk_score": 8.9, "path_severity": "HIGH", "verified": True, "steps": []}],
            "chain_summary": {"total_chains": 1, "verified_chains": 1, "inferred_chains": 0, "max_path_risk_score": 8.9, "max_path_severity": "HIGH"},
            "mermaid": "graph TD\n    n1 -->|ENABLES_AUTH_BYPASS| n2",
        }
        (target_dir / "output" / "report" / "attack-graph.json").write_text(
            json.dumps(saved_payload), encoding="utf-8"
        )

        h = _http_handler("GET", "/api/targets/app.example.com/attack-graph", srv=srv)
        h.do_GET()
        assert h._status_code == 200
        data = _response_json(h)
        assert data["total_nodes"] == 2
        assert len(data["attack_chains"]) == 1
        assert data["chain_summary"]["verified_chains"] == 1
        assert "ENABLES_AUTH_BYPASS" in data["mermaid"]

        # When attack-graph.json is absent, endpoint builds cleanly via AttackGraphBuilder
        (target_dir / "output" / "report" / "attack-graph.json").unlink()
        h2 = _http_handler("GET", "/api/targets/app.example.com/attack-graph", srv=srv)
        h2.do_GET()
        assert h2._status_code == 200
        built = _response_json(h2)
        assert "attack_chains" in built
        assert "chain_summary" in built
        assert "mermaid" in built
        assert built["mermaid"].startswith("graph TD")


class TestValidateRemediationRetestRollbackEndpoints:
    def test_validate_endpoint_non_destructive_and_respects_scope(self, tmp_path, monkeypatch):
        target_dir = _make_target(tmp_path)
        monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
        monkeypatch.delenv("MOROS_ALLOW_GATED_POST", raising=False)
        srv = types.SimpleNamespace(allow_remote=False, rate_limit_rpm=600)

        # Out-of-scope finding is rejected safely without confirming
        h_oos = _http_handler(
            "POST",
            "/api/targets/app.example.com/validate",
            body={"finding": {"title": "XSS", "type": "xss", "url": "https://evil.other.org/search?q=1"}},
            srv=srv,
        )
        h_oos.do_POST()
        assert h_oos._status_code == 200
        oos_data = _response_json(h_oos)
        assert oos_data["validation_result"]["status"] == "inconclusive"
        assert "Out-of-scope" in oos_data["validation_result"]["limitations"][0]

        # State-changing POST method is blocked by default (non-destructive)
        h_post_method = _http_handler(
            "POST",
            "/api/targets/app.example.com/validate",
            body={"finding": {"title": "XSS", "type": "xss", "method": "POST", "url": "https://app.example.com/submit"}},
            srv=srv,
        )
        h_post_method.do_POST()
        assert h_post_method._status_code == 200
        post_data = _response_json(h_post_method)
        assert post_data["validation_result"]["status"] == "inconclusive"
        assert "MOROS_ALLOW_GATED_POST" in post_data["validation_result"]["limitations"][0]

        # Successful validation via mocked ExploitValidator
        fake_res = ValidationResult(
            finding_id="fnd-123",
            validation_run_id="val-abc",
            target="app.example.com",
            endpoint="https://app.example.com/search?q=1",
            strategy="xss-reflected",
            status="confirmed",
            confidence=0.92,
            evidence_ids=["ev-123"],
            proof_artifact="output/evidence/validation/val-abc.json",
        )
        with patch("tools.exploit_validator.ExploitValidator.validate_finding", return_value=fake_res):
            h_ok = _http_handler(
                "POST",
                "/api/targets/app.example.com/validate",
                body={"finding": {"finding_id": "fnd-123", "title": "XSS", "url": "https://app.example.com/search?q=1"}},
                srv=srv,
            )
            h_ok.do_POST()
        assert h_ok._status_code == 200
        ok_data = _response_json(h_ok)
        assert ok_data["validation_result"]["status"] == "confirmed"
        assert ok_data["validation_result"]["proof_artifact"] == "output/evidence/validation/val-abc.json"

    def test_remediate_endpoint_refuses_unconfirmed_and_runs_isolated_for_confirmed(self, tmp_path, monkeypatch):
        target_dir = _make_target(tmp_path)
        repo_dir = tmp_path / "vuln_repo"
        (repo_dir / "tests").mkdir(parents=True)
        (repo_dir / "app.py").write_text(
            "import html\n\ndef render_greeting(name: str) -> str:\n    return f'<h1>Hello {name}</h1>'\n",
            encoding="utf-8",
        )
        (repo_dir / "tests" / "test_app.py").write_text(
            "from app import render_greeting\n\n"
            "def test_xss_escaped():\n"
            "    out = render_greeting('<script>alert(1)</script>')\n"
            "    assert '<script>' not in out\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
        srv = types.SimpleNamespace(allow_remote=False, rate_limit_rpm=600)

        # 1. Unconfirmed candidate finding MUST be refused when require_confirmed=True (default)
        h_unconf = _http_handler(
            "POST",
            "/api/targets/app.example.com/remediate",
            body={
                "repo_root": str(repo_dir),
                "finding": {
                    "finding_id": "fnd-cand",
                    "title": "Candidate XSS",
                    "type": "xss",
                    "affected_file": "app.py",
                    "status": "candidate",
                },
            },
            srv=srv,
        )
        h_unconf.do_POST()
        assert h_unconf._status_code == 400
        assert "unconfirmed" in _response_json(h_unconf)["error"].lower()

        # 2. Confirmed finding succeeds in isolated workspace, leaving repo_root untouched
        before_source = (repo_dir / "app.py").read_text(encoding="utf-8")
        h_conf = _http_handler(
            "POST",
            "/api/targets/app.example.com/remediate",
            body={
                "repo_root": str(repo_dir),
                "test_paths": ["tests/test_app.py"],
                "finding": {
                    "finding_id": "fnd-xss-1",
                    "title": "Reflected XSS in render_greeting",
                    "type": "xss",
                    "affected_file": "app.py",
                    "status": "confirmed",
                    "validation_result": {
                        "status": "confirmed",
                        "proof_artifact": "output/evidence/validation/val-1.json",
                        "evidence_ids": ["ev-1"],
                    },
                },
            },
            srv=srv,
        )
        h_conf.do_POST()
        assert h_conf._status_code == 200
        rem_data = _response_json(h_conf)
        report = rem_data["remediation_report"]
        assert report["finding_id"] == "fnd-xss-1"
        assert report["approval_status"] == "pending_approval"
        assert report["affected_file"] == "app.py"
        assert "html.escape" in report["patch_diff"]
        assert report["test_results"]["passed"] is True
        # Main repo must remain unmodified
        assert (repo_dir / "app.py").read_text(encoding="utf-8") == before_source

    def test_retest_endpoint_returns_retest_result_and_preserves_evidence(self, tmp_path, monkeypatch):
        target_dir = _make_target(tmp_path)
        monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
        srv = types.SimpleNamespace(allow_remote=False, rate_limit_rpm=600)

        finding = {
            "finding_id": "fnd-rt-1",
            "title": "Reflected XSS",
            "type": "xss",
            "url": "https://app.example.com/search?q=1",
            "status": "confirmed",
            "proof_artifact": "output/evidence/validation/val-orig.json",
            "evidence_ids": ["ev-orig"],
            "validation_result": {
                "status": "confirmed",
                "validation_run_id": "val-orig",
                "proof_artifact": "output/evidence/validation/val-orig.json",
                "evidence_ids": ["ev-orig"],
            },
        }
        fake_rt = RetestResult(
            retest_id="rt-123",
            plan_id="plan-123",
            finding_id="fnd-rt-1",
            target="app.example.com",
            endpoint="https://app.example.com/search?q=1",
            outcome="fixed",
            confidence=0.9,
            original_validation_run_id="val-orig",
            original_evidence_ids=["ev-orig"],
            original_proof_artifact="output/evidence/validation/val-orig.json",
            original_proof_sha256="a" * 64,
            retest_validation_run_id="val-rt-1",
            retest_proof_artifact="output/evidence/validation/val-rt-1.json",
            retest_evidence_ids=["ev-rt-1"],
            retest_artifact="output/evidence/retests/rt-123.json",
            retest_evidence_id="ev-rt-1",
        )

        with patch("tools.retest_engine.RetestEngine.retest_finding", return_value=fake_rt) as mock_rt:
            h = _http_handler(
                "POST",
                "/api/targets/app.example.com/retest",
                body={"finding": finding, "remediation_id": "rem-1"},
                srv=srv,
            )
            h.do_POST()
        assert h._status_code == 200
        mock_rt.assert_called_once()
        data = _response_json(h)
        assert data["retest_result"]["outcome"] == "fixed"
        assert data["retest_result"]["original_evidence_ids"] == ["ev-orig"]
        assert len(data["retest_result"]["limitations"]) >= 1

    def test_skill_proposals_rollback_disable_enable(self, tmp_path, monkeypatch):
        target_dir = _make_target(tmp_path)
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
        monkeypatch.setattr(server, "SKILLS_DIR", skills_dir)
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
        srv = types.SimpleNamespace(allow_remote=False, rate_limit_rpm=600)

        learner = SkillLearner(target_dir=target_dir, skills_dir=skills_dir)
        meta = learner.draft_proposal({
            "skill_id": "custom-idor-check",
            "title": "Custom IDOR Check",
            "description": "Check object ownership",
            "steps": ["Compare user A vs user B responses"],
            "source_runs": ["run-1"],
            "source_evidence_ids": ["ev-1"],
            "trace_span_ids": ["sp-1"],
        })
        pid = meta["proposal_id"]
        learner.approve_proposal(pid, approved_by="human:tester", activate=True)
        assert (skills_dir / "custom-idor-check" / "SKILL.md").is_file()

        # Disable
        h_dis = _http_handler(
            "POST",
            "/api/targets/app.example.com/skill-proposals/rollback",
            body={"proposal_id": pid, "action": "disable", "reason": "Noisy"},
            srv=srv,
        )
        h_dis.do_POST()
        assert h_dis._status_code == 200
        assert _response_json(h_dis)["proposal"]["status"] == "disabled"
        assert not (skills_dir / "custom-idor-check").exists()

        # Re-enable
        h_en = _http_handler(
            "POST",
            "/api/targets/app.example.com/skill-proposals/rollback",
            body={"proposal_id": pid, "action": "enable"},
            srv=srv,
        )
        h_en.do_POST()
        assert h_en._status_code == 200
        assert _response_json(h_en)["proposal"]["status"] == "approved"
        assert (skills_dir / "custom-idor-check" / "SKILL.md").is_file()

        # Rollback
        h_rb = _http_handler(
            "POST",
            "/api/targets/app.example.com/skill-proposals/rollback",
            body={"proposal_id": pid, "action": "rollback", "reason": "Revert"},
            srv=srv,
        )
        h_rb.do_POST()
        assert h_rb._status_code == 200
        rb_prop = _response_json(h_rb)["proposal"]
        assert rb_prop["status"] == "rolled_back"
        assert rb_prop["approved"] is False
        assert not (skills_dir / "custom-idor-check").exists()


class TestRoadmapEndpointsSecurityAndHtml:
    def test_auth_csrf_ratelimit_and_path_containment_on_new_endpoints(self, tmp_path, monkeypatch):
        _make_target(tmp_path)
        monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
        monkeypatch.setenv("MOROS_DASHBOARD_TOKEN", "roadmap-secret-token")
        srv = types.SimpleNamespace(allow_remote=False, rate_limit_rpm=600)

        endpoints = [
            ("GET", "/api/targets/app.example.com/attack-graph", None),
            ("POST", "/api/targets/app.example.com/validate", {"finding": {"url": "https://app.example.com/"}}),
            ("POST", "/api/targets/app.example.com/remediate", {"finding": {"status": "candidate"}}),
            ("POST", "/api/targets/app.example.com/retest", {"finding": {"url": "https://app.example.com/"}}),
            ("POST", "/api/targets/app.example.com/skill-proposals/rollback", {"proposal_id": "p1"}),
        ]

        # 1. Missing token -> 401
        for method, path, body in endpoints:
            h = _http_handler(method, path, body=body, srv=srv)
            getattr(h, f"do_{method}")()
            assert h._status_code == 401

        # 2. Cross-origin POST -> 403 CSRF blocked
        for method, path, body in endpoints[1:]:
            h = _http_handler(
                method,
                path,
                body=body,
                headers={"Origin": "https://evil.example", "Authorization": "Bearer roadmap-secret-token"},
                srv=srv,
            )
            h.do_POST()
            assert h._status_code == 403

        # 3. Invalid target traversal -> 400
        h_trav = _http_handler(
            "GET",
            "/api/targets/..%2Fetc/attack-graph",
            headers={"Authorization": "Bearer roadmap-secret-token"},
            srv=srv,
        )
        h_trav.do_GET()
        assert h_trav._status_code == 400

        # 4. Rate limit enforced -> 429 on 3rd request from same IP
        srv_rl = types.SimpleNamespace(allow_remote=False, rate_limit_rpm=2)
        h_rl1 = _http_handler("GET", "/api/targets/app.example.com/attack-graph", headers={"Authorization": "Bearer roadmap-secret-token"}, client_ip="10.9.9.9", srv=srv_rl)
        h_rl1.do_GET()
        assert h_rl1._status_code == 200
        h_rl2 = _http_handler("GET", "/api/targets/app.example.com/attack-graph", headers={"Authorization": "Bearer roadmap-secret-token"}, client_ip="10.9.9.9", srv=srv_rl)
        h_rl2.do_GET()
        assert h_rl2._status_code == 200
        h_rl3 = _http_handler("GET", "/api/targets/app.example.com/attack-graph", headers={"Authorization": "Bearer roadmap-secret-token"}, client_ip="10.9.9.9", srv=srv_rl)
        h_rl3.do_GET()
        assert h_rl3._status_code == 429

    def test_dashboard_html_wires_lifecycle_attack_chains_and_rollback_ui(self):
        html = (Path(__file__).resolve().parent.parent / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")

        # Lifecycle badges & summaries in Findings & Triage
        for token in (
            "CANDIDATE",
            "CONFIRMED",
            "INCONCLUSIVE",
            "FALSE POSITIVE",
            "FIXED",
            "ACCEPTED RISK",
            "VALIDATED",
            "HUMAN REVIEWED",
            "Validation Summary",
            "Retest Summary",
            "Remediation Summary",
            "validateFindingAction",
            "remediateFindingAction",
            "retestFindingAction",
        ):
            assert token in html

        # Attack chain visualization panel & endpoint wiring
        for token in (
            "attackChainPanel",
            "attackChainsList",
            "attackGraphNodesEdges",
            "attackGraphMermaid",
            "/attack-graph",
            "/validate",
            "/remediate",
            "/retest",
        ):
            assert token in html

        # Skill proposal rollback / disable / enable controls
        for token in (
            "rollbackSkillProposal",
            "/skill-proposals/rollback",
            "Disable",
            "Rollback",
            "Enable",
        ):
            assert token in html
