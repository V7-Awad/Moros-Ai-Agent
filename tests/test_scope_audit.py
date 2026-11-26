import json
from pathlib import Path

from tools.hackbot_orchestrator import HackbotOrchestrator
from tools.finding_dedupe import deduplicate_findings
from tools.finding_review import review_candidates
from dashboard.server import DashboardHandler


class FakeScopeValidator:
    policy = {"same_host_only": True}

    def is_allowed(self, host):
        host = (host or "").lower().rstrip(".")
        return (host == "lastpass.com", "exact host only")


class FakeHttpClient:
    request_count = 1
    max_requests = 40
    delay_seconds = 0.8
    request_logs = [{
        "method": "GET",
        "url": "https://lastpass.com/",
        "status": "response",
        "status_code": 302,
    }]
    policy_violations = [{
        "kind": "blocked_redirect",
        "from": "lastpass.com",
        "to": "www.lastpass.com",
        "status_code": 302,
    }]
    stop_requested = True


def _orchestrator(tmp_path: Path) -> HackbotOrchestrator:
    orch = HackbotOrchestrator.__new__(HackbotOrchestrator)
    orch.target = "lastpass.com"
    orch.target_dir = tmp_path
    orch.current_run = {
        "run_id": "run-test",
        "started_at": "2026-11-26T11:00:00+00:00",
    }
    orch.scope_validator = FakeScopeValidator()
    orch.runner = type("Runner", (), {"http": FakeHttpClient()})()
    orch.scope_blocked_skills = ["xss-reflected"]
    orch.failed_skills = []
    orch.skills = ["recon-subdomain", "xss-reflected"]
    orch.models = ["default"]
    orch.runs_per_skill = 1
    orch.execution_log = []
    orch.skill_results = {}
    return orch


def test_scope_audit_records_scoped_client_requests_and_distinguishes_blocked_redirect(tmp_path):
    orch = _orchestrator(tmp_path)

    audit = orch._write_scope_audit()

    assert audit["request_count"] == 1
    assert audit["hosts_observed"] == {"lastpass.com": 1}
    assert audit["methods_observed"] == {"GET": 1}
    assert audit["out_of_scope_hosts"] == {}
    assert audit["out_of_policy_requests"] == []
    assert audit["stopped_by_policy"] is True
    assert audit["deviation_detected"] is False
    assert json.loads((tmp_path / "output/logs/scope-audit-latest.json").read_text())["hosts_observed"] == {
        "lastpass.com": 1
    }


def test_orchestration_log_reports_blocked_scope_not_success(tmp_path):
    orch = _orchestrator(tmp_path)

    orch._write_orchestration_log()

    log = json.loads((tmp_path / "output/logs/orchestration-log.json").read_text())
    assert log["status"] == "BLOCKED_SCOPE"
    assert log["scope_audit"]["stopped_by_policy"] is True


def test_dashboard_keeps_scope_block_status_after_restart(tmp_path, monkeypatch):
    target_dir = tmp_path / "lastpass.com"
    run_dir = target_dir / "output" / "runs" / "run-test"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps({"run_id": "run-test", "status": "blocked"}), encoding="utf-8")

    class FakeRunManager:
        def __init__(self, _target_dir):
            pass

        def get_latest_or_active_run(self):
            return {"run_id": "run-test", "status": "blocked"}

    import dashboard.server as dashboard_server
    monkeypatch.setattr(dashboard_server, "TARGETS_DIR", tmp_path)
    monkeypatch.setattr(dashboard_server, "RunManager", FakeRunManager)

    status = DashboardHandler.__new__(DashboardHandler).get_scan_status("lastpass.com")

    assert status["status"] == "blocked_scope"


def test_finding_review_and_dedupe_preserve_verified_lifecycle_states_and_force_unverified(tmp_path):
    proof_file = tmp_path / "output" / "evidence" / "validation" / "val-1.json"
    proof_file.parent.mkdir(parents=True)
    proof_file.write_text('{"ok": true}', encoding="utf-8")

    findings = [
        # Valid machine-confirmed finding
        {
            "title": "Reflected XSS in /search",
            "type": "Reflected XSS",
            "url": "https://example.com/search?q=test",
            "cwe": "CWE-79",
            "status": "confirmed",
            "validation_result": {
                "status": "confirmed",
                "evidence_ids": ["ev-1"],
                "proof_artifact": "output/evidence/validation/val-1.json",
                "deterministic": True,
            },
        },
        # Duplicate of same confirmed finding without proof -> must preserve confirmed!
        {
            "title": "Reflected XSS in /search",
            "type": "Reflected XSS",
            "url": "https://example.com/search?q=test",
            "status": "candidate",
            "validation_status": "unverified",
            "evidence_ids": ["ev-2"],
        },
        # Valid human-validated finding
        {
            "title": "IDOR on /api/orders/1",
            "type": "IDOR",
            "url": "https://example.com/api/orders/1",
            "validation_record": {
                "verified_by": "human:alice",
                "method": "curl",
                "evidence_ids": ["ev-3"],
                "outcome": "reproduced",
            },
        },
        # Unverified finding claiming confirmed WITHOUT proof_artifact / evidence_ids -> forced to candidate
        {
            "title": "Fake Confirmed SQLi",
            "type": "SQLi",
            "url": "https://example.com/items?id=1",
            "status": "confirmed",
            "validation_status": "confirmed",
            "validation_result": {"status": "confirmed", "evidence_ids": []},
        },
        # LLM-only claim -> forced to candidate
        {
            "title": "LLM-only SSRF",
            "type": "SSRF",
            "url": "https://example.com/fetch",
            "status": "confirmed",
            "validation_result": {
                "status": "confirmed",
                "evidence_ids": ["ev-4"],
                "proof_artifact": "output/evidence/validation/val-1.json",
                "deterministic": False,
                "llm_only": True,
            },
        },
        # Additive lifecycle states backed by validation_result / validation_record
        {
            "title": "Pending SSTI",
            "type": "SSTI",
            "url": "https://example.com/render",
            "validation_result": {"status": "validating"},
        },
        {
            "title": "Inconclusive CORS",
            "type": "CORS",
            "url": "https://example.com/api/me",
            "validation_result": {"status": "inconclusive"},
        },
        {
            "title": "False Positive WAF Block",
            "type": "SQLi",
            "url": "https://example.com/blocked",
            "status_code": 403,
            "response_body": "Access Denied by WAF",
            "validation_result": {"status": "false_positive"},
        },
        {
            "title": "Fixed Open Redirect",
            "type": "Open Redirect",
            "url": "https://example.com/go",
            "validation_result": {"status": "fixed"},
        },
        {
            "title": "Accepted Risk Banner",
            "type": "Info",
            "url": "https://example.com/",
            "status": "accepted_risk",
            "validation_record": {"verified_by": "human:sec-lead", "outcome": "accepted_risk"},
        },
        # Bare accepted_risk without human record -> forced to candidate
        {
            "title": "Unapproved Accepted Risk",
            "type": "IDOR",
            "url": "https://example.com/admin",
            "status": "accepted_risk",
        },
    ]

    deduped = deduplicate_findings(findings)
    assert len(deduped) == 10

    review = review_candidates("example.com", tmp_path, deduped, active_checks_allowed=True)
    by_title = {item["title"]: item for item in deduped}

    assert by_title["Reflected XSS in /search"]["status"] == "confirmed"
    assert by_title["Reflected XSS in /search"]["validation_status"] == "confirmed"
    assert by_title["Reflected XSS in /search"]["evidence_review"]["proof_exists"] is True
    assert by_title["Reflected XSS in /search"]["cvss"]["cvss_score"] == 6.1

    assert by_title["IDOR on /api/orders/1"]["status"] == "validated"
    assert by_title["IDOR on /api/orders/1"]["validation_status"] == "validated"

    assert by_title["Fake Confirmed SQLi"]["status"] == "candidate"
    assert by_title["Fake Confirmed SQLi"]["validation_status"] == "unverified"
    assert by_title["Fake Confirmed SQLi"]["cvss"]["cvss_score"] >= 9.0  # additive CVSS enrichment

    assert by_title["LLM-only SSRF"]["status"] == "candidate"
    assert by_title["LLM-only SSRF"]["validation_status"] == "unverified"

    assert by_title["Pending SSTI"]["status"] == "validating"
    assert by_title["Inconclusive CORS"]["status"] == "inconclusive"
    assert by_title["False Positive WAF Block"]["status"] == "false_positive"
    assert by_title["False Positive WAF Block"]["fp_analysis"]["is_known_fp"] is True
    assert by_title["Fixed Open Redirect"]["status"] == "fixed"
    assert by_title["Accepted Risk Banner"]["status"] == "accepted_risk"
    assert by_title["Unapproved Accepted Risk"]["status"] == "candidate"

    assert review["confirmed_findings"] == 1
    assert review["human_validated_findings"] == 1
    assert review["validated_findings"] == 2
    assert review["unverified_candidates"] == 3


def test_finding_review_fp_filter_enriches_without_overwriting_candidate_status(tmp_path):
    findings = [{
        "title": "WAF Block Page XSS",
        "type": "xss",
        "url": "https://example.com/search",
        "status_code": 403,
        "response_body": "Access Denied",
    }]
    review = review_candidates("example.com", tmp_path, findings, active_checks_allowed=False)
    assert findings[0]["status"] == "candidate"
    assert findings[0]["validation_status"] == "unverified"
    assert findings[0]["fp_analysis"]["is_known_fp"] is True
    assert review["unverified_candidates"] == 1


