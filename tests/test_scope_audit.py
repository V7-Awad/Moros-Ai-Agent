import json
from pathlib import Path

from tools.hackbot_orchestrator import HackbotOrchestrator
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

