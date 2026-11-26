import importlib.util
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


class _FakeHttpResponse:
    def __init__(self, status: int, url: str, body: bytes, headers: dict | None = None):
        self.status = status
        self._url = url
        self._body = body
        self.headers = headers or {"Content-Type": "application/json"}

    def geturl(self) -> str:
        return self._url

    def read(self, n: int = -1) -> bytes:
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_run_manager_resumable_selection_and_mark_resumed(tmp_path):
    from tools.run_manager import RunManager

    rm = RunManager(tmp_path)

    # Completed run is not resumable
    done_run = rm.create_run("example.com", ["recon-subdomain", "js-discover"])
    rm.update_skill_progress(done_run["run_id"], "recon-subdomain", status="completed")
    rm.update_skill_progress(done_run["run_id"], "js-discover", status="completed")
    rm.finish_run(done_run["run_id"], status="completed")

    # Failed run with pending skills IS resumable
    failed_run = rm.create_run("example.com", ["recon-subdomain", "js-discover", "js-analyze"])
    rm.update_skill_progress(failed_run["run_id"], "recon-subdomain", status="completed")
    rm.update_skill_progress(failed_run["run_id"], "js-discover", status="failed", summary="network blip")
    rm.finish_run(failed_run["run_id"], status="failed", error="interrupted")

    # Ensure deterministic newest ordering by adjusting started_at on a newer aborted run
    aborted_run = rm.create_run("example.com", ["recon-subdomain", "xss-reflected"])
    aborted_file = tmp_path / "output" / "runs" / aborted_run["run_id"] / "run.json"
    aborted_data = json.loads(aborted_file.read_text(encoding="utf-8"))
    aborted_data["started_at"] = "2099-01-01T00:00:00+00:00"
    aborted_file.write_text(json.dumps(aborted_data, indent=2), encoding="utf-8")
    rm.update_skill_progress(aborted_run["run_id"], "recon-subdomain", status="completed")
    rm.finish_run(aborted_run["run_id"], status="aborted")

    latest = rm.get_latest_resumable_run()
    assert latest is not None
    assert latest["run_id"] == aborted_run["run_id"]

    plan_latest = rm.prepare_resume_plan()
    assert plan_latest is not None
    assert plan_latest["run_id"] == aborted_run["run_id"]
    assert plan_latest["skills_completed"] == ["recon-subdomain"]
    assert plan_latest["skills_pending"] == ["xss-reflected"]

    plan_specific = rm.prepare_resume_plan(failed_run["run_id"])
    assert plan_specific is not None
    assert plan_specific["skills_pending"] == ["js-discover", "js-analyze"]
    assert rm.prepare_resume_plan(done_run["run_id"]) is None
    assert rm.prepare_resume_plan("run-does-not-exist") is None

    resumed = rm.mark_run_resumed(failed_run["run_id"])
    assert resumed["status"] == "running"
    assert resumed["pid"] == os.getpid()
    assert resumed["completed_at"] is None
    assert resumed["current_skill"] == "js-discover"

    events_file = tmp_path / "output" / "runs" / failed_run["run_id"] / "events.jsonl"
    events = [json.loads(line) for line in events_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(ev["event"] == "RUN_RESUMED" for ev in events)

    # Retrying the previously failed skill clears it from skills_failed when completed
    rm.update_skill_progress(failed_run["run_id"], "js-discover", status="completed")
    updated = rm.get_run(failed_run["run_id"])
    assert "js-discover" in updated["skills_completed"]
    assert "js-discover" not in updated["skills_failed"]


def test_orchestrator_resume_skips_completed_and_falls_back_when_missing(tmp_path, monkeypatch, caplog):
    from tools.hackbot_orchestrator import HackbotOrchestrator
    from tools.run_manager import RunManager

    (tmp_path / "scope-of-work.md").write_text(
        "Authorized security assessment for example.com (in scope).", encoding="utf-8"
    )
    (tmp_path / "output" / "js").mkdir(parents=True, exist_ok=True)
    (tmp_path / "output" / "js" / "endpoints.json").write_text('{"endpoints": []}', encoding="utf-8")

    rm = RunManager(tmp_path)
    prior = rm.create_run(
        target="example.com",
        skills=["recon-subdomain", "js-discover", "js-analyze", "report-conglomeration"],
    )
    rm.update_skill_progress(prior["run_id"], "recon-subdomain", status="completed")
    rm.update_skill_progress(prior["run_id"], "js-discover", status="completed")
    rm.finish_run(prior["run_id"], status="aborted")

    executed_skills = []
    monkeypatch.setenv("MOROS_LLM_PROVIDER", "none")

    orch = HackbotOrchestrator(
        target="example.com",
        target_dir=str(tmp_path),
        skills=["recon-subdomain", "js-discover", "js-analyze", "report-conglomeration"],
        resume_run_id="latest",
        proxy="http://127.0.0.1:8888",
        enable_tracing=False,
    )
    monkeypatch.setattr(orch, "_model_preflight", lambda: None)
    assert os.environ.get("MOROS_PROXY") == "http://127.0.0.1:8888"

    monkeypatch.setattr(orch.runner.http, "request", lambda *a, **kw: {"status": "error"})
    monkeypatch.setattr(
        orch.runner,
        "run_recon_subdomain",
        lambda **kw: (executed_skills.append("recon-subdomain"), {"status": "SUCCESS"})[1],
    )
    monkeypatch.setattr(
        orch.runner,
        "run_js_discover",
        lambda: (executed_skills.append("js-discover"), {"status": "COMPLETED", "files_collected": 0})[1],
    )
    monkeypatch.setattr(
        orch.runner,
        "run_js_analyze",
        lambda: (executed_skills.append("js-analyze"), {"status": "COMPLETED", "findings_count": 0, "summary": "ok"})[1],
    )
    monkeypatch.setattr(
        orch.runner,
        "run_report_conglomeration",
        lambda: (executed_skills.append("report-conglomeration"), {"status": "SUCCESS", "findings_count": 0})[1],
    )
    monkeypatch.setattr(
        orch.runner,
        "run_review_skill",
        lambda s: {"overall_status": "PASS", "non_zero_logs_count": 1},
    )

    res = orch.run()
    assert res["status"] == "SUCCESS"
    assert res["run_id"] == prior["run_id"]
    assert res["resumed"] is True
    assert executed_skills == ["js-analyze", "report-conglomeration"]

    final_rec = rm.get_run(prior["run_id"])
    assert final_rec["status"] == "completed"
    assert set(final_rec["skills_completed"]) == {
        "recon-subdomain", "js-discover", "js-analyze", "report-conglomeration"
    }

    # Now no resumable run remains; asking to resume should warn and start a fresh run
    caplog.clear()
    executed_fresh = []
    fresh_orch = HackbotOrchestrator(
        target="example.com",
        target_dir=str(tmp_path),
        skills=["recon-subdomain"],
        resume_run_id="latest",
        enable_tracing=False,
    )
    monkeypatch.setattr(fresh_orch, "_model_preflight", lambda: None)
    monkeypatch.setattr(fresh_orch.runner.http, "request", lambda *a, **kw: {"status": "error"})
    monkeypatch.setattr(
        fresh_orch.runner,
        "run_recon_subdomain",
        lambda **kw: (executed_fresh.append("recon-subdomain"), {"status": "SUCCESS"})[1],
    )
    monkeypatch.setattr(
        fresh_orch.runner,
        "run_review_skill",
        lambda s: {"overall_status": "PASS", "non_zero_logs_count": 1},
    )

    fresh_res = fresh_orch.run()
    assert fresh_res["status"] == "SUCCESS"
    assert fresh_res["resumed"] is False
    assert fresh_res["run_id"] != prior["run_id"]
    assert executed_fresh == ["recon-subdomain"]
    assert any("No resumable run found" in rec.message for rec in caplog.records)


def test_cli_parses_proxy_resume_and_no_failover(tmp_path, monkeypatch):
    import run as moros_run
    from tools.run_manager import RunManager

    target_dir = tmp_path / "example.com"
    target_dir.mkdir(parents=True)
    (target_dir / "scope-of-work.md").write_text(
        "Authorized testing for example.com (in scope).", encoding="utf-8"
    )

    # Create a resumable run to verify `--resume` without `--skills` restores prior skills_requested
    rm = RunManager(target_dir)
    prior = rm.create_run("example.com", ["recon-subdomain", "js-discover"])
    rm.update_skill_progress(prior["run_id"], "recon-subdomain", status="completed")
    rm.finish_run(prior["run_id"], status="failed")

    captured = {}

    class DummyRunner:
        sandbox_mode = None
        max_subagents = None

    class DummyCostTracker:
        @staticmethod
        def get_running_total():
            return {"total_calls": 0}

    class DummyOrchestrator:
        def __init__(self, **kwargs):
            captured["kwargs"] = kwargs
            self.runner = DummyRunner()
            self.cost_tracker = DummyCostTracker()

        def run(self):
            return {"status": "SUCCESS"}

    monkeypatch.delenv("MOROS_PROXY", raising=False)
    monkeypatch.delenv("MOROS_LLM_FAILOVER", raising=False)
    monkeypatch.setattr(moros_run, "HackbotOrchestrator", DummyOrchestrator)

    try:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "run.py",
                "--target", "example.com",
                "--target-dir", str(target_dir),
                "--proxy", "http://127.0.0.1:8080",
                "--resume",
                "--no-failover",
            ],
        )
        moros_run.main()

        assert os.environ.get("MOROS_PROXY") == "http://127.0.0.1:8080"
        assert os.environ.get("MOROS_LLM_FAILOVER") == "0"
        assert captured["kwargs"]["proxy"] == "http://127.0.0.1:8080"
        assert captured["kwargs"]["resume_run_id"] == "latest"
        assert captured["kwargs"]["skills"] == ["recon-subdomain", "js-discover"]

        # Explicit run ID with `--resume <run_id>`
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "run.py",
                "--target", "example.com",
                "--target-dir", str(target_dir),
                "--skills", "recon-subdomain",
                "--resume", prior["run_id"],
            ],
        )
        moros_run.main()
        assert captured["kwargs"]["resume_run_id"] == prior["run_id"]
        assert captured["kwargs"]["skills"] == ["recon-subdomain"]
    finally:
        os.environ.pop("MOROS_PROXY", None)
        os.environ.pop("MOROS_LLM_FAILOVER", None)


def test_business_logic_skill_direct_offline_execution(tmp_path):
    target_dir = tmp_path / "shop.local"
    out_dir = target_dir / "output"
    (out_dir / "js").mkdir(parents=True)
    (out_dir / "api").mkdir(parents=True)

    (out_dir / "js" / "endpoints.json").write_text(
        json.dumps({
            "endpoints": [
                {"url": "https://shop.local/api/cart/update", "method": "POST", "parameters": ["quantity", "price"]},
                {"url": "https://shop.local/api/coupons/apply", "method": "POST", "parameters": [{"name": "coupon_code"}]},
                {"url": "https://shop.local/healthz", "method": "GET"},
                {"url": "https://shop.local/static/app.js", "method": "GET"},
            ]
        }),
        encoding="utf-8",
    )
    (out_dir / "api" / "endpoints.json").write_text(
        json.dumps({
            "endpoints": [
                {"path": "/api/wallet/transfer", "method": "POST", "parameters": ["amount", "to_account"]},
                {"path": "/api/subscription/upgrade", "method": "POST", "parameters": ["tier"]},
            ]
        }),
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["MOROS_HTTP_REQUESTS_REMAINING"] = "0"
    env["MOROS_LLM_PROVIDER"] = "none"

    proc = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "skills" / "business-logic" / "run.py"),
            "--target", "shop.local",
            "--target-dir", str(target_dir),
            "--output-dir", str(out_dir),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr

    out_json = out_dir / "findings" / "candidates-business-logic.json"
    log_file = out_dir / "logs" / "business-logic" / "run.log"
    assert out_json.is_file()
    assert log_file.is_file()
    assert log_file.stat().st_size > 0

    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["skill"] == "business-logic"
    assert payload["llm_enriched"] is False
    findings = payload["findings"]
    assert len(findings) == 4
    urls = [f["url"] for f in findings]
    assert "https://shop.local/healthz" not in urls
    assert "https://shop.local/static/app.js" not in urls
    assert all(f["status"] == "candidate" and f["validation_status"] == "unverified" for f in findings)

    cart_finding = next(f for f in findings if "/api/cart/update" in f["url"])
    assert "negative_or_zero_quantity" in cart_finding["risk_indicators"]
    assert "quantity" in cart_finding["tamper_parameters"]
    assert cart_finding["hitl_tamper_tested"] is False


def test_business_logic_skill_hitl_gated_post_and_llm_enrichment(tmp_path, monkeypatch):
    from tools.checkpoint_manager import CheckpointManager
    from tools.skill_runner import SkillRunner

    target_dir = tmp_path / "shop.local"
    out_dir = target_dir / "output"
    (out_dir / "api").mkdir(parents=True)
    (target_dir / "scope-of-work.md").write_text(
        "Authorized assessment for shop.local (in scope).", encoding="utf-8"
    )
    checkout_url = "https://shop.local/api/cart/checkout"
    (out_dir / "api" / "endpoints.json").write_text(
        json.dumps({"endpoints": [{"url": checkout_url, "method": "POST", "parameters": ["quantity", "price"]}]}),
        encoding="utf-8",
    )

    # Pre-approve checkpoint for HITL-gated negative-quantity POST check
    cm = CheckpointManager("shop.local", target_dir)
    cp = cm.create_checkpoint(
        "Business Logic Tamper Probe",
        checkout_url,
        method="POST",
        reason="Test tamper",
        risk_level="MEDIUM",
    )
    cm.decide(cp["id"], "approve", notes="Approved in test")

    sent_payloads = []

    def _mock_open(self, req, timeout=15.0):
        body = req.data.decode("utf-8") if req.data else ""
        sent_payloads.append((req.get_method(), req.full_url, body))
        return _FakeHttpResponse(200, req.full_url, b'{"order_id": 42, "total": -10, "accepted": true}')

    monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "5")
    monkeypatch.setenv("MOROS_ALLOW_GATED_POST", "1")
    monkeypatch.delenv("MOROS_LLM_PROVIDER", raising=False)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _mock_open)

    script_path = PROJECT_ROOT / "skills" / "business-logic" / "run.py"
    spec = importlib.util.spec_from_file_location("skill_business_logic_run", script_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class _MockLLM:
        provider = "mock"
        model = "mock-logic"

        def __init__(self, provider="auto", **kwargs):
            pass

        def is_available(self):
            return True

        def complete(self, prompt, **kwargs):
            return json.dumps([
                {
                    "url": checkout_url,
                    "abuse_scenario": "Submitting quantity=-1 reverses subtotal calculation.",
                    "verification_step": "Verify server rejects negative integer quantities.",
                }
            ])

    monkeypatch.setattr(mod, "LLMClient", _MockLLM)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(script_path), "--target", "shop.local", "--target-dir", str(target_dir), "--output-dir", str(out_dir)],
    )
    mod.main()

    assert len(sent_payloads) == 1
    assert sent_payloads[0][0] == "POST"
    assert '"quantity": -1' in sent_payloads[0][2]

    result = json.loads((out_dir / "findings" / "candidates-business-logic.json").read_text(encoding="utf-8"))
    assert result["llm_enriched"] is True
    finding = result["findings"][0]
    assert finding["hitl_tamper_tested"] is True
    assert finding["severity"] == "HIGH"
    assert "reverses subtotal" in finding["llm_analysis"]["abuse_scenario"]

    # Ensure SkillRunner.run_custom_skill accepts skills/business-logic/run.py without unscoped-network block
    monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "0")
    monkeypatch.setenv("MOROS_LLM_PROVIDER", "none")
    runner = SkillRunner("shop.local", target_dir, sandbox_mode="none")
    runner.scope_authorized = True
    custom_res = runner.run_custom_skill("business-logic")
    assert custom_res["status"] == "COMPLETED"
    assert custom_res["findings_count"] >= 1
