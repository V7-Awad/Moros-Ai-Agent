#!/usr/bin/env python3
"""End-to-end roadmap lifecycle tests for Moros AI (Phases 1-6 + CLI/Orchestrator wiring)."""

import http.client
import importlib.util
import json
import os
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import run as moros_run
from learning_engine.engine import LearningEngine
from tools.exploit_validator import ProofRecorder
from tools.hackbot_orchestrator import HackbotOrchestrator
from tools.retest_engine import FIXED_LIMITATION_NOTE, RetestEngine


class _EphemeralHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )


def _create_vulnerable_git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repo containing a deliberately vulnerable Python web helper + unit tests."""
    repo = tmp_path / "lab_repo"
    (repo / "tests").mkdir(parents=True)

    (repo / "vuln_app.py").write_text(
        "def render_search_page(q: str) -> str:\n"
        "    # Route: /search?q=...\n"
        "    return f\"<html><body><h1>Search Results</h1><div>{q}</div></body></html>\"\n",
        encoding="utf-8",
    )

    (repo / "tests" / "test_vuln_app.py").write_text(
        "from vuln_app import render_search_page\n\n"
        "def test_search_renders_benign_query():\n"
        "    body = render_search_page('hello')\n"
        "    assert 'hello' in body\n\n"
        "def test_search_escapes_html_probe():\n"
        "    body = render_search_page('<moros-probe data-id=\"1\">1</moros-probe>')\n"
        "    assert '<moros-probe' not in body\n"
        "    assert '&lt;moros-probe' in body\n",
        encoding="utf-8",
    )

    _git(repo, "init")
    _git(repo, "config", "user.email", "moros-lab@example.local")
    _git(repo, "config", "user.name", "Moros Lab")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "initial vulnerable lab app")
    return repo


def _make_lab_handler(server_state: dict):
    class LabHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _send(self, status: int, content_type: str, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self._send(200, "text/html; charset=utf-8", b"")

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            if path == "/":
                html = (
                    "<!doctype html><html><head><title>Lab App</title></head>"
                    "<body><h1>Controlled Lab</h1>"
                    "<a href='/search?q=hello'>Search</a>"
                    "<a href='/redirect?next=/home'>Redirect</a>"
                    "<script src='/app.js'></script>"
                    "</body></html>"
                ).encode("utf-8")
                self._send(200, "text/html; charset=utf-8", html)
                return

            if path == "/app.js":
                js = (
                    "async function doSearch(q) { return fetch('/search?q=' + encodeURIComponent(q)); }\n"
                    "async function doRedirect(next) { return fetch('/redirect?next=' + encodeURIComponent(next)); }\n"
                ).encode("utf-8")
                self._send(200, "application/javascript; charset=utf-8", js)
                return

            if path == "/search":
                q = params.get("q", [""])[0]
                if server_state.get("patched_xss"):
                    import html as html_lib
                    safe_q = html_lib.escape(str(q), quote=True)
                    body = f"<html><body><h1>Search Results</h1><div id='results'>{safe_q}</div></body></html>"
                else:
                    body = f"<html><body><h1>Search Results</h1><div id='results'>{q}</div></body></html>"
                self._send(200, "text/html; charset=utf-8", body.encode("utf-8"))
                return

            if path == "/redirect":
                next_url = params.get("next", ["/"])[0]
                if server_state.get("patched_redirect"):
                    parsed_next = urllib.parse.urlparse(next_url)
                    if parsed_next.scheme or parsed_next.netloc or not next_url.startswith("/") or next_url.startswith("//"):
                        next_url = "/"
                self.send_response(302)
                self.send_header("Location", next_url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            self._send(404, "text/plain; charset=utf-8", b"Not Found")

    return LabHandler


def test_complete_moros_roadmap_lifecycle_e2e(tmp_path, monkeypatch):
    """
    Exercise the full Moros roadmap lifecycle offline:
    discover candidate -> deterministic validate (confirmed + SHA-256) ->
    attack-chain correlation -> remediation proposal & isolated test pass ->
    retest after patched fixture (fixed + preserved proof) ->
    ci_gate (2 before fix, 0 after fix) -> advisory learning recall.
    """
    repo_dir = _create_vulnerable_git_repo(tmp_path)
    server_state = {"patched_xss": False, "patched_redirect": False}
    httpd = _EphemeralHTTPServer(("127.0.0.1", 0), _make_lab_handler(server_state))
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    orig_http_init = http.client.HTTPConnection.__init__

    def _port_forwarded_init(conn_self, host, conn_port=None, *args, **kwargs):
        if conn_port is None and "port" in kwargs:
            conn_port = kwargs.pop("port")
        if host == "127.0.0.1" and conn_port in (None, 80):
            conn_port = port
        return orig_http_init(conn_self, host, conn_port, *args, **kwargs)

    monkeypatch.setattr(http.client.HTTPConnection, "__init__", _port_forwarded_init)
    monkeypatch.setenv("MOROS_LLM_PROVIDER", "none")

    class ScriptedLabLLM:
        provider = "test"
        model = "scripted-lab-model"
        last_error = None
        last_usage = {"input_tokens": 1, "output_tokens": 1}

        def __init__(self):
            self.js_calls = 0

        @staticmethod
        def is_available():
            return True

        def complete(self, prompt, system_prompt="", **kwargs):
            if "javascript & api hunter" in system_prompt.lower():
                actions = ["extract_endpoints()", "fingerprint_tech_stack()"]
                if self.js_calls < len(actions):
                    act = actions[self.js_calls]
                    self.js_calls += 1
                    return f"Thought: analyze JS\nAction: {act}"
            return "Final Answer: Completed lab analysis."

    try:
        target_name = "127.0.0.1"
        target_dir = tmp_path / "targets" / target_name
        target_dir.mkdir(parents=True)
        (target_dir / "scope-of-work.md").write_text(
            "# Authorized Scope\n"
            "Authorized security assessment for 127.0.0.1 (in scope).\n"
            "## In Scope\n- 127.0.0.1\n",
            encoding="utf-8",
        )

        # ── Step 1 & 2: Discover Candidates + Deterministic Phase 1 Validation + Attack Chain ──
        orch = HackbotOrchestrator(
            target=target_name,
            target_dir=str(target_dir),
            skills=["js-discover", "js-analyze", "xss-reflected", "open-redirect", "report-conglomeration"],
            max_http_requests=80,
            request_delay=0.0,
            enable_tracing=False,
            validate_candidates=True,
        )
        orch.runner.sandbox_mode = "none"
        orch.runner.http.base_url = f"http://{target_name}"
        orch.runner.http.scope_validator.policy["same_host_only"] = True
        orch.runner.http.scope_validator.policy["allow_cross_host_sources"] = False
        monkeypatch.setattr(orch, "_model_preflight", lambda: None)
        scripted_llm = ScriptedLabLLM()
        monkeypatch.setattr(orch, "_llm_for_model", lambda _m: scripted_llm)

        # Execute skills/open-redirect/run.py in-process so it shares the port-forwarded loopback socket
        orig_run_custom = orch.runner.run_custom_skill

        def _run_custom_in_process(skill_name: str):
            if skill_name == "open-redirect":
                script_path = PROJECT_ROOT / "skills" / "open-redirect" / "run.py"
                spec = importlib.util.spec_from_file_location("open_redirect_e2e", script_path)
                mod = importlib.util.module_from_spec(spec)
                assert spec and spec.loader
                spec.loader.exec_module(mod)
                prev_argv = sys.argv
                try:
                    sys.argv = [
                        str(script_path),
                        "--target", f"http://{target_name}",
                        "--target-dir", str(target_dir),
                        "--output-dir", str(target_dir / "output"),
                    ]
                    mod.main()
                finally:
                    sys.argv = prev_argv
                out_file = target_dir / "output" / "findings" / "candidates-open-redirect.json"
                items = json.loads(out_file.read_text(encoding="utf-8")).get("findings", []) if out_file.is_file() else []
                orch.runner.log_step("open-redirect", "run.log", f"Open Redirect scan completed: {len(items)} candidates found.")
                return {"status": "COMPLETED", "findings_count": len(items), "findings": items, "summary": f"Found {len(items)} redirect candidates"}
            return orig_run_custom(skill_name)

        monkeypatch.setattr(orch.runner, "run_custom_skill", _run_custom_in_process)

        run_res = orch.run()
        assert run_res["status"] == "SUCCESS"
        assert orch.validation_summary["confirmed"] >= 2

        # Verify SHA-256 proof artifacts + ledger integrity
        recorder = ProofRecorder(target_name, target_dir=target_dir)
        report_files = sorted((target_dir / "output" / "report").glob("hackbot-report-*.json"))
        assert report_files
        report_doc = json.loads(report_files[-1].read_text(encoding="utf-8"))
        findings = report_doc["findings"]

        xss_finding = next(f for f in findings if "/search" in str(f.get("url", "")))
        redir_finding = next(f for f in findings if "/redirect" in str(f.get("url", "")))

        assert xss_finding["status"] == "confirmed"
        assert xss_finding["validation_status"] == "confirmed"
        assert xss_finding.get("proof_artifact")
        assert xss_finding.get("evidence_ids")
        assert recorder.verify_proof_integrity(xss_finding["proof_artifact"])["valid"] is True

        assert redir_finding["status"] == "confirmed"
        assert recorder.verify_proof_integrity(redir_finding["proof_artifact"])["valid"] is True
        assert report_doc["summary"]["confirmed_findings"] >= 2

        # Verify Phase 2 Attack-Chain Correlation
        attack_graph_file = target_dir / "output" / "report" / "attack-graph.json"
        attack_chains_file = target_dir / "output" / "report" / "attack-chains.json"
        assert attack_graph_file.is_file()
        assert attack_chains_file.is_file()
        graph_doc = json.loads(attack_graph_file.read_text(encoding="utf-8"))
        assert graph_doc["attack_chains"], "Expected correlated open_redirect -> xss attack chain"
        assert any(
            edge.get("relation") == "CHAINS_TO_XSS" and edge.get("verified") is True
            for edge in graph_doc["edges"]
        )

        # ── Step 3: CI Gate BEFORE fix -> exit code 2 ──
        pr_before = tmp_path / "pr-summary-before.md"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "run.py",
                "--target", target_name,
                "--target-dir", str(target_dir),
                "--ci-gate",
                "--min-severity", "medium",
                "--fail-on-confirmed",
                "--pr-summary-out", str(pr_before),
            ],
        )
        with pytest.raises(SystemExit) as gate_before_exc:
            moros_run.main()
        assert gate_before_exc.value.code == 2
        assert pr_before.is_file()
        pr_before_text = pr_before.read_text(encoding="utf-8")
        assert "FAIL" in pr_before_text

        # ── Step 4: Remediation Proposal & Isolated Tests via run.py --remediate ──
        xss_fid = xss_finding["finding_id"]
        orig_proof_artifact = xss_finding["proof_artifact"]
        orig_evidence_ids = list(xss_finding["evidence_ids"])

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "run.py",
                "--target", target_name,
                "--target-dir", str(target_dir),
                "--remediate", xss_fid,
                "--repo-dir", str(repo_dir),
            ],
        )
        with pytest.raises(SystemExit) as rem_exc:
            moros_run.main()
        assert rem_exc.value.code == 0

        rem_report_path = target_dir / "output" / "remediation" / f"{xss_fid}.json"
        assert rem_report_path.is_file()
        rem_report = json.loads(rem_report_path.read_text(encoding="utf-8"))
        assert rem_report["approval_status"] == "pending_approval"
        assert rem_report["affected_file"] == "vuln_app.py"
        assert "html.escape" in rem_report["patch_diff"]
        assert rem_report["test_results"]["passed"] is True

        # Ensure main git repo working tree was never modified or auto-committed
        assert _git(repo_dir, "status", "--porcelain").stdout.strip() == ""
        assert "html.escape" not in (repo_dir / "vuln_app.py").read_text(encoding="utf-8")

        # ── Step 5: Deploy fix to live server & Retest via run.py --retest ──
        server_state["patched_xss"] = True
        server_state["patched_redirect"] = True

        for fid in (xss_fid, redir_finding["finding_id"]):
            monkeypatch.setattr(
                sys,
                "argv",
                [
                    "run.py",
                    "--target", target_name,
                    "--target-dir", str(target_dir),
                    "--retest", fid,
                ],
            )
            with pytest.raises(SystemExit) as retest_exc:
                moros_run.main()
            assert retest_exc.value.code == 0

        retest_files = sorted((target_dir / "output" / "evidence" / "retests").glob("ret-*.json"))
        assert len(retest_files) >= 2
        retest_engine = RetestEngine(target=f"http://{target_name}", target_dir=target_dir)
        xss_retest_doc = next(
            json.loads(p.read_text(encoding="utf-8"))
            for p in retest_files
            if json.loads(p.read_text(encoding="utf-8")).get("finding_id") == xss_fid
        )
        assert xss_retest_doc["outcome"] == "fixed"
        assert FIXED_LIMITATION_NOTE in xss_retest_doc["limitations"]
        assert retest_engine.verify_retest_integrity(xss_retest_doc["retest_artifact"])["valid"] is True

        # Verify historical proof + evidence_ids preserved on finding in report
        updated_report = json.loads(report_files[-1].read_text(encoding="utf-8"))
        updated_xss = next(f for f in updated_report["findings"] if f.get("finding_id") == xss_fid)
        assert updated_xss["status"] == "fixed"
        assert updated_xss["proof_artifact"] == orig_proof_artifact
        assert updated_xss.get("validation_result", {}).get("status") == "confirmed"
        for eid in orig_evidence_ids:
            assert eid in updated_xss["evidence_ids"]
        assert len(updated_xss.get("retest_history", [])) >= 1

        # ── Step 6: CI Gate AFTER fix -> exit code 0 ──
        pr_after = tmp_path / "pr-summary-after.md"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "run.py",
                "--target", target_name,
                "--target-dir", str(target_dir),
                "--ci-gate",
                "--min-severity", "medium",
                "--fail-on-confirmed",
                "--pr-summary-out", str(pr_after),
            ],
        )
        with pytest.raises(SystemExit) as gate_after_exc:
            moros_run.main()
        assert gate_after_exc.value.code == 0
        pr_after_text = pr_after.read_text(encoding="utf-8")
        assert "PASS" in pr_after_text

        # ── Step 7: Advisory Learning Recall ──
        with LearningEngine(root=target_dir) as le:
            stats = le.stats()
            assert stats["findings"] >= 1
            assert stats["outcome_events"] >= 4  # validations + remediation + retests
            assert stats["attack_paths"] >= 1
            recon_recall = le.before_recon(target_name)
            assert recon_recall["ok"] is True
            assert len(recon_recall["relevant_lessons"]) >= 1
            outcomes = le.get_outcomes(finding_id=xss_fid)
            kinds = {o["outcome_kind"]: o["outcome"] for o in outcomes}
            assert kinds.get("validation") == "confirmed"
            assert kinds.get("remediation") == "tested_pass"
            assert kinds.get("retest") == "fixed"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_advisory_prioritization_non_binding_and_preserves_boundaries(tmp_path):
    """apply_advisory_prioritization() reorders skills as non-binding hints without altering scope/budgets."""
    target_dir = tmp_path / "app.local"
    target_dir.mkdir(parents=True)
    (target_dir / "scope.json").write_text(
        json.dumps({"target": "app.local", "allow_active_vulnerability_checks": False}),
        encoding="utf-8",
    )

    with LearningEngine(root=target_dir) as le:
        le.record_tech_fingerprint(target="app.local", technology="graphql", run_id="r-1", evidence_ids=["ev-1"])
        le.record_skill_telemetry(
            target="app.local",
            skill_id="ssrf-identify",
            vuln_class="ssrf",
            findings_count=4,
            confirmed_count=3,
            cost_usd=0.05,
            tech_stack=["graphql"],
            run_id="r-1",
            evidence_ids=["ev-1"],
        )
        le.record_skill_telemetry(
            target="app.local",
            skill_id="xss-reflected",
            vuln_class="xss",
            findings_count=1,
            confirmed_count=0,
            cost_usd=0.40,
            tech_stack=["graphql"],
            run_id="r-2",
            evidence_ids=["ev-2"],
        )

    orch = HackbotOrchestrator(
        target="app.local",
        target_dir=str(target_dir),
        skills=["recon-subdomain", "xss-reflected", "ssrf-identify", "report-conglomeration"],
        budget_usd=4.25,
        max_http_requests=55,
        enable_tracing=False,
    )
    orig_budget = orch.budget_usd
    orig_max_reqs = orch.max_http_requests
    orig_policy = dict(orch.scope_validator.policy)

    hint = orch.apply_advisory_prioritization(techs=["graphql"])
    assert hint["advisory"] is True
    assert hint["applied"] is True
    assert hint["ordered_skills"] == [
        "recon-subdomain",
        "ssrf-identify",
        "xss-reflected",
        "report-conglomeration",
    ]
    assert orch.skills == hint["ordered_skills"]
    # Strict boundary immutability
    assert orch.budget_usd == orig_budget
    assert orch.max_http_requests == orig_max_reqs
    assert orch.scope_validator.policy == orig_policy
    assert orch.scope_authorized is False


def test_cli_validate_flag_and_oob_listen_summary(tmp_path, monkeypatch, capsys):
    """run.py forwards --validate to HackbotOrchestrator and fixes --oob-listen start/summary calls."""
    target_dir = tmp_path / "oob.local"
    target_dir.mkdir(parents=True)
    (target_dir / "scope-of-work.md").write_text(
        "Authorized security test for oob.local (in scope).",
        encoding="utf-8",
    )

    captured = {}

    class DummyRunner:
        sandbox_mode = None
        max_subagents = None

    class DummyCostTracker:
        @staticmethod
        def get_running_total():
            return {"total_calls": 0}

    class DummyOOBOrchestrator:
        def __init__(self, **kwargs):
            captured["kwargs"] = kwargs
            self.runner = DummyRunner()
            self.cost_tracker = DummyCostTracker()

        def run(self):
            oob_url = os.environ.get("MOROS_OOB_URL", "")
            captured["oob_url"] = oob_url
            assert isinstance(oob_url, str) and oob_url.startswith("http://127.0.0.1:")
            # Deliver a real HTTP hit to the active OOB listener
            with urllib.request.urlopen(oob_url + "/oob/test-hit", timeout=3) as resp:
                assert resp.status == 200
            return {"status": "SUCCESS"}

    import os
    monkeypatch.delenv("MOROS_OOB_URL", raising=False)
    monkeypatch.delenv("MOROS_CALLBACK_URL", raising=False)
    monkeypatch.setattr(moros_run, "HackbotOrchestrator", DummyOOBOrchestrator)
    monkeypatch.setattr(
        moros_run,
        "LLMClient",
        lambda provider="auto": type("AvailLLM", (), {"is_available": staticmethod(lambda: True)})(),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run.py",
            "--target", "oob.local",
            "--target-dir", str(target_dir),
            "--skills", "recon-subdomain",
            "--validate",
            "--oob-listen",
        ],
    )
    moros_run.main()

    out = capsys.readouterr().out
    assert captured["kwargs"]["validate_candidates"] is True
    assert captured["oob_url"].startswith("http://127.0.0.1:")
    assert "OOB Listener captured 1 callback(s)" in out
