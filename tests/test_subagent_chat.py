import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from dashboard.server import DashboardHandler
from tools.conversation_store import ConversationStore
from tools.run_manager import RunManager


def test_roster_active_status():
    with tempfile.TemporaryDirectory() as tmp_dir:
        target_path = Path(tmp_dir) / "test.com"
        target_path.mkdir(parents=True)

        with patch("dashboard.server.TARGETS_DIR", Path(tmp_dir)):
            handler = DashboardHandler.__new__(DashboardHandler)
            roster = handler.get_subagent_roster("test.com")

            assert len(roster) == 9
            # Coordinator reflects primary session, specialists reflect on-demand skills
            coord = next(a for a in roster if a["id"] == "coordinator")
            assert "Coordinator" in coord["tier"]
            assert coord["status"] in ("CONFIGURED (Ready)", "ONLINE (Active)", "LLM OFFLINE", "RUNNING")

            specialists = [a for a in roster if a["id"] != "coordinator"]
            assert len(specialists) == 8
            for s in specialists:
                assert s["tier"]
                assert s["status"] in ("STANDBY (On-Demand)", "COMPLETED", "BLOCKED BY SCOPE", "FAILED", "RUNNING", "QUEUED")
            assert {"evidence-integrity-review", "skeptical-false-positive-review"}.issubset({a["id"] for a in specialists})


def test_agent_greetings():
    handler = DashboardHandler.__new__(DashboardHandler)
    recon_greeting = handler.get_agent_greeting("test.com", "recon-agent")
    assert "Reconnaissance Specialist" in recon_greeting
    assert "Directives supported:" in recon_greeting

    js_greeting = handler.get_agent_greeting("test.com", "js-analyzer")
    assert "JavaScript & API Hunter" in js_greeting

    sarif_greeting = handler.get_agent_greeting("test.com", "report-specialist")
    assert "SARIF 2.1.0" in sarif_greeting


def test_execute_subagent_chat_deterministic():
    with tempfile.TemporaryDirectory() as tmp_dir:
        target_path = Path(tmp_dir) / "test.com"
        target_path.mkdir(parents=True)
        (target_path / "scope-of-work.md").write_text("# Authorized Scope\n## In Scope\n- `test.com`\n", encoding="utf-8")

        with patch("dashboard.server.TARGETS_DIR", Path(tmp_dir)):
            handler = DashboardHandler.__new__(DashboardHandler)

            # Test recon directive with mocked recon execution and mocked offline mode
            with patch("tools.llm_client.LLMClient.is_available", return_value=False):
                with patch("tools.skill_runner.SkillRunner.run_recon_subdomain") as mock_recon:
                    mock_recon.return_value = {"status": "SUCCESS", "subdomains_found": 5, "alive_hosts": 2}
                    res = handler.execute_subagent_chat("test.com", "recon-agent", "Scan subdomains for test.com")
                    assert res["status"] == "fallback"
                    assert res["fallback_used"] is True
                    assert res["source"] == "deterministic_fallback"
                    assert res["provider"] == "deterministic-fallback"
                    assert "RECON-AGENT" in res["message"]
                    assert "Subdomain Enumeration Directive Executed" in res["message"]
                    assert "LLM UNAVAILABLE — DETERMINISTIC FALLBACK" in res["message"]

            # Verify conversation was stored
            store = ConversationStore(target_path)
            history = store.read("recon-agent")
            assert len(history) == 2
            assert history[0]["role"] == "user"
            assert history[1]["role"] == "assistant"
            assert history[1].get("source") == "deterministic_fallback"

            # Verify agent session was recorded in RunManager
            rm = RunManager(target_path)
            latest_run = rm.get_latest_or_active_run()
            assert latest_run is not None
            sessions = rm.list_agent_sessions(latest_run["run_id"])
            assert any(s["agent_id"] == "recon-agent" for s in sessions)


def test_execute_subagent_chat_successful_plain_text():
    with tempfile.TemporaryDirectory() as tmp_dir:
        target_path = Path(tmp_dir) / "test.com"
        target_path.mkdir(parents=True)
        (target_path / "scope-of-work.md").write_text("# Authorized Scope\n## In Scope\n- `test.com`\n", encoding="utf-8")

        with patch("dashboard.server.TARGETS_DIR", Path(tmp_dir)):
            handler = DashboardHandler.__new__(DashboardHandler)

            with patch("tools.llm_client.LLMClient.is_available", return_value=True), \
                 patch("tools.llm_client.LLMClient.complete", return_value="PONG"):
                res = handler.execute_subagent_chat("test.com", "coordinator", "Connectivity check only. Reply exactly PONG if you can answer.")
                assert res["status"] == "success"
                assert res["fallback_used"] is False
                assert res["source"] == "llm"
                assert res["message"] == "PONG"

            history = ConversationStore(target_path).read("coordinator")
            assert [item["role"] for item in history] == ["user", "assistant"]
            assert history[0]["content"].startswith("Connectivity check only.")
            assert history[1]["content"] == "PONG"


def test_dashboard_conversation_hides_legacy_runtime_duplicates():
    history = [
        {"role": "user", "content": "PONG?", "source": "dashboard"},
        {"role": "system", "content": "internal prompt", "run_id": "run-1"},
        {"role": "user", "content": "PONG?", "run_id": "run-1"},
        {"role": "assistant", "content": "PONG", "step": 1, "run_id": "run-1"},
        {"role": "assistant", "content": "PONG", "source": "llm", "model": "gemini"},
    ]

    visible = DashboardHandler._dashboard_conversation_messages(history)

    assert [(item["role"], item["content"]) for item in visible] == [
        ("user", "PONG?"),
        ("assistant", "PONG"),
    ]


def test_execute_subagent_chat_ping_failure_explicit_fallback():
    with tempfile.TemporaryDirectory() as tmp_dir:
        target_path = Path(tmp_dir) / "test.com"
        target_path.mkdir(parents=True)
        (target_path / "scope-of-work.md").write_text("# Authorized Scope\n## In Scope\n- `test.com`\n", encoding="utf-8")

        with patch("dashboard.server.TARGETS_DIR", Path(tmp_dir)):
            handler = DashboardHandler.__new__(DashboardHandler)

            # When LLM raises error during ping
            with patch("tools.llm_client.LLMClient.is_available", return_value=True), \
                 patch("tools.llm_client.LLMClient.complete", return_value=None):
                res = handler.execute_subagent_chat("test.com", "coordinator", "Connectivity check only. Reply exactly PONG if you can answer.")
                assert res["status"] == "fallback"
                assert res["fallback_used"] is True
                assert res["source"] == "deterministic_fallback"
                assert "LLM UNAVAILABLE — DETERMINISTIC FALLBACK" in res["message"]
                assert "ping/connectivity request because the upstream LLM backend is unavailable" in res["message"]
                # Must never return operational briefing pretending to be a valid response
                assert "Operational Briefing" not in res["message"]


def test_llm_config_connection_states():
    handler = DashboardHandler.__new__(DashboardHandler)

    from dashboard.server import llm_runtime_state
    # 1. Offline state (no API key)
    with patch("tools.llm_client.LLMClient.is_available", return_value=False), \
         patch.object(DashboardHandler, "get_llm_config", wraps=handler.get_llm_config):
        llm_runtime_state["model_responding"] = False
        llm_runtime_state["status"] = "offline"
        cfg = handler.get_llm_config()
        assert cfg["connection_state"] == "offline"
        assert cfg["model_responding"] is False

    # 2. Configured state (key saved, but untested)
    with patch("tools.llm_client.LLMClient.is_available", return_value=True), \
         patch("tools.llm_client.LLMClient.complete", return_value=None):
        llm_runtime_state["model_responding"] = False
        llm_runtime_state["status"] = "configured"
        llm_runtime_state["tested"] = False
        with patch.dict("os.environ", {"GEMINI_API_KEY": "dummy_test_key_12345"}):
            cfg = handler.get_llm_config()
            assert cfg["connection_state"] == "configured"
            assert cfg["model_responding"] is False

    # 3. Connected state (model responded)
    llm_runtime_state["model_responding"] = True
    llm_runtime_state["status"] = "connected"
    with patch.dict("os.environ", {"GEMINI_API_KEY": "dummy_test_key_12345"}):
        cfg = handler.get_llm_config()
        assert cfg["connection_state"] == "connected"
        assert cfg["model_responding"] is True
