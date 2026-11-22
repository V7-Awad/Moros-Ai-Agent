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

            assert len(roster) == 8
            # In Moros AI, subagents are autonomous active specialists, not CHAT_ONLY
            for agent in roster:
                assert agent["status"] in ("ACTIVE", "READY")
                assert "CHAT_ONLY" not in agent["status"]


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
        (target_path / "scope.md").write_text("# Authorized Scope\n*.test.com", encoding="utf-8")

        with patch("dashboard.server.TARGETS_DIR", Path(tmp_dir)):
            handler = DashboardHandler.__new__(DashboardHandler)

            # Test recon directive with mocked recon execution and mocked offline mode
            with patch("tools.llm_client.LLMClient.is_available", return_value=False):
                with patch("tools.skill_runner.SkillRunner.run_recon_subdomain") as mock_recon:
                    mock_recon.return_value = {"status": "SUCCESS", "subdomains_found": 5, "alive_hosts": 2}
                    res = handler.execute_subagent_chat("test.com", "recon-agent", "Scan subdomains for test.com")
                    assert res["status"] == "success"
                    assert "RECON-AGENT" in res["message"]
                    assert "Subdomain Enumeration Directive Executed" in res["message"]

            # Verify conversation was stored
            store = ConversationStore(target_path)
            history = store.read("recon-agent")
            assert len(history) == 2
            assert history[0]["role"] == "user"
            assert history[1]["role"] == "assistant"

            # Verify agent session was recorded in RunManager
            rm = RunManager(target_path)
            latest_run = rm.get_latest_or_active_run()
            assert latest_run is not None
            sessions = rm.list_agent_sessions(latest_run["run_id"])
            assert any(s["agent_id"] == "recon-agent" for s in sessions)
