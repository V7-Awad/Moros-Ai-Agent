#!/usr/bin/env python3
"""Tests for sandbox_manager.py — Sandbox Abstraction."""

import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from sandbox_manager import (
    LocalSandbox, DockerSandbox, E2BSandbox, ModalSandbox,
    SandboxResult, build_scrubbed_env, create_sandbox,
)


class TestScrubbedEnv:
    def test_removes_llm_and_cloud_keys(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-12345")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSecret12345")
        monkeypatch.setenv("MOROS_TARGET", "example.com")

        env = build_scrubbed_env({"CUSTOM_VAR": "ok"})
        assert "OPENAI_API_KEY" not in env
        assert "GEMINI_API_KEY" not in env
        assert env["MOROS_TARGET"] == "example.com"
        assert env["CUSTOM_VAR"] == "ok"


class TestLocalSandbox:
    def test_context_manager_creates_and_cleans_workspace(self):
        with LocalSandbox() as sb:
            ws = sb.workspace
            assert ws is not None
            assert ws.exists()
            res = sb.run_command([sys.executable, "-c", "print('moros_ok')"])
            assert res.exit_code == 0
            assert "moros_ok" in res.stdout
            assert res.backend == "local"
        assert not ws.exists()

    def test_timeout_enforced(self):
        with LocalSandbox() as sb:
            res = sb.run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
            assert res.timed_out is True
            assert res.exit_code == -1

    def test_env_scrubbed_inside_sandbox(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-should-not-leak")
        with LocalSandbox(scrub_secrets=True) as sb:
            res = sb.run_command([sys.executable, "-c", "import os; print('KEY=' + os.environ.get('DEEPSEEK_API_KEY', 'MISSING'))"])
            assert "KEY=MISSING" in res.stdout


class TestSandboxFactoryAndAdapters:
    def test_create_auto_defaults_to_local(self, monkeypatch):
        monkeypatch.delenv("E2B_API_KEY", raising=False)
        monkeypatch.delenv("MODAL_TOKEN_ID", raising=False)
        sb = create_sandbox("auto")
        assert isinstance(sb, LocalSandbox)

    def test_explicit_e2b_without_key_raises(self, monkeypatch):
        monkeypatch.delenv("E2B_API_KEY", raising=False)
        sb = create_sandbox("e2b")
        with pytest.raises(RuntimeError, match="E2B_API_KEY"):
            sb.start()

    def test_explicit_modal_without_key_raises(self, monkeypatch):
        monkeypatch.delenv("MODAL_TOKEN_ID", raising=False)
        sb = create_sandbox("modal")
        with pytest.raises(RuntimeError, match="MODAL_TOKEN_ID"):
            sb.start()

    def test_unsupported_backend_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            create_sandbox("firecracker-unknown")

    def test_result_to_dict(self):
        r = SandboxResult(exit_code=0, stdout="hi", stderr="", duration_ms=12.34, backend="local")
        d = r.to_dict()
        assert d["exit_code"] == 0
        assert d["duration_ms"] == 12.3
