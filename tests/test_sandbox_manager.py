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

    def test_docker_sandbox_accepts_extra_env_and_scrubs_secrets(self):
        sb = create_sandbox(
            "docker",
            extra_env={"OPENAI_API_KEY": "sk-bad", "MOROS_IN_SCOPE": "example.com"},
            scrub_secrets=True,
        )
        assert isinstance(sb, DockerSandbox)
        assert sb._extra_env["MOROS_IN_SCOPE"] == "example.com"


class TestCustomSkillSandboxIntegration:
    def test_run_custom_skill_scrubs_secrets_and_preserves_moros_env(self, tmp_path, monkeypatch):
        import json
        import skill_registry
        from skill_runner import SkillRunner

        skills_dir = tmp_path / "skills"
        skill_dir = skills_dir / "env-audit-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# Env Audit Skill\n", encoding="utf-8")
        (skill_dir / "run.py").write_text(
            "import argparse, json, os\n"
            "from pathlib import Path\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--target'); p.add_argument('--target-dir'); p.add_argument('--output-dir')\n"
            "a = p.parse_args()\n"
            "out = Path(a.output_dir) / 'findings' / 'candidates-env-audit-skill.json'\n"
            "out.parent.mkdir(parents=True, exist_ok=True)\n"
            "finding = {\n"
            "  'title': 'Env Check',\n"
            "  'url': f'https://{a.target}/check',\n"
            "  'gemini_present': 'GEMINI_API_KEY' in os.environ,\n"
            "  'openai_present': 'OPENAI_API_KEY' in os.environ,\n"
            "  'remaining': os.environ.get('MOROS_HTTP_REQUESTS_REMAINING'),\n"
            "  'delay': os.environ.get('MOROS_REQUEST_DELAY'),\n"
            "  'in_scope': os.environ.get('MOROS_IN_SCOPE'),\n"
            "  'out_of_scope': os.environ.get('MOROS_OUT_OF_SCOPE'),\n"
            "}\n"
            "out.write_text(json.dumps({'findings': [finding]}), encoding='utf-8')\n",
            encoding="utf-8",
        )

        monkeypatch.setattr(skill_registry, "SKILLS_DIR", skills_dir)
        monkeypatch.setenv("GEMINI_API_KEY", "AIza-secret-gemini-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-openai-key")
        monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "7")
        monkeypatch.setenv("MOROS_REQUEST_DELAY", "0.25")
        monkeypatch.setenv("MOROS_IN_SCOPE", "*.example.com")
        monkeypatch.setenv("MOROS_OUT_OF_SCOPE", "blog.example.com")

        target_dir = tmp_path / "target"
        target_dir.mkdir()
        runner = SkillRunner("example.com", target_dir)
        res = runner.run_custom_skill("env-audit-skill")

        assert res["status"] == "COMPLETED"
        assert res["findings_count"] == 1
        data = json.loads(
            (target_dir / "output" / "findings" / "candidates-env-audit-skill.json").read_text(encoding="utf-8")
        )
        recorded = data["findings"][0]
        assert recorded["gemini_present"] is False
        assert recorded["openai_present"] is False
        assert recorded["remaining"] == "7"
        assert recorded["delay"] == "0.25"
        assert recorded["in_scope"] == "*.example.com"
        assert recorded["out_of_scope"] == "blog.example.com"
        assert (target_dir / "output" / "evidence" / "ledger.jsonl").is_file()
