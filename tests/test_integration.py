import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()


def test_dry_run_exits_cleanly(tmp_path):
    """Test that --dry-run shows plan and exits 0."""
    target_dir = tmp_path / "targets" / "test.local"
    target_dir.mkdir(parents=True)
    (target_dir / "scope-of-work.md").write_text(
        "# Scope\nAuthorized testing of test.local\n## In Scope\n- test.local",
        encoding="utf-8"
    )
    (target_dir / "output").mkdir()

    result = subprocess.run(
        [sys.executable, "run.py", "--target", "test.local",
         "--target-dir", str(target_dir), "--dry-run"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT)
    )
    assert result.returncode == 0
    assert "DRY RUN" in result.stdout


def test_active_scan_is_blocked_without_configured_model(tmp_path):
    target_dir = tmp_path / "targets" / "test.local"
    target_dir.mkdir(parents=True)
    (target_dir / "scope-of-work.md").write_text(
        "# Scope\nAuthorized testing of test.local\n## In Scope\n- test.local",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["MOROS_LLM_PROVIDER"] = "none"
    for key in ("OPENAI_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY"):
        env.pop(key, None)

    result = subprocess.run(
        [sys.executable, "run.py", "--target", "test.local", "--target-dir", str(target_dir),
         "--skills", "recon-subdomain"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        env=env,
    )
    assert result.returncode == 2
    assert "Scan blocked: no LLM provider is configured" in result.stderr


def test_list_skills():
    """Test that --list-skills lists available skills and exits 0."""
    result = subprocess.run(
        [sys.executable, "run.py", "--list-skills"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT)
    )
    assert result.returncode == 0
    assert "recon-subdomain" in result.stdout
    assert "Total:" in result.stdout


def test_check_prerequisites():
    """Test that --check runs without crashing."""
    result = subprocess.run(
        [sys.executable, "run.py", "--check"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT)
    )
    assert result.returncode in (0, 1)


def test_init_target_creates_scope_files(tmp_path, monkeypatch):
    """Test setup.py init-target generates scope.json and scope-of-work.md."""
    from setup import init_target
    test_domain = "integration-verify.local"
    target_dir = PROJECT_ROOT / "targets" / test_domain
    try:
        init_target(test_domain)
        assert target_dir.is_dir()
        scope_json = target_dir / "scope.json"
        scope_md = target_dir / "scope-of-work.md"
        assert scope_json.is_file()
        assert scope_md.is_file()

        data = json.loads(scope_json.read_text(encoding="utf-8"))
        assert data["target"] == test_domain
        assert test_domain in data["in_scope"]
    finally:
        # Cleanup
        if target_dir.exists():
            import shutil
            shutil.rmtree(target_dir, ignore_errors=True)
