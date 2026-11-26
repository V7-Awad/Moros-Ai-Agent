"""Validation tests for containerization and CI configuration files."""

from pathlib import Path
import shlex
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_dockerignore_entries(path: Path) -> list[str]:
    """Return non-empty, non-comment pattern lines from a .dockerignore file."""
    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def _parse_dockerfile_instructions(path: Path) -> list[tuple[str, str]]:
    """Parse Dockerfile instructions while joining line continuations."""
    instructions: list[tuple[str, str]] = []
    buffer = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1].rstrip() + " "
            continue
        full_line = (buffer + stripped).strip()
        buffer = ""
        if not full_line or full_line.startswith("#"):
            continue
        parts = full_line.split(None, 1)
        directive = parts[0].upper()
        value = parts[1].strip() if len(parts) > 1 else ""
        instructions.append((directive, value))
    if buffer.strip():
        parts = buffer.strip().split(None, 1)
        instructions.append((parts[0].upper(), parts[1].strip() if len(parts) > 1 else ""))
    return instructions


def _normalize_command(cmd) -> list[str]:
    """Normalize a string or list Docker Compose command into argument tokens."""
    if isinstance(cmd, list):
        return [str(part) for part in cmd]
    if isinstance(cmd, str):
        return shlex.split(cmd)
    return []


def test_devops_files_exist():
    """All required DevOps and CI configuration files must exist and be non-empty."""
    expected = [
        REPO_ROOT / "Dockerfile",
        REPO_ROOT / "docker-compose.yml",
        REPO_ROOT / ".dockerignore",
        REPO_ROOT / ".github" / "workflows" / "ci.yml",
    ]
    for path in expected:
        assert path.is_file(), f"Missing required DevOps file: {path}"
        assert path.read_text(encoding="utf-8").strip(), f"DevOps file is empty: {path}"


def test_dockerignore_excludes_sensitive_and_runtime_files():
    """Verify .dockerignore excludes secrets, git history, caches, targets, and PDFs."""
    entries = _read_dockerignore_entries(REPO_ROOT / ".dockerignore")
    normalized = {entry.rstrip("/") for entry in entries}

    required_patterns = {
        ".git",
        ".env",
        ".env.*",
        "!.env.example",
        "targets/*",
        "!targets/.gitkeep",
        "__pycache__",
        ".pytest_cache",
        "*.pyc",
        "_ref",
        "docs/*.pdf",
    }
    missing = required_patterns - normalized
    assert not missing, f".dockerignore missing required patterns: {sorted(missing)}"
    assert "!.env" not in normalized, ".dockerignore must never un-ignore .env"


def test_dockerfile_non_root_and_runtime_defaults():
    """Verify Dockerfile uses python:3.11-slim, non-root user moros, port 8080, and help CMD."""
    instructions = _parse_dockerfile_instructions(REPO_ROOT / "Dockerfile")
    directives = {name for name, _ in instructions}

    from_values = [val for name, val in instructions if name == "FROM"]
    assert from_values == ["python:3.11-slim"], f"Expected FROM python:3.11-slim, got {from_values}"

    workdir_values = [val for name, val in instructions if name == "WORKDIR"]
    assert "/app" in workdir_values

    run_commands = "\n".join(val for name, val in instructions if name == "RUN")
    assert "requirements.txt" in run_commands
    assert "pip install" in run_commands
    assert "INSTALL_PLAYWRIGHT_BROWSERS" in "\n".join(
        val for name, val in instructions if name in {"ARG", "RUN"}
    )

    user_values = [val for name, val in instructions if name == "USER"]
    assert user_values, "Dockerfile must specify a non-root USER"
    final_user = user_values[-1].split(":")[0].strip()
    assert final_user == "moros" and final_user not in {"root", "0"}

    expose_values = [val for name, val in instructions if name == "EXPOSE"]
    assert any("8080" in val.split() for val in expose_values)

    cmd_values = [val for name, val in instructions if name == "CMD"]
    assert cmd_values, "Dockerfile must define a default CMD"
    assert '"run.py"' in cmd_values[-1] and '"--help"' in cmd_values[-1]
    assert {"ARG", "COPY", "USER", "EXPOSE", "CMD"}.issubset(directives)


def test_docker_compose_parses_and_configures_services():
    """Verify docker-compose.yml parses cleanly and defines dashboard + scanner services."""
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert isinstance(compose, dict)
    services = compose.get("services")
    assert isinstance(services, dict)
    assert {"dashboard", "scanner"}.issubset(services.keys())

    dashboard = services["dashboard"]
    assert "127.0.0.1:8080:8080" in [str(p) for p in dashboard.get("ports", [])]
    dash_cmd = _normalize_command(dashboard.get("command"))
    assert dash_cmd[:2] == ["python", "dashboard.py"]
    assert "--host" in dash_cmd and "0.0.0.0" in dash_cmd
    assert "--port" in dash_cmd and "8080" in dash_cmd
    assert "--no-open" in dash_cmd
    assert "./targets:/app/targets" in [str(v) for v in dashboard.get("volumes", [])]

    env_files = dashboard.get("env_file", [])
    assert any(
        (item == ".env") or (isinstance(item, dict) and item.get("path") == ".env" and item.get("required") is False)
        for item in env_files
    ), "dashboard should configure optional .env via env_file"

    env_items = dashboard.get("environment", [])
    if isinstance(env_items, dict):
        assert "MOROS_DASHBOARD_TOKEN" in env_items
    else:
        assert any("MOROS_DASHBOARD_TOKEN" in str(item) for item in env_items)

    scanner = services["scanner"]
    assert "cli" in scanner.get("profiles", [])
    assert "./targets:/app/targets" in [str(v) for v in scanner.get("volumes", [])]
    scanner_cmd = _normalize_command(scanner.get("command"))
    assert "run.py" in scanner_cmd


def test_github_actions_ci_workflow_valid():
    """Verify .github/workflows/ci.yml triggers on main, runs Python >=3.10 matrix, and runs pytest."""
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    assert isinstance(workflow, dict)

    # PyYAML parses unquoted `on:` as boolean True under YAML 1.1 rules.
    triggers = workflow.get("on") if "on" in workflow else workflow.get(True)
    assert isinstance(triggers, dict)
    assert "main" in triggers.get("push", {}).get("branches", [])
    assert "main" in triggers.get("pull_request", {}).get("branches", [])

    jobs = workflow.get("jobs", {})
    assert jobs, "CI workflow must define at least one job"
    test_job = next(iter(jobs.values()))
    versions = test_job["strategy"]["matrix"]["python-version"]
    assert len(versions) >= 2
    parsed_versions = [tuple(int(part) for part in str(v).split(".")[:2]) for v in versions]
    assert all(ver >= (3, 10) for ver in parsed_versions)
    assert (3, 10) in parsed_versions and (3, 12) in parsed_versions

    run_scripts = "\n".join(str(step.get("run", "")) for step in test_job.get("steps", []))
    assert "requirements.txt" in run_scripts
    assert "compileall" in run_scripts or "py_compile" in run_scripts
    assert "run.py --check" in run_scripts
    assert "run.py --list-skills" in run_scripts
    assert "pytest tests/" in run_scripts
