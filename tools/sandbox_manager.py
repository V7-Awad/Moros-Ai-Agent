#!/usr/bin/env python3
"""
sandbox_manager.py — Execution Sandbox Abstraction for Moros.

Provides a uniform sandbox interface for isolated command/script execution:
- LocalSandbox: Isolated temporary workspace with scrubbed environment variables
  and strict subprocess timeout enforcement.
- DockerSandbox: Containerized isolation when Docker daemon is available.
- E2BSandbox / ModalSandbox: Cloud microVM adapter stubs that check SDK and
  API credentials and fail explicitly rather than falling back silently.
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sandbox-manager")

# Environment variables stripped before untrusted or skill subprocess execution.
_SENSITIVE_ENV_PREFIXES = (
    "OPENAI_", "ANTHROPIC_", "GEMINI_", "DEEPSEEK_", "GROQ_",
    "OPENROUTER_", "XAI_", "MISTRAL_", "TOGETHER_", "CEREBRAS_",
    "SAMBANOVA_", "FIREWORKS_", "PERPLEXITY_", "COHERE_",
    "AWS_", "AZURE_", "GCP_", "E2B_", "MODAL_",
)


@dataclass
class SandboxResult:
    """Standard execution result returned by any sandbox backend."""
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    backend: str
    timed_out: bool = False
    artifacts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": round(self.duration_ms, 1),
            "backend": self.backend,
            "timed_out": self.timed_out,
            "artifacts": self.artifacts,
        }


class BaseSandbox(ABC):
    """Abstract sandbox execution interface."""

    backend_name: str = "base"

    @abstractmethod
    def start(self) -> None:
        """Initialize the sandbox environment."""

    @abstractmethod
    def run_command(self, command: List[str], timeout: int = 60,
                    cwd: Optional[str] = None) -> SandboxResult:
        """Execute a command inside the sandbox."""

    @abstractmethod
    def stop(self) -> None:
        """Clean up sandbox resources."""

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


def build_scrubbed_env(extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a copy of os.environ with LLM/cloud secrets removed."""
    clean = {}
    for k, v in os.environ.items():
        if any(k.upper().startswith(prefix) for prefix in _SENSITIVE_ENV_PREFIXES):
            continue
        clean[k] = v
    if extra_env:
        clean.update(extra_env)
    return clean


class LocalSandbox(BaseSandbox):
    """
    Isolated local temporary workspace with scrubbed environment variables
    and deterministic timeout enforcement.
    """

    backend_name = "local"

    def __init__(self, workspace_dir: Optional[Path] = None,
                 extra_env: Optional[Dict[str, str]] = None,
                 scrub_secrets: bool = True):
        self._explicit_dir = Path(workspace_dir) if workspace_dir else None
        self._temp_dir: Optional[Path] = None
        self._extra_env = extra_env or {}
        self._scrub_secrets = scrub_secrets

    @property
    def workspace(self) -> Optional[Path]:
        return self._explicit_dir or self._temp_dir

    def start(self) -> None:
        if self._explicit_dir:
            self._explicit_dir.mkdir(parents=True, exist_ok=True)
        else:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="moros-sandbox-"))
        logger.debug("LocalSandbox started at %s", self.workspace)

    def run_command(self, command: List[str], timeout: int = 60,
                    cwd: Optional[str] = None) -> SandboxResult:
        if not self.workspace or not self.workspace.exists():
            self.start()

        run_cwd = cwd or str(self.workspace)
        env = build_scrubbed_env(self._extra_env) if self._scrub_secrets else {**os.environ, **self._extra_env}

        started = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                cwd=run_cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration_ms = (time.monotonic() - started) * 1000
            return SandboxResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=duration_ms,
                backend=self.backend_name,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = (time.monotonic() - started) * 1000
            return SandboxResult(
                exit_code=-1,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=f"Command timed out after {timeout}s",
                duration_ms=duration_ms,
                backend=self.backend_name,
                timed_out=True,
            )

    def stop(self) -> None:
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
        logger.debug("LocalSandbox stopped")


class DockerSandbox(BaseSandbox):
    """Docker container sandbox adapter (requires local Docker CLI & daemon)."""

    backend_name = "docker"

    def __init__(self, image: str = "python:3.12-slim", network_disabled: bool = True,
                 memory_limit: str = "512m", cpus: str = "1.0"):
        self.image = image
        self.network_disabled = network_disabled
        self.memory_limit = memory_limit
        self.cpus = cpus
        self._workspace: Optional[Path] = None

    @staticmethod
    def is_available() -> bool:
        return shutil.which("docker") is not None

    def start(self) -> None:
        if not self.is_available():
            raise RuntimeError("Docker CLI is not installed or not on PATH.")
        self._workspace = Path(tempfile.mkdtemp(prefix="moros-docker-"))

    def run_command(self, command: List[str], timeout: int = 60,
                    cwd: Optional[str] = None) -> SandboxResult:
        if not self.is_available():
            raise RuntimeError("Docker CLI is not installed or not on PATH.")
        if not self._workspace:
            self.start()

        docker_cmd = [
            "docker", "run", "--rm",
            "--memory", self.memory_limit,
            "--cpus", self.cpus,
            "--read-only",
            "-v", f"{self._workspace}:/workspace:rw",
            "-w", "/workspace",
        ]
        if self.network_disabled:
            docker_cmd.extend(["--network", "none"])
        docker_cmd.append(self.image)
        docker_cmd.extend(command)

        started = time.monotonic()
        try:
            proc = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=timeout)
            return SandboxResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=(time.monotonic() - started) * 1000,
                backend=self.backend_name,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                exit_code=-1, stdout="",
                stderr=f"Docker execution timed out after {timeout}s",
                duration_ms=(time.monotonic() - started) * 1000,
                backend=self.backend_name, timed_out=True,
            )

    def stop(self) -> None:
        if self._workspace and self._workspace.exists():
            shutil.rmtree(self._workspace, ignore_errors=True)
            self._workspace = None


class E2BSandbox(BaseSandbox):
    """Cloud microVM adapter for E2B (requires E2B_API_KEY and e2b package)."""

    backend_name = "e2b"

    def __init__(self, api_key: Optional[str] = None, template: str = "base"):
        self.api_key = api_key or os.environ.get("E2B_API_KEY", "").strip()
        self.template = template
        self._sandbox = None

    @staticmethod
    def is_configured() -> bool:
        return bool(os.environ.get("E2B_API_KEY", "").strip())

    def start(self) -> None:
        if not self.api_key:
            raise RuntimeError("E2B_API_KEY is not configured; cannot start cloud microVM.")
        try:
            from e2b_code_interpreter import Sandbox  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "e2b-code-interpreter SDK is not installed. Run: pip install e2b-code-interpreter"
            ) from exc
        self._sandbox = Sandbox(template=self.template, api_key=self.api_key)

    def run_command(self, command: List[str], timeout: int = 60,
                    cwd: Optional[str] = None) -> SandboxResult:
        if not self._sandbox:
            self.start()
        started = time.monotonic()
        cmd_str = " ".join(command)
        proc = self._sandbox.commands.run(cmd_str, timeout=timeout)
        return SandboxResult(
            exit_code=getattr(proc, "exit_code", 0),
            stdout=getattr(proc, "stdout", ""),
            stderr=getattr(proc, "stderr", ""),
            duration_ms=(time.monotonic() - started) * 1000,
            backend=self.backend_name,
        )

    def stop(self) -> None:
        if self._sandbox and hasattr(self._sandbox, "kill"):
            try:
                self._sandbox.kill()
            except Exception:
                pass
        self._sandbox = None


class ModalSandbox(BaseSandbox):
    """Cloud serverless sandbox adapter for Modal (requires MODAL_TOKEN_ID and modal package)."""

    backend_name = "modal"

    def __init__(self, image_name: str = "debian_slim"):
        self.image_name = image_name
        self._app = None

    @staticmethod
    def is_configured() -> bool:
        return bool(
            os.environ.get("MODAL_TOKEN_ID", "").strip()
            and os.environ.get("MODAL_TOKEN_SECRET", "").strip()
        )

    def start(self) -> None:
        if not self.is_configured():
            raise RuntimeError("MODAL_TOKEN_ID / MODAL_TOKEN_SECRET are not configured.")
        try:
            import modal  # type: ignore
        except ImportError as exc:
            raise RuntimeError("modal SDK is not installed. Run: pip install modal") from exc
        self._app = modal.App.lookup("moros-sandbox", create_if_missing=True)

    def run_command(self, command: List[str], timeout: int = 60,
                    cwd: Optional[str] = None) -> SandboxResult:
        if not self._app:
            self.start()
        import modal  # type: ignore
        started = time.monotonic()
        sb = modal.Sandbox.create(*command, app=self._app, timeout=timeout)
        sb.wait()
        return SandboxResult(
            exit_code=sb.returncode or 0,
            stdout=sb.stdout.read(),
            stderr=sb.stderr.read(),
            duration_ms=(time.monotonic() - started) * 1000,
            backend=self.backend_name,
        )

    def stop(self) -> None:
        self._app = None


def create_sandbox(backend: str = "auto", **kwargs) -> BaseSandbox:
    """
    Factory returning the requested sandbox backend.
    In 'auto' mode, uses E2B if configured, else Modal if configured, else LocalSandbox.
    Explicit cloud backends raise if credentials/SDKs are missing.
    """
    choice = (backend or "auto").lower().strip()
    if choice == "auto":
        if E2BSandbox.is_configured():
            try:
                import e2b_code_interpreter  # noqa: F401
                return E2BSandbox(**kwargs)
            except ImportError:
                pass
        if ModalSandbox.is_configured():
            try:
                import modal  # noqa: F401
                return ModalSandbox(**kwargs)
            except ImportError:
                pass
        return LocalSandbox(**kwargs)
    if choice == "local":
        return LocalSandbox(**kwargs)
    if choice == "docker":
        return DockerSandbox(**kwargs)
    if choice == "e2b":
        return E2BSandbox(**kwargs)
    if choice == "modal":
        return ModalSandbox(**kwargs)
    raise ValueError(f"Unsupported sandbox backend: {backend}")
