#!/usr/bin/env python3
"""
llm_client.py — Universal LLM Client for Moros AI Agent.

Supports multi-model / multi-tier execution as specified in Section 7 of the build plan:
- Frontier tier: Claude (Anthropic), GPT-4o (OpenAI)
- Mid-tier: Claude Sonnet, GPT-4o-mini
- Local / Open-weight: Ollama, vLLM, OpenRouter, Local OpenCode gateways

Uses standard urllib for zero-dependency HTTP requests.
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger("llm-client")


def redact_secrets(text: Optional[str]) -> str:
    """Redact sensitive API keys, tokens, and authorization headers from text."""
    if not text:
        return ""
    text = str(text)
    # Redact Google API keys (AIzaSy...)
    text = re.sub(r"AIza[0-9A-Za-z-_]{30,45}", "[REDACTED_API_KEY]", text)
    # Redact OpenAI / Anthropic / general secret keys
    text = re.sub(r"\b(sk-[a-zA-Z0-9_\-\.]{20,})\b", "[REDACTED_API_KEY]", text)
    # Redact query string API keys: ?key=... or &api_key=...
    text = re.sub(r"([?&](?:key|api_key|token|auth)=)[^&\s'\"]+", r"\g<1>[REDACTED]", text, flags=re.IGNORECASE)
    # Redact Bearer tokens in headers or text
    text = re.sub(r"\bBearer\s+[A-Za-z0-9_\-\.]{10,}\b", "Bearer [REDACTED]", text, flags=re.IGNORECASE)
    # Redact authorization / API key headers
    text = re.sub(r"((?:x-goog-api-key|x-api-key):\s*)[^\r\n,;'\"]+", r"\g<1>[REDACTED]", text, flags=re.IGNORECASE)
    text = re.sub(r"(authorization:\s*)(?:Basic|Token)\s+[^\r\n,;'\"]+", r"\g<1>[REDACTED]", text, flags=re.IGNORECASE)
    # Check loaded environment variables for any other configured keys
    for var in (
        "GEMINI_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "XAI_API_KEY",
        "MISTRAL_API_KEY",
        "TOGETHER_API_KEY",
        "CEREBRAS_API_KEY",
        "SAMBANOVA_API_KEY",
        "FIREWORKS_API_KEY",
        "PERPLEXITY_API_KEY",
        "COHERE_API_KEY",
        "DISCORD_WEBHOOK_URL",
        "TELEGRAM_BOT_TOKEN",
        "SLACK_WEBHOOK_URL",
    ):
        val = os.environ.get(var, "").strip()
        if val and len(val) >= 8 and val in text:
            text = text.replace(val, "[REDACTED_API_KEY]")
    return text


def load_dotenv_if_present():
    """Load key-value pairs from .env in project root if present, without external dependencies."""
    project_root = Path(__file__).parent.parent.resolve()
    env_paths = [project_root / ".env", Path.cwd() / ".env"]
    for env_path in env_paths:
        if env_path.is_file():
            try:
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass


KNOWN_PROVIDERS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "env_key": "DEEPSEEK_API_KEY",
        "env_model": "DEEPSEEK_MODEL",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
        "env_model": "OPENAI_MODEL",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-3-5-sonnet-20241022",
        "env_key": "ANTHROPIC_API_KEY",
        "env_model": "ANTHROPIC_MODEL",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "env_key": "GROQ_API_KEY",
        "env_model": "GROQ_MODEL",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com",
        "default_model": "gemini-3.8-flash",
        "env_key": "GEMINI_API_KEY",
        "env_model": "GEMINI_MODEL",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "meta-llama/llama-3.1-8b-instruct",
        "env_key": "OPENROUTER_API_KEY",
        "env_model": "OPENROUTER_MODEL",
    },
    "xai": {
        "base_url": "https://api.x.ai/v1",
        "default_model": "grok-2-latest",
        "env_key": "XAI_API_KEY",
        "env_model": "XAI_MODEL",
    },
    "grok": {
        "base_url": "https://api.x.ai/v1",
        "default_model": "grok-2-latest",
        "env_key": "XAI_API_KEY",
        "env_model": "XAI_MODEL",
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-large-latest",
        "env_key": "MISTRAL_API_KEY",
        "env_model": "MISTRAL_MODEL",
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "env_key": "TOGETHER_API_KEY",
        "env_model": "TOGETHER_MODEL",
    },
    "cerebras": {
        "base_url": "https://api.cerebras.ai/v1",
        "default_model": "llama3.3-70b",
        "env_key": "CEREBRAS_API_KEY",
        "env_model": "CEREBRAS_MODEL",
    },
    "sambanova": {
        "base_url": "https://api.sambanova.ai/v1",
        "default_model": "Meta-Llama-3.3-70B-Instruct",
        "env_key": "SAMBANOVA_API_KEY",
        "env_model": "SAMBANOVA_MODEL",
    },
    "fireworks": {
        "base_url": "https://api.fireworks.ai/inference/v1",
        "default_model": "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "env_key": "FIREWORKS_API_KEY",
        "env_model": "FIREWORKS_MODEL",
    },
    "perplexity": {
        "base_url": "https://api.perplexity.ai",
        "default_model": "sonar-pro",
        "env_key": "PERPLEXITY_API_KEY",
        "env_model": "PERPLEXITY_MODEL",
    },
    "cohere": {
        "base_url": "https://api.cohere.com/v2",
        "default_model": "command-r-plus",
        "env_key": "COHERE_API_KEY",
        "env_model": "COHERE_MODEL",
    },
    "ollama": {
        "base_url": "http://localhost:11434",
        "default_model": "llama3",
        "env_key": "",
        "env_model": "OLLAMA_MODEL",
    },
}

PROVIDER_PRIORITY_ORDER = [
    "deepseek",
    "groq",
    "openai",
    "anthropic",
    "gemini",
    "openrouter",
    "xai",
    "mistral",
    "together",
    "cerebras",
    "sambanova",
    "fireworks",
    "perplexity",
    "cohere",
    "ollama",
]


class LLMClient:
    def __init__(
        self,
        provider: str = "auto",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        fallback_providers: Optional[List[str]] = None,
        enable_failover: Optional[bool] = None,
    ):
        load_dotenv_if_present()
        self._requested_provider = provider.strip().lower() if provider else "auto"
        self.provider = self._requested_provider
        self._logical_provider = self._requested_provider
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.fallback_providers = (
            [p.strip().lower() for p in fallback_providers if p and str(p).strip()]
            if fallback_providers is not None
            else None
        )
        self.enable_failover = enable_failover
        self.last_error: Optional[str] = None
        self.last_usage: Dict[str, int] = {"input_tokens": 0, "output_tokens": 0}
        self.last_failover_attempts: List[Dict[str, str]] = []
        self._detect_provider()

    def _resolve_provider_settings(
        self,
        selected: str,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        """Resolve (runtime_provider, model, api_key, base_url) for a logical provider."""
        if selected == "anthropic":
            return (
                "anthropic",
                model or os.environ.get("ANTHROPIC_MODEL") or "claude-3-5-sonnet-20241022",
                api_key or os.environ.get("ANTHROPIC_API_KEY"),
                base_url or os.environ.get("ANTHROPIC_BASE_URL") or None,
            )
        if selected == "gemini":
            return (
                "gemini",
                model or os.environ.get("GEMINI_MODEL") or "gemini-3-flash-preview",
                api_key or os.environ.get("GEMINI_API_KEY"),
                base_url or os.environ.get("GEMINI_BASE_URL") or None,
            )
        if selected == "ollama":
            return (
                "ollama",
                model or os.environ.get("OLLAMA_MODEL") or "llama3",
                api_key,
                base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
            )
        if selected in KNOWN_PROVIDERS:
            info = KNOWN_PROVIDERS[selected]
            prov_env_base = os.environ.get(f"{selected.upper()}_BASE_URL")
            if selected == "openai":
                prov_env_base = prov_env_base or os.environ.get("OPENAI_BASE_URL")
            resolved_base = base_url or prov_env_base or info["base_url"]
            resolved_key = (
                api_key
                or os.environ.get(info["env_key"])
                or (os.environ.get("OPENAI_API_KEY") if selected == "openai" else None)
            )
            resolved_model = model or os.environ.get(info["env_model"]) or info["default_model"]
            return ("openai", resolved_model, resolved_key, resolved_base)
        if selected in ["custom", "openai_compatible"] or base_url or os.environ.get("OPENAI_BASE_URL"):
            return (
                "openai",
                model or os.environ.get("OPENAI_MODEL") or os.environ.get("LLM_MODEL") or "default",
                api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY") or "none",
                base_url or os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_BASE_URL") or "http://localhost:1234/v1",
            )
        if selected != "none":
            return (
                "openai",
                model or os.environ.get(f"{selected.upper()}_MODEL") or "default",
                api_key or os.environ.get(f"{selected.upper()}_API_KEY") or os.environ.get("OPENAI_API_KEY"),
                base_url or os.environ.get(f"{selected.upper()}_BASE_URL") or "https://api.openai.com/v1",
            )
        return ("none", model, api_key, base_url)

    def _detect_provider(self):
        """Auto-detect provider based on environment variables or explicit selection."""
        if self.provider == "auto":
            selected = os.environ.get("MOROS_LLM_PROVIDER", "").strip().lower()
            if not selected:
                # Priority auto-detection order
                if os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_BASE_URL"):
                    selected = "custom"
                elif os.environ.get("DEEPSEEK_API_KEY"):
                    selected = "deepseek"
                elif os.environ.get("GROQ_API_KEY"):
                    selected = "groq"
                elif os.environ.get("OPENAI_API_KEY"):
                    selected = "openai"
                elif os.environ.get("ANTHROPIC_API_KEY"):
                    selected = "anthropic"
                elif os.environ.get("GEMINI_API_KEY"):
                    selected = "gemini"
                elif os.environ.get("OPENROUTER_API_KEY"):
                    selected = "openrouter"
                elif os.environ.get("XAI_API_KEY"):
                    selected = "xai"
                elif os.environ.get("MISTRAL_API_KEY"):
                    selected = "mistral"
                elif os.environ.get("TOGETHER_API_KEY"):
                    selected = "together"
                elif os.environ.get("CEREBRAS_API_KEY"):
                    selected = "cerebras"
                elif os.environ.get("SAMBANOVA_API_KEY"):
                    selected = "sambanova"
                elif os.environ.get("FIREWORKS_API_KEY"):
                    selected = "fireworks"
                elif os.environ.get("PERPLEXITY_API_KEY"):
                    selected = "perplexity"
                elif os.environ.get("COHERE_API_KEY"):
                    selected = "cohere"
                elif os.environ.get("OLLAMA_BASE_URL") or self._check_ollama():
                    selected = "ollama"
                else:
                    selected = "none"

            self.provider = selected

        selected = self.provider
        self._logical_provider = selected
        self.provider, self.model, self.api_key, self.base_url = self._resolve_provider_settings(
            selected, model=self.model, api_key=self.api_key, base_url=self.base_url
        )

    def _check_ollama(self) -> bool:
        """Check if local Ollama daemon is reachable."""
        base = (os.environ.get("OLLAMA_BASE_URL") or "http://localhost:11434").rstrip("/")
        try:
            req = urllib.request.Request(f"{base}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _sanitize_text(self, text: Optional[str], extra_secrets: Optional[List[Optional[str]]] = None) -> str:
        """Redact known secret patterns and any explicit client API keys from text."""
        cleaned = redact_secrets(text)
        candidates = [self.api_key]
        if extra_secrets:
            candidates.extend(extra_secrets)
        for secret in candidates:
            if not secret:
                continue
            val = str(secret).strip()
            if val and val.lower() != "none" and len(val) >= 8 and val in cleaned:
                cleaned = cleaned.replace(val, "[REDACTED_API_KEY]")
        return cleaned

    @staticmethod
    def _extract_http_error_details(exc: urllib.error.HTTPError) -> str:
        """Safely read and extract an error message from an urllib HTTPError."""
        raw_error = ""
        try:
            raw_error = exc.read(4096).decode("utf-8", errors="replace")
        except Exception:
            raw_error = ""
        if raw_error:
            try:
                parsed_error = json.loads(raw_error)
                if isinstance(parsed_error, dict):
                    error = parsed_error.get("error", parsed_error)
                    if isinstance(error, dict):
                        return str(error.get("message") or raw_error)
                    return str(error)
                return str(parsed_error)
            except (json.JSONDecodeError, TypeError, ValueError):
                return raw_error
        return str(getattr(exc, "reason", "") or exc)

    @staticmethod
    def _is_same_provider(a: str, b: str) -> bool:
        a_norm = (a or "").strip().lower()
        b_norm = (b or "").strip().lower()
        if a_norm == b_norm:
            return True
        return {a_norm, b_norm} == {"xai", "grok"}

    def _is_provider_configured(self, cand: str, explicit: bool = False, include_ollama: bool = True) -> bool:
        if cand == "ollama":
            return explicit or (include_ollama and self._check_ollama())
        if cand in KNOWN_PROVIDERS:
            info = KNOWN_PROVIDERS[cand]
            env_key = info.get("env_key", "")
            return bool(env_key and os.environ.get(env_key, "").strip())
        if cand in {"custom", "openai_compatible"}:
            return bool(os.environ.get("OPENAI_BASE_URL", "").strip() or os.environ.get("LLM_BASE_URL", "").strip())
        return bool(
            os.environ.get(f"{cand.upper()}_API_KEY", "").strip()
            or os.environ.get(f"{cand.upper()}_BASE_URL", "").strip()
        )

    def _discover_failover_candidates(self, include_ollama: bool = True) -> List[str]:
        if self._logical_provider == "none":
            return []
        explicit = self.fallback_providers is not None
        source = self.fallback_providers if explicit else PROVIDER_PRIORITY_ORDER
        primary = self._logical_provider

        candidates: List[str] = []
        seen = set()
        for raw in source:
            cand = (raw or "").strip().lower()
            if not cand or cand in {"auto", "none"}:
                continue
            if self._is_same_provider(cand, primary):
                continue
            canonical = "xai" if cand == "grok" else cand
            if canonical in seen:
                continue
            if self._is_provider_configured(cand, explicit=explicit, include_ollama=include_ollama):
                seen.add(canonical)
                candidates.append(cand)
        return candidates

    def _get_failover_candidates(self) -> List[str]:
        """Return configured backup providers in priority order, excluding the primary."""
        return self._discover_failover_candidates(include_ollama=True)

    def _is_failover_enabled(self) -> bool:
        if self._logical_provider == "none":
            return False
        if self.enable_failover is not None:
            return bool(self.enable_failover)
        env_flag = os.environ.get("MOROS_LLM_FAILOVER", "").strip().lower()
        if env_flag in {"0", "false", "no", "off"}:
            return False
        if env_flag in {"1", "true", "yes", "on"}:
            return True
        if self.fallback_providers is not None:
            return len(self.fallback_providers) > 0
        return self._requested_provider == "auto"

    def _resolve_runtime_failover_candidates(self, include_ollama: bool = True) -> List[str]:
        if (
            type(self)._get_failover_candidates is not LLMClient._get_failover_candidates
            or "_get_failover_candidates" in self.__dict__
        ):
            return list(self._get_failover_candidates() or [])
        return self._discover_failover_candidates(include_ollama=include_ollama)

    def is_available(self) -> bool:
        """Return True if an LLM backend is configured and ready."""
        if self._logical_provider == "none" or self.provider == "none":
            return False
        if bool(self.api_key or self.provider == "ollama"):
            return True
        if self._is_failover_enabled():
            return bool(self._resolve_runtime_failover_candidates(include_ollama=False))
        return False

    def _invoke_current_provider(
        self,
        prompt: str,
        system_prompt: str,
        temperature: float,
        max_tokens: int,
        timeout: int,
    ) -> Optional[str]:
        if self.provider in ["openai", "openrouter"]:
            return self._call_openai_compatible(prompt, system_prompt, temperature, max_tokens, timeout=timeout)
        if self.provider == "anthropic":
            return self._call_anthropic(prompt, system_prompt, temperature, max_tokens, timeout=timeout)
        if self.provider == "gemini":
            return self._call_gemini(prompt, system_prompt, temperature, max_tokens, timeout=timeout)
        if self.provider == "ollama":
            return self._call_ollama(prompt, system_prompt, temperature, max_tokens, timeout=timeout)
        return None

    def _finalize_success(
        self,
        res: str,
        prompt: str,
        system_prompt: str,
        extra_secrets: Optional[List[Optional[str]]] = None,
    ) -> str:
        self.last_error = None
        if self.last_usage["input_tokens"] == 0 and self.last_usage["output_tokens"] == 0:
            self.last_usage = {
                "input_tokens": max(1, (len(prompt) + len(system_prompt)) // 4),
                "output_tokens": max(1, len(res) // 4),
            }
        return self._sanitize_text(res, extra_secrets=extra_secrets)

    def complete(self, prompt: str, system_prompt: str = "", temperature: float = 0.2, max_tokens: int = 8192, timeout: Optional[int] = None) -> Optional[str]:
        """Generate text completion from the configured LLM backend, failing over if enabled."""
        self.last_failover_attempts = []
        if not self.is_available():
            logger.debug("No LLM API key configured — skipping model inference.")
            return None

        call_timeout = timeout or getattr(self, "timeout", None) or 20
        self.last_usage = {"input_tokens": 0, "output_tokens": 0}

        original_state = (
            self.provider,
            self._logical_provider,
            self.model,
            self.api_key,
            self.base_url,
        )
        seen_secrets: List[Optional[str]] = [self.api_key]
        primary_label = self._logical_provider or self.provider
        primary_model = str(self.model or "")
        primary_error = ""

        if self.provider == "ollama" or self.api_key:
            try:
                res = self._invoke_current_provider(prompt, system_prompt, temperature, max_tokens, call_timeout)
                if res:
                    return self._finalize_success(res, prompt, system_prompt, extra_secrets=seen_secrets)
                primary_error = f"{primary_label} returned an empty response"
            except Exception as exc:
                primary_error = self._sanitize_text(str(exc), extra_secrets=seen_secrets)[:500]
                logger.warning(f"LLM completion failed ({primary_label}/{self.model}): {primary_error}")
        else:
            primary_error = f"{primary_label} API key not configured"

        self.last_error = primary_error

        if not self._is_failover_enabled():
            return None

        candidates = self._resolve_runtime_failover_candidates(include_ollama=False)
        tried_ollama = self._is_same_provider("ollama", primary_label) or "ollama" in candidates

        if not candidates and not tried_ollama and self.fallback_providers is None:
            if self._check_ollama():
                candidates = ["ollama"]
            tried_ollama = True

        if not candidates:
            return None

        attempts: List[Dict[str, str]] = [
            {
                "provider": primary_label,
                "model": primary_model,
                "status": "failed",
                "error": primary_error,
            }
        ]

        idx = 0
        while idx < len(candidates):
            cand = candidates[idx]
            idx += 1
            cand_runtime, cand_model, cand_key, cand_base = self._resolve_provider_settings(cand)
            if cand_key:
                seen_secrets.append(cand_key)

            self.provider = cand_runtime
            self._logical_provider = cand
            self.model = cand_model
            self.api_key = cand_key
            self.base_url = cand_base
            self.last_usage = {"input_tokens": 0, "output_tokens": 0}

            if cand_runtime != "ollama" and not cand_key:
                cand_err = f"{cand} API key not configured"
                attempts.append({
                    "provider": cand,
                    "model": str(cand_model or ""),
                    "status": "failed",
                    "error": cand_err,
                })
                self.last_error = cand_err
                continue

            try:
                res = self._invoke_current_provider(prompt, system_prompt, temperature, max_tokens, call_timeout)
                if res:
                    attempts.append({
                        "provider": cand,
                        "model": str(self.model or ""),
                        "status": "succeeded",
                        "error": "",
                    })
                    self.last_failover_attempts = attempts
                    logger.info(f"LLM failover succeeded: {primary_label} -> {cand}/{self.model}")
                    return self._finalize_success(res, prompt, system_prompt, extra_secrets=seen_secrets)
                cand_err = f"{cand} returned an empty response"
            except Exception as exc:
                cand_err = self._sanitize_text(str(exc), extra_secrets=seen_secrets)[:500]
                logger.warning(f"LLM failover attempt failed ({cand}/{cand_model}): {cand_err}")

            attempts.append({
                "provider": cand,
                "model": str(cand_model or ""),
                "status": "failed",
                "error": cand_err,
            })
            self.last_error = cand_err

            if idx == len(candidates) and not tried_ollama and self.fallback_providers is None:
                tried_ollama = True
                if self._check_ollama():
                    candidates.append("ollama")

        self.provider, self._logical_provider, self.model, self.api_key, self.base_url = original_state
        self.last_failover_attempts = attempts
        return None

    def _call_openai_compatible(self, prompt: str, system_prompt: str, temperature: float, max_tokens: int, timeout: int = 60) -> str:
        base = self.base_url or ("https://openrouter.ai/api/v1" if self.provider == "openrouter" else "https://api.openai.com/v1")
        url = f"{base.rstrip('/')}/chat/completions"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model or ("gpt-4o-mini" if self.provider == "openai" else "meta-llama/llama-3.1-8b-instruct"),
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if self.provider == "openrouter" or self._logical_provider == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/V7-Awad/Moros-Ai-Agent"
            headers["X-Title"] = "Moros AI Pentest Agent"

        for attempt in range(3):
            try:
                req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                usage = data.get("usage") or {}
                if usage:
                    self.last_usage = {
                        "input_tokens": int(usage.get("prompt_tokens", 0)),
                        "output_tokens": int(usage.get("completion_tokens", 0)),
                    }
                return data["choices"][0]["message"]["content"]
            except urllib.error.HTTPError as exc:
                details = self._sanitize_text(self._extract_http_error_details(exc))
                if exc.code in (429, 503) and attempt < 2:
                    wait = (attempt + 1) * 2
                    logger.warning(f"{self._logical_provider}/{self.model} HTTP {exc.code} ({details[:120]}); retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                raise RuntimeError(f"{self._logical_provider} API HTTP {exc.code}: {details[:300]}") from None
            except (TimeoutError, urllib.error.URLError) as exc:
                exc_msg = self._sanitize_text(str(exc))
                raise RuntimeError(f"{self._logical_provider} connection error: {exc_msg[:200]}") from None

    def _call_anthropic(self, prompt: str, system_prompt: str, temperature: float, max_tokens: int, timeout: int = 60) -> str:
        base = (self.base_url or "https://api.anthropic.com/v1").rstrip("/")
        url = f"{base}/messages"
        payload = {
            "model": self.model or "claude-3-5-sonnet-20241022",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        for attempt in range(3):
            try:
                req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                usage = data.get("usage") or {}
                if usage:
                    self.last_usage = {
                        "input_tokens": int(usage.get("input_tokens", 0)),
                        "output_tokens": int(usage.get("output_tokens", 0)),
                    }
                content = data.get("content") or []
                if isinstance(content, list) and content:
                    texts = [blk.get("text", "") for blk in content if isinstance(blk, dict) and blk.get("text")]
                    if texts:
                        return "\n".join(texts)
                return data["content"][0]["text"]
            except urllib.error.HTTPError as exc:
                details = self._sanitize_text(self._extract_http_error_details(exc))
                if exc.code in (429, 503) and attempt < 2:
                    wait = (attempt + 1) * 2
                    logger.warning(f"anthropic/{self.model} HTTP {exc.code} ({details[:120]}); retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                raise RuntimeError(f"Anthropic API HTTP {exc.code}: {details[:300]}") from None
            except (TimeoutError, urllib.error.URLError) as exc:
                exc_msg = self._sanitize_text(str(exc))
                raise RuntimeError(f"Anthropic connection error: {exc_msg[:200]}") from None

    def _call_gemini(self, prompt: str, system_prompt: str, temperature: float, max_tokens: int, timeout: int = 15) -> str:
        primary_model = self.model or "gemini-3.8-flash"
        # Candidate models to try in order on capacity spikes / deprecation
        candidate_models = [primary_model]
        for fallback in ["gemini-3-flash-preview", "gemini-2.5-flash", "gemini-flash-latest"]:
            if fallback not in candidate_models:
                candidate_models.append(fallback)

        base = (self.base_url or "https://generativelanguage.googleapis.com").rstrip("/")
        url = f"{base}/v1beta/interactions"
        last_exc = None

        for model_name in candidate_models:
            for attempt in range(2):
                payload = {
                    "model": model_name,
                    "input": prompt,
                    "store": False,
                    "generation_config": {
                        "temperature": temperature,
                        "max_output_tokens": max_tokens,
                        "thinking_level": "low",
                    },
                }
                if system_prompt:
                    payload["system_instruction"] = system_prompt

                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "x-goog-api-key": self.api_key,
                    },
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    details = self._sanitize_text(self._extract_http_error_details(exc))
                    if exc.code == 503:
                        logger.warning(f"Gemini {model_name} HTTP 503 spike ({details[:120]}); checking next candidate...")
                        last_exc = RuntimeError(f"Gemini API HTTP {exc.code} on {model_name}: {details[:300]}")
                        break
                    if exc.code == 404:
                        logger.warning(f"Gemini {model_name} HTTP 404 ({details[:120]}); checking next candidate...")
                        last_exc = RuntimeError(f"Gemini API HTTP {exc.code} on {model_name}: {details[:300]}")
                        break
                    raise RuntimeError(f"Gemini API HTTP {exc.code}: {details[:300]}") from None
                except (TimeoutError, urllib.error.URLError) as exc:
                    exc_msg = self._sanitize_text(str(exc))
                    if attempt == 0 and model_name == candidate_models[-1]:
                        time.sleep(0.5)
                        continue
                    if model_name != candidate_models[-1]:
                        logger.warning(f"Gemini {model_name} network/timeout ({exc_msg[:120]}); trying next candidate model...")
                        last_exc = RuntimeError(f"Gemini {model_name} request error: {exc_msg[:200]}")
                        break
                    raise RuntimeError(f"Gemini connection error: {exc_msg[:200]}") from None

                if data.get("status") != "completed":
                    details = data.get("errors") or data.get("status") or "no completed response"
                    raise RuntimeError(f"Gemini interaction did not complete: {self._sanitize_text(str(details))}")

                output = []
                for step in data.get("steps", []):
                    if step.get("type") == "model_output":
                        for part in step.get("content", []):
                            if part.get("type") == "text" and part.get("text"):
                                output.append(part["text"])
                if output:
                    if self.model != model_name:
                        logger.info(f"Switched active Gemini model from '{self.model}' to working candidate '{model_name}'")
                        self.model = model_name
                    return self._sanitize_text("\n".join(output))

        if last_exc:
            raise last_exc
        raise RuntimeError("Gemini returned no text output")

    def _call_ollama(self, prompt: str, system_prompt: str, temperature: float, max_tokens: int, timeout: int = 90) -> str:
        url = f"{(self.base_url or 'http://localhost:11434').rstrip('/')}/api/generate"
        payload = {
            "model": self.model or "llama3",
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "")
        except urllib.error.HTTPError as exc:
            details = self._sanitize_text(self._extract_http_error_details(exc))
            raise RuntimeError(f"Ollama API HTTP {exc.code}: {details[:300]}") from None
        except (TimeoutError, urllib.error.URLError) as exc:
            exc_msg = self._sanitize_text(str(exc))
            raise RuntimeError(f"Ollama connection error: {exc_msg[:200]}") from None
