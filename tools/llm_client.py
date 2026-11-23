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
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger("llm-client")


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


class LLMClient:
    def __init__(self, provider: str = "auto", model: str = None, api_key: str = None, base_url: str = None):
        load_dotenv_if_present()
        self.provider = provider.lower() if provider else "auto"
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.last_error = None
        self._detect_provider()

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

        # Anthropic, Gemini, Ollama have specialized protocols
        if selected == "anthropic":
            self.api_key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
            self.model = self.model or os.environ.get("ANTHROPIC_MODEL") or "claude-3-5-sonnet-20241022"
        elif selected == "gemini":
            self.api_key = self.api_key or os.environ.get("GEMINI_API_KEY")
            self.model = self.model or os.environ.get("GEMINI_MODEL") or "gemini-3.8-flash"
        elif selected == "ollama":
            self.base_url = self.base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
            self.model = self.model or os.environ.get("OLLAMA_MODEL") or "llama3"
        elif selected in KNOWN_PROVIDERS:
            # Route all known OpenAI-compatible providers
            info = KNOWN_PROVIDERS[selected]
            self.provider = "openai"
            prov_env_base = os.environ.get(f"{selected.upper()}_BASE_URL")
            if selected == "openai":
                prov_env_base = prov_env_base or os.environ.get("OPENAI_BASE_URL")
            self.base_url = self.base_url or prov_env_base or info["base_url"]
            self.api_key = self.api_key or os.environ.get(info["env_key"]) or (os.environ.get("OPENAI_API_KEY") if selected == "openai" else None)
            self.model = self.model or os.environ.get(info["env_model"]) or info["default_model"]
        elif selected in ["custom", "openai_compatible"] or self.base_url or os.environ.get("OPENAI_BASE_URL"):
            # Custom OpenAI compatible gateway (LM Studio, vLLM, LocalAI, etc.)
            self.provider = "openai"
            self.base_url = self.base_url or os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_BASE_URL") or "http://localhost:1234/v1"
            self.api_key = self.api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY") or "none"
            self.model = self.model or os.environ.get("OPENAI_MODEL") or os.environ.get("LLM_MODEL") or "default"
        elif selected != "none":
            # Universal fallback: Any arbitrary provider name with an API key or base URL is routed as OpenAI-compatible
            self.provider = "openai"
            self.base_url = self.base_url or os.environ.get(f"{selected.upper()}_BASE_URL") or "https://api.openai.com/v1"
            self.api_key = self.api_key or os.environ.get(f"{selected.upper()}_API_KEY") or os.environ.get("OPENAI_API_KEY")
            self.model = self.model or os.environ.get(f"{selected.upper()}_MODEL") or "default"
        else:
            self.provider = "none"

    def _check_ollama(self) -> bool:
        """Check if local Ollama daemon is reachable."""
        try:
            req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1) as resp:
                return resp.status == 200
        except Exception:
            return False

    def is_available(self) -> bool:
        """Return True if an LLM backend is configured and ready."""
        return self.provider != "none" and bool(self.api_key or self.provider == "ollama")

    def complete(self, prompt: str, system_prompt: str = "", temperature: float = 0.2, max_tokens: int = 8192) -> Optional[str]:
        """Generate text completion from the configured LLM backend."""
        if not self.is_available():
            logger.debug("No LLM API key configured — skipping model inference.")
            return None

        try:
            if self.provider in ["openai", "openrouter"]:
                return self._call_openai_compatible(prompt, system_prompt, temperature, max_tokens)
            elif self.provider == "anthropic":
                return self._call_anthropic(prompt, system_prompt, temperature, max_tokens)
            elif self.provider == "gemini":
                return self._call_gemini(prompt, system_prompt, temperature, max_tokens)
            elif self.provider == "ollama":
                return self._call_ollama(prompt, system_prompt, temperature, max_tokens)
        except Exception as e:
            error_text = str(e)
            if self.api_key:
                error_text = error_text.replace(self.api_key, "[redacted]")
            self.last_error = error_text[:500]
            logger.warning(f"LLM completion failed ({self.provider}/{self.model}): {self.last_error}")
            return None

    def _call_openai_compatible(self, prompt: str, system_prompt: str, temperature: float, max_tokens: int) -> str:
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
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/V7-Awad/Moros-Ai-Agent"
            headers["X-Title"] = "Moros AI Pentest Agent"

        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]

    def _call_anthropic(self, prompt: str, system_prompt: str, temperature: float, max_tokens: int) -> str:
        url = "https://api.anthropic.com/v1/messages"
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

        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["content"][0]["text"]

    def _call_gemini(self, prompt: str, system_prompt: str, temperature: float, max_tokens: int) -> str:
        primary_model = self.model or "gemini-3.8-flash"
        # Candidate models to try in order on capacity spikes / deprecation
        candidate_models = [primary_model]
        if "3.8" in primary_model and "gemini-3.5-flash" not in candidate_models:
            candidate_models.append("gemini-3.5-flash")
        elif "3.5" in primary_model and "gemini-3.8-flash" not in candidate_models:
            candidate_models.append("gemini-3.8-flash")

        url = "https://generativelanguage.googleapis.com/v1beta/interactions"
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
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    raw_error = exc.read(4096).decode("utf-8", errors="replace")
                    try:
                        parsed_error = json.loads(raw_error)
                        error = parsed_error.get("error", parsed_error)
                        details = error.get("message", raw_error) if isinstance(error, dict) else str(error)
                    except json.JSONDecodeError:
                        details = raw_error or exc.reason
                    if exc.code == 503 and attempt == 0:
                        logger.warning(f"Gemini {model_name} HTTP 503 spike; backing off 1.5s for retry...")
                        time.sleep(1.5)
                        continue
                    if exc.code in {503, 404} and model_name != candidate_models[-1]:
                        logger.warning(f"Gemini {model_name} HTTP {exc.code} ({str(details)[:150]}); trying fallback model {candidate_models[-1]}...")
                        last_exc = RuntimeError(f"Gemini API HTTP {exc.code}: {str(details)[:400]}")
                        break
                    raise RuntimeError(f"Gemini API HTTP {exc.code}: {str(details)[:400]}") from None
                except (TimeoutError, urllib.error.URLError) as exc:
                    if attempt == 0:
                        time.sleep(1.0)
                        continue
                    if model_name != candidate_models[-1]:
                        logger.warning(f"Gemini {model_name} network/timeout issue; trying fallback model {candidate_models[-1]}...")
                        last_exc = exc
                        break
                    raise

                if data.get("status") != "completed":
                    details = data.get("errors") or data.get("status") or "no completed response"
                    raise RuntimeError(f"Gemini interaction did not complete: {details}")

                output = []
                for step in data.get("steps", []):
                    if step.get("type") == "model_output":
                        for part in step.get("content", []):
                            if part.get("type") == "text" and part.get("text"):
                                output.append(part["text"])
                if output:
                    return "\n".join(output)

        if last_exc:
            raise last_exc
        raise RuntimeError("Gemini returned no text output")

    def _call_ollama(self, prompt: str, system_prompt: str, temperature: float, max_tokens: int) -> str:
        url = f"{(self.base_url or 'http://localhost:11434').rstrip('/')}/api/generate"
        payload = {
            "model": self.model or "llama3",
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "")
