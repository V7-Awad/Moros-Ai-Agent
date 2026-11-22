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
import urllib.error
import urllib.request
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger("llm-client")


class LLMClient:
    def __init__(self, provider: str = "auto", model: str = None, api_key: str = None, base_url: str = None):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self._detect_provider()

    def _detect_provider(self):
        """Auto-detect provider based on environment variables if provider is 'auto'."""
        if self.provider != "auto":
            return

        if os.environ.get("OPENAI_API_KEY"):
            self.provider = "openai"
            self.api_key = os.environ.get("OPENAI_API_KEY")
            self.model = self.model or "gpt-4o-mini"
        elif os.environ.get("ANTHROPIC_API_KEY"):
            self.provider = "anthropic"
            self.api_key = os.environ.get("ANTHROPIC_API_KEY")
            self.model = self.model or "claude-3-5-sonnet-20241022"
        elif os.environ.get("GEMINI_API_KEY"):
            self.provider = "gemini"
            self.api_key = os.environ.get("GEMINI_API_KEY")
            self.model = self.model or "gemini-1.5-flash"
        elif os.environ.get("OPENROUTER_API_KEY"):
            self.provider = "openrouter"
            self.api_key = os.environ.get("OPENROUTER_API_KEY")
            self.model = self.model or "meta-llama/llama-3.1-8b-instruct"
        elif os.environ.get("OLLAMA_BASE_URL") or self._check_ollama():
            self.provider = "ollama"
            self.base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
            self.model = self.model or "llama3"
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

    def complete(self, prompt: str, system_prompt: str = "", temperature: float = 0.2, max_tokens: int = 4000) -> Optional[str]:
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
            logger.warning(f"LLM completion failed ({self.provider}/{self.model}): {e}")
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
        model_name = self.model or "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={self.api_key}"

        combined = f"System: {system_prompt}\n\nUser: {prompt}" if system_prompt else prompt
        payload = {
            "contents": [{"parts": [{"text": combined}]}],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens}
        }

        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"]

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
