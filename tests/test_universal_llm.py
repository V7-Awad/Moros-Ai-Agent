import pytest
from tools.llm_client import LLMClient, KNOWN_PROVIDERS


def test_known_providers_populated():
    assert "deepseek" in KNOWN_PROVIDERS
    assert "openai" in KNOWN_PROVIDERS
    assert "anthropic" in KNOWN_PROVIDERS
    assert "groq" in KNOWN_PROVIDERS
    assert "gemini" in KNOWN_PROVIDERS
    assert "openrouter" in KNOWN_PROVIDERS
    assert "xai" in KNOWN_PROVIDERS
    assert "mistral" in KNOWN_PROVIDERS
    assert "together" in KNOWN_PROVIDERS
    assert "cerebras" in KNOWN_PROVIDERS
    assert "sambanova" in KNOWN_PROVIDERS
    assert "fireworks" in KNOWN_PROVIDERS
    assert "perplexity" in KNOWN_PROVIDERS
    assert "cohere" in KNOWN_PROVIDERS
    assert "ollama" in KNOWN_PROVIDERS


def test_provider_direct_instantiation():
    client = LLMClient(provider="deepseek", api_key="sk-test", model="deepseek-chat")
    assert client.provider == "openai"  # routed through openai-compatible engine
    assert "deepseek.com" in client.base_url
    assert client.model == "deepseek-chat"
    assert client.is_available() is True


def test_universal_custom_provider():
    # Any custom provider name with a base_url and key must work!
    client = LLMClient(
        provider="my-custom-provider",
        api_key="sk-secret",
        base_url="https://api.my-llm.com/v1",
        model="custom-coder-32b"
    )
    assert client.provider == "openai"
    assert client.base_url == "https://api.my-llm.com/v1"
    assert client.model == "custom-coder-32b"
    assert client.is_available() is True


def test_xai_grok_provider():
    client = LLMClient(provider="xai", api_key="xai-test", model="grok-2-latest")
    assert client.provider == "openai"
    assert "x.ai" in client.base_url
    assert client.model == "grok-2-latest"
    assert client.is_available() is True


def test_mistral_provider():
    client = LLMClient(provider="mistral", api_key="test-key", model="codestral-latest")
    assert client.provider == "openai"
    assert "mistral.ai" in client.base_url
    assert client.model == "codestral-latest"
    assert client.is_available() is True
