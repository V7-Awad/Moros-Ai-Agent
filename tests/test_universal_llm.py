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


def test_gemini_provider_instantiation():
    client = LLMClient(provider="gemini", api_key="AIzaSyTestKey1234567890123456789012345")
    assert client.provider == "gemini"
    assert "gemini" in client.model
    assert client.is_available() is True


def test_gemini_503_failover_to_candidate():
    import io
    import json
    import urllib.error
    from unittest.mock import patch, MagicMock

    client = LLMClient(provider="gemini", api_key="test-key", model="gemini-3.8-flash")

    # Simulate 503 spike on 3.8-flash, then success on candidate gemini-3-flash-preview
    call_count = 0

    def mock_urlopen(req, timeout=15):
        nonlocal call_count
        call_count += 1
        body = json.loads(req.data.decode("utf-8"))
        if body["model"] == "gemini-3.8-flash":
            err_fp = io.BytesIO(b'{"error":{"code":503,"message":"gemini-3.8-flash demand spike"}}')
            raise urllib.error.HTTPError(req.full_url, 503, "Service Unavailable", {}, err_fp)
        else:
            resp_data = {
                "status": "completed",
                "steps": [
                    {
                        "type": "model_output",
                        "content": [{"type": "text", "text": "PONG"}]
                    }
                ]
            }
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(resp_data).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_resp.__exit__.return_value = None
            return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        result = client._call_gemini("Ping", "", 0.1, 100, timeout=5)
        assert result == "PONG"
        # Verified it switched model to candidate that succeeded
        assert client.model == "gemini-3-flash-preview"


def test_gemini_all_503_raises_sanitized_error():
    import io
    import urllib.error
    from unittest.mock import patch

    client = LLMClient(provider="gemini", api_key="AIzaSySecretApiKey12345678901234567890", model="gemini-3.8-flash")

    def mock_urlopen_fail(req, timeout=15):
        err_fp = io.BytesIO(b'{"error":{"code":503,"message":"high demand spike for key AIzaSySecretApiKey12345678901234567890"}}')
        raise urllib.error.HTTPError(req.full_url, 503, "Service Unavailable", {}, err_fp)

    with patch("urllib.request.urlopen", side_effect=mock_urlopen_fail):
        with pytest.raises(RuntimeError) as exc_info:
            client._call_gemini("Ping", "", 0.1, 100, timeout=5)
        err_str = str(exc_info.value)
        assert "503" in err_str
        assert "AIzaSySecretApiKey" not in err_str
        assert "[REDACTED_API_KEY]" in err_str
