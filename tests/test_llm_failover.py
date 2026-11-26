import io
import json
import os
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from tools.llm_client import LLMClient


@pytest.fixture(autouse=True)
def _isolated_llm_env(monkeypatch):
    """Keep tests offline and completely isolated from host env vars and .env."""
    monkeypatch.setattr("tools.llm_client.load_dotenv_if_present", lambda: None)
    for key in list(os.environ.keys()):
        if (
            key.endswith("_API_KEY")
            or key.endswith("_BASE_URL")
            or key.endswith("_MODEL")
            or key.startswith("MOROS_LLM")
        ):
            monkeypatch.delenv(key, raising=False)


def _mock_json_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = None
    return resp


def _http_error(url: str, code: int, body: dict | str, reason: str = "Error") -> urllib.error.HTTPError:
    raw = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body.encode("utf-8")
    return urllib.error.HTTPError(url, code, reason, {}, io.BytesIO(raw))


def test_auto_provider_failover_503_to_secondary(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-test-1234567890123456")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test-1234567890123456")

    client = LLMClient(provider="auto")
    assert client.model == "deepseek-chat"

    seen_urls = []
    seen_models = []

    def mock_urlopen(req, timeout=20):
        seen_urls.append(req.full_url)
        body = json.loads(req.data.decode("utf-8"))
        seen_models.append(body["model"])
        if "api.deepseek.com" in req.full_url:
            raise _http_error(req.full_url, 503, {"error": {"message": "DeepSeek capacity spike"}}, "Service Unavailable")
        return _mock_json_response({
            "choices": [{"message": {"content": "FAILOVER_OK"}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7},
        })

    with patch("urllib.request.urlopen", side_effect=mock_urlopen), patch("time.sleep") as mock_sleep:
        res = client.complete("Ping")

    assert res == "FAILOVER_OK"
    assert client.last_error is None
    assert client.provider == "openai"
    assert client.model == "gpt-4o-mini"
    assert client.last_usage == {"input_tokens": 11, "output_tokens": 7}
    assert seen_urls.count("https://api.deepseek.com/v1/chat/completions") == 3
    assert "https://api.openai.com/v1/chat/completions" in seen_urls
    assert "gpt-4o-mini" in seen_models
    assert mock_sleep.call_count == 2
    assert len(client.last_failover_attempts) == 2
    assert client.last_failover_attempts[0]["provider"] == "deepseek"
    assert client.last_failover_attempts[0]["status"] == "failed"
    assert "503" in client.last_failover_attempts[0]["error"]
    assert client.last_failover_attempts[1] == {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "status": "succeeded",
        "error": "",
    }


def test_explicit_provider_with_enable_failover_true_429_to_anthropic(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test-1234567890123456")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123456789012345678")

    client = LLMClient(provider="openai", enable_failover=True)

    def mock_urlopen(req, timeout=20):
        if "api.openai.com" in req.full_url:
            raise _http_error(req.full_url, 429, {"error": {"message": "Rate limit reached"}}, "Too Many Requests")
        return _mock_json_response({
            "content": [{"type": "text", "text": "ANTHROPIC_BACKUP_OK"}],
            "usage": {"input_tokens": 25, "output_tokens": 9},
        })

    with patch("urllib.request.urlopen", side_effect=mock_urlopen), patch("time.sleep"):
        res = client.complete("Hello")

    assert res == "ANTHROPIC_BACKUP_OK"
    assert client.provider == "anthropic"
    assert client.model == "claude-3-5-sonnet-20241022"
    assert client.last_error is None
    assert client.last_usage == {"input_tokens": 25, "output_tokens": 9}
    assert [a["provider"] for a in client.last_failover_attempts] == ["openai", "anthropic"]
    assert client.last_failover_attempts[0]["status"] == "failed"
    assert "429" in client.last_failover_attempts[0]["error"]
    assert client.last_failover_attempts[1]["status"] == "succeeded"


def test_gemini_candidate_exhaustion_and_errors_failover_to_backup(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyTestGeminiKey12345678901234567890")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-backup-1234567890123456")

    # 1. All Gemini candidates return 503 -> failover to OpenAI
    client_503 = LLMClient(provider="gemini", model="gemini-3.8-flash", enable_failover=True)
    gemini_models_tried = []

    def mock_urlopen_503(req, timeout=20):
        body = json.loads(req.data.decode("utf-8"))
        if "generativelanguage.googleapis.com" in req.full_url:
            gemini_models_tried.append(body["model"])
            raise _http_error(req.full_url, 503, {"error": {"message": "overloaded"}}, "Service Unavailable")
        assert body["model"] == "gpt-4o-mini"
        return _mock_json_response({"choices": [{"message": {"content": "FROM_OPENAI_AFTER_GEMINI_503"}}]})

    with patch("urllib.request.urlopen", side_effect=mock_urlopen_503), patch("time.sleep"):
        res = client_503.complete("Check")

    assert res == "FROM_OPENAI_AFTER_GEMINI_503"
    assert len(gemini_models_tried) == 4
    assert client_503.last_failover_attempts[0]["provider"] == "gemini"
    assert client_503.last_failover_attempts[1]["provider"] == "openai"

    # 2. Gemini HTTP 429 -> failover to OpenAI
    client_429 = LLMClient(provider="gemini", fallback_providers=["openai"])

    def mock_urlopen_429(req, timeout=20):
        if "generativelanguage.googleapis.com" in req.full_url:
            raise _http_error(req.full_url, 429, {"error": {"message": "quota exceeded"}}, "Too Many Requests")
        return _mock_json_response({"choices": [{"message": {"content": "FROM_OPENAI_AFTER_GEMINI_429"}}]})

    with patch("urllib.request.urlopen", side_effect=mock_urlopen_429):
        res_429 = client_429.complete("Check 429")
    assert res_429 == "FROM_OPENAI_AFTER_GEMINI_429"

    # 3. Gemini connection error -> failover to OpenAI
    client_conn = LLMClient(provider="gemini", fallback_providers=["openai"])

    def mock_urlopen_conn(req, timeout=20):
        if "generativelanguage.googleapis.com" in req.full_url:
            raise urllib.error.URLError("DNS resolution failed")
        return _mock_json_response({"choices": [{"message": {"content": "FROM_OPENAI_AFTER_CONN_ERR"}}]})

    with patch("urllib.request.urlopen", side_effect=mock_urlopen_conn), patch("time.sleep"):
        res_conn = client_conn.complete("Check conn")
    assert res_conn == "FROM_OPENAI_AFTER_CONN_ERR"


def test_explicit_provider_and_enable_failover_false_do_not_failover(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-test-1234567890123456")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test-1234567890123456")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123456789012345678")

    # Explicit single provider without fallback_providers / enable_failover must NOT jump to backup
    explicit_client = LLMClient(provider="openai")
    called_urls = []

    def mock_fail_openai(req, timeout=20):
        called_urls.append(req.full_url)
        raise _http_error(req.full_url, 503, {"error": {"message": "OpenAI unavailable"}}, "Service Unavailable")

    with patch("urllib.request.urlopen", side_effect=mock_fail_openai), patch("time.sleep"):
        assert explicit_client.complete("Hi") is None

    assert all("api.openai.com" in u for u in called_urls)
    assert len(called_urls) == 3
    assert explicit_client.last_failover_attempts == []
    assert "503" in (explicit_client.last_error or "")

    # Auto provider with enable_failover=False must NOT failover
    no_failover_auto = LLMClient(provider="auto", enable_failover=False)
    called_urls.clear()

    with patch("urllib.request.urlopen", side_effect=mock_fail_openai), patch("time.sleep"):
        assert no_failover_auto.complete("Hi") is None

    assert all("api.deepseek.com" in u for u in called_urls)
    assert no_failover_auto.last_failover_attempts == []

    # Explicit fallback_providers with enable_failover=False must NOT failover
    no_failover_explicit = LLMClient(
        provider="openai",
        fallback_providers=["anthropic"],
        enable_failover=False,
    )
    called_urls.clear()

    with patch("urllib.request.urlopen", side_effect=mock_fail_openai), patch("time.sleep"):
        assert no_failover_explicit.complete("Hi") is None

    assert all("api.openai.com" in u for u in called_urls)
    assert no_failover_explicit.last_failover_attempts == []


def test_moros_llm_failover_env_flag(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test-1234567890123456")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123456789012345678")

    monkeypatch.setenv("MOROS_LLM_FAILOVER", "1")
    client_on = LLMClient(provider="openai")

    def mock_urlopen(req, timeout=20):
        if "api.openai.com" in req.full_url:
            raise _http_error(req.full_url, 503, {"error": {"message": "down"}}, "Service Unavailable")
        return _mock_json_response({"content": [{"type": "text", "text": "ENV_FAILOVER_OK"}]})

    with patch("urllib.request.urlopen", side_effect=mock_urlopen), patch("time.sleep"):
        assert client_on.complete("Hi") == "ENV_FAILOVER_OK"

    monkeypatch.setenv("MOROS_LLM_FAILOVER", "0")
    client_off = LLMClient(provider="auto")
    called = []

    def mock_fail(req, timeout=20):
        called.append(req.full_url)
        raise _http_error(req.full_url, 503, {"error": {"message": "down"}}, "Service Unavailable")

    with patch("urllib.request.urlopen", side_effect=mock_fail), patch("time.sleep"):
        assert client_off.complete("Hi") is None
    assert all("api.openai.com" in u for u in called)


def test_get_failover_candidates_priority_and_ollama_rules(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-ds-1234567890123456")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oa-1234567890123456")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-1234567890123456")
    monkeypatch.setenv("XAI_API_KEY", "xai-key-1234567890123456")

    # Auto primary selects deepseek -> backup candidates exclude deepseek, skip unreachable ollama
    c1 = LLMClient(provider="auto")
    with patch.object(c1, "_check_ollama", return_value=False):
        assert c1._get_failover_candidates() == ["openai", "anthropic", "xai"]

    # When ollama is reachable, it is included at the end
    with patch.object(c1, "_check_ollama", return_value=True):
        assert c1._get_failover_candidates() == ["openai", "anthropic", "xai", "ollama"]

    # When ollama is explicitly listed in fallback_providers, include even if not probed/reachable
    c2 = LLMClient(provider="deepseek", fallback_providers=["ollama", "openai"])
    with patch.object(c2, "_check_ollama", return_value=False):
        assert c2._get_failover_candidates() == ["ollama", "openai"]

    # xai and grok aliases exclude each other as primary
    c3 = LLMClient(provider="xai", fallback_providers=["grok", "xai", "openai"])
    assert c3._get_failover_candidates() == ["openai"]


def test_anthropic_transient_429_and_503_retry_succeeds(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123456789012345678")
    client = LLMClient(provider="anthropic")

    attempt_num = 0

    def mock_urlopen(req, timeout=60):
        nonlocal attempt_num
        attempt_num += 1
        assert req.headers.get("X-api-key") == "sk-ant-test-123456789012345678"
        if attempt_num == 1:
            raise _http_error(req.full_url, 429, {"error": {"message": "slow down"}}, "Too Many Requests")
        if attempt_num == 2:
            raise _http_error(req.full_url, 503, {"error": {"message": "overloaded_error"}}, "Service Unavailable")
        return _mock_json_response({
            "content": [{"type": "text", "text": "ANTHROPIC_RETRY_OK"}],
            "usage": {"input_tokens": 42, "output_tokens": 13},
        })

    with patch("urllib.request.urlopen", side_effect=mock_urlopen), patch("time.sleep") as mock_sleep:
        res = client._call_anthropic("Ping", "System", 0.1, 128, timeout=10)

    assert res == "ANTHROPIC_RETRY_OK"
    assert attempt_num == 3
    assert client.last_usage == {"input_tokens": 42, "output_tokens": 13}
    assert [c.args[0] for c in mock_sleep.call_args_list] == [2, 4]


def test_secret_redaction_in_last_error_and_failover_attempts(monkeypatch):
    ds_secret = "sk-deepseek-supersecret-key-9876543210"
    oa_secret = "custom-openai-token-secret-xyz123456789"
    ant_secret = "sk-ant-api03-supersecret-key-1234567890"
    gem_secret = "AIzaSySecretLeakTestKey12345678901234567"

    monkeypatch.setenv("DEEPSEEK_API_KEY", ds_secret)
    monkeypatch.setenv("OPENAI_API_KEY", oa_secret)
    monkeypatch.setenv("ANTHROPIC_API_KEY", ant_secret)
    monkeypatch.setenv("GEMINI_API_KEY", gem_secret)

    client = LLMClient(provider="auto")

    def mock_urlopen_all_fail(req, timeout=20):
        if "api.deepseek.com" in req.full_url:
            raise _http_error(
                req.full_url,
                401,
                {"error": {"message": f"Invalid key {ds_secret} Bearer {oa_secret}"}},
                "Unauthorized",
            )
        if "api.openai.com" in req.full_url:
            raise urllib.error.URLError(
                f"Failed https://api.openai.com/v1?key={oa_secret} with {oa_secret}"
            )
        if "api.anthropic.com" in req.full_url:
            raise _http_error(
                req.full_url,
                503,
                {"error": {"message": f"Anthropic key {ant_secret} overloaded"}},
                "Service Unavailable",
            )
        raise _http_error(
            req.full_url,
            503,
            {"error": {"message": f"Gemini key {gem_secret} spike"}},
            "Service Unavailable",
        )

    with patch("urllib.request.urlopen", side_effect=mock_urlopen_all_fail), \
         patch.object(client, "_check_ollama", return_value=False), \
         patch("time.sleep"):
        res = client.complete("Ping")

    assert res is None
    # Primary attributes restored when all failover attempts fail
    assert client._logical_provider == "deepseek"
    assert client.model == "deepseek-chat"

    assert client.last_error is not None
    serialized = json.dumps(client.last_failover_attempts)
    for leaked in (ds_secret, oa_secret, ant_secret, gem_secret):
        assert leaked not in client.last_error
        assert leaked not in serialized

    assert "[REDACTED_API_KEY]" in serialized
    assert [a["provider"] for a in client.last_failover_attempts] == ["deepseek", "openai", "anthropic", "gemini"]
    assert all(a["status"] == "failed" for a in client.last_failover_attempts)


def test_constructor_explicit_non_sk_secret_redacted_and_missing_primary_key_failover(monkeypatch):
    explicit_non_sk = "non-standard-primary-secret-token-xyz987"
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-backup-1234567890123456")

    # 1. Explicit constructor api_key not present in os.environ is still redacted
    c_explicit = LLMClient(
        provider="anthropic",
        api_key=explicit_non_sk,
        fallback_providers=["openai"],
    )

    def mock_urlopen_explicit(req, timeout=20):
        if "api.anthropic.com" in req.full_url:
            raise _http_error(
                req.full_url,
                401,
                {"error": {"message": f"bad credential {explicit_non_sk}"}},
                "Unauthorized",
            )
        return _mock_json_response({"choices": [{"message": {"content": "BACKUP_OK"}}]})

    with patch("urllib.request.urlopen", side_effect=mock_urlopen_explicit):
        res = c_explicit.complete("Ping")

    assert res == "BACKUP_OK"
    assert c_explicit.last_error is None
    serialized = json.dumps(c_explicit.last_failover_attempts)
    assert explicit_non_sk not in serialized
    assert "[REDACTED_API_KEY]" in serialized

    # 2. Primary provider missing its key fails over to explicit fallback without hitting primary URL
    c_missing_primary = LLMClient(provider="gemini", fallback_providers=["openai"])
    assert c_missing_primary.is_available() is True

    seen_urls = []

    def mock_urlopen_backup_only(req, timeout=20):
        seen_urls.append(req.full_url)
        return _mock_json_response({"choices": [{"message": {"content": "FALLBACK_DIRECT_OK"}}]})

    with patch("urllib.request.urlopen", side_effect=mock_urlopen_backup_only):
        res2 = c_missing_primary.complete("Ping")

    assert res2 == "FALLBACK_DIRECT_OK"
    assert seen_urls == ["https://api.openai.com/v1/chat/completions"]
    assert c_missing_primary.last_failover_attempts[0]["provider"] == "gemini"
    assert c_missing_primary.last_failover_attempts[0]["status"] == "failed"
    assert c_missing_primary.last_failover_attempts[1]["provider"] == "openai"
    assert c_missing_primary.last_failover_attempts[1]["status"] == "succeeded"
