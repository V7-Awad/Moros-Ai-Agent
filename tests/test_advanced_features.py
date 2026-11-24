import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tools.scope_validator import ScopeValidator
from tools.poc_generator import PoCGenerator
from tools.alert_dispatcher import AlertDispatcher
from tools.scoped_http import ScopedHttpClient


def test_scope_validator_in_and_out_of_scope():
    validator = ScopeValidator(
        target="example.com",
        in_scope=["*.example.com", "example.com"],
        out_of_scope=["blog.example.com", "status.example.com", "*.zendesk.com"]
    )

    # Allowed in-scope
    ok1, reason1 = validator.is_allowed("api.example.com")
    assert ok1 is True
    ok2, reason2 = validator.is_allowed("example.com")
    assert ok2 is True

    # Blocked out-of-scope
    blocked1, r_b1 = validator.is_allowed("blog.example.com")
    assert blocked1 is False
    assert "OUT-OF-SCOPE" in r_b1

    blocked2, r_b2 = validator.is_allowed("support.zendesk.com")
    assert blocked2 is False
    assert "OUT-OF-SCOPE" in r_b2

    # Blocked foreign domain
    blocked3, r_b3 = validator.is_allowed("malicious.com")
    assert blocked3 is False


def test_poc_generator(tmp_path):
    gen = PoCGenerator("target.com", tmp_path)
    finding = {
        "title": "DOM XSS in Search Input",
        "url": "https://target.com/search?q=test",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "evidence": "location.href reflection",
        "notes": "Parameter q reflects in innerHTML"
    }

    pocs = gen.generate_poc(finding, custom_headers={"X-Test": "123"})
    assert "poc_sh" in pocs
    assert "poc_py" in pocs

    sh_file = Path(pocs["poc_sh_abs"])
    py_file = Path(pocs["poc_py_abs"])

    assert sh_file.is_file()
    assert py_file.is_file()

    sh_text = sh_file.read_text(encoding="utf-8")
    assert "curl" in sh_text
    assert "https://target.com/search?q=test" in sh_text
    assert "X-Test: 123" in sh_text

    py_text = py_file.read_text(encoding="utf-8")
    assert "reproduce()" in py_text
    assert "https://target.com/search?q=test" in py_text


def test_scoped_http_client_authenticated_headers():
    client = ScopedHttpClient(
        target="example.com",
        auth_headers={"Authorization": "Bearer test-jwt-token"},
        cookies="session=abc123xyz"
    )

    assert client.auth_headers["Authorization"] == "Bearer test-jwt-token"
    assert client.cookies == "session=abc123xyz"
    assert hasattr(client, "get")
    assert hasattr(client, "head")


def test_scope_validator_reads_env_vars(monkeypatch):
    monkeypatch.setenv("MOROS_IN_SCOPE", "api.test.com,*.cdn.test.com")
    monkeypatch.setenv("MOROS_OUT_OF_SCOPE", "blog.test.com")
    sv = ScopeValidator("test.com")
    assert "api.test.com" in sv.in_scope
    assert "blog.test.com" in sv.out_of_scope
    allowed, _ = sv.is_allowed("api.test.com")
    assert allowed
    allowed, _ = sv.is_allowed("blog.test.com")
    assert not allowed


def test_alert_dispatcher_safe_handling():
    with patch.dict("os.environ", {}, clear=True):
        dispatcher = AlertDispatcher()
        assert dispatcher.is_configured() is False
        # Should not crash when not configured
        dispatcher.send_alert("Test Alert", "Test Message", "HIGH")
