"""Tests for Phase 5 CI/CD gate, scope guard, SARIF validation, PR summary, and GitHub workflows."""

import json
from pathlib import Path
import re
import sys

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

from tools.ci_gate import (
    EXIT_GATE_TRIGGERED,
    EXIT_INVALID_CONFIG,
    EXIT_PASS,
    EXIT_SCOPE_VIOLATION,
    GateConfig,
    evaluate_gate,
    generate_pr_summary,
    main as ci_gate_main,
    redact_sensitive_text,
    validate_authorized_scope,
    validate_sarif_document,
    validate_sarif_file,
)
from tools.sarif_exporter import build_sarif_report, write_sarif_report


SHA_PIN_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _make_clean_output(tmp_path: Path, findings: list | None = None, target: str = "app.example.com") -> Path:
    out_dir = tmp_path / "targets" / target / "output"
    (out_dir / "report").mkdir(parents=True, exist_ok=True)
    (out_dir / "logs").mkdir(parents=True, exist_ok=True)
    items = findings or []
    report_json = out_dir / "report" / f"hackbot-report-{target}-20261126.json"
    report_json.write_text(
        json.dumps({"target": target, "findings": items}, indent=2),
        encoding="utf-8",
    )
    report_md = out_dir / "report" / f"hackbot-report-{target}-20261126.md"
    report_md.write_text("# Report\n", encoding="utf-8")
    write_sarif_report(out_dir / "report" / "findings.sarif", items, target=target)
    (out_dir / "logs" / "scope-audit-latest.json").write_text(
        json.dumps({
            "target": target,
            "stopped_by_policy": False,
            "deviation_detected": False,
            "out_of_scope_hosts": {},
            "out_of_policy_requests": [],
            "policy_violations": [],
        }),
        encoding="utf-8",
    )
    return out_dir


def test_ci_gate_clean_pass_and_resolved_findings(tmp_path):
    out_empty = _make_clean_output(tmp_path / "empty", findings=[])
    res_empty = evaluate_gate(out_empty, GateConfig(min_severity="low", fail_on_candidate=True))
    assert res_empty["exit_code"] == EXIT_PASS
    assert res_empty["passed"] is True
    assert res_empty["status"] == "pass"

    resolved_findings = [
        {"title": "Old XSS", "severity": "CRITICAL", "status": "fixed", "confidence": 0.99},
        {"title": "Benign Header", "severity": "HIGH", "status": "false_positive", "confidence": 0.9},
        {"title": "Accepted Info", "severity": "MEDIUM", "status": "accepted_risk", "confidence": 0.8},
        {"title": "Low Signal", "severity": "LOW", "status": "confirmed", "confidence": 0.95},
        {"title": "Unverified Lead", "severity": "HIGH", "status": "candidate", "confidence": 0.7},
    ]
    out_resolved = _make_clean_output(tmp_path / "resolved", findings=resolved_findings)
    res = evaluate_gate(
        out_resolved,
        GateConfig(min_severity="high", fail_on_confirmed=True, fail_on_candidate=False),
    )
    assert res["exit_code"] == EXIT_PASS
    assert res["passed"] is True
    assert res["counts"]["fixed"] == 1
    assert res["counts"]["false_positive"] == 1
    assert res["counts"]["accepted_risk"] == 1
    assert res["counts"]["confirmed"] == 1
    assert res["counts"]["candidate"] == 1
    assert res["counts"]["triggering"] == 0


def test_ci_gate_triggers_on_confirmed_severity_and_confidence(tmp_path):
    findings = [
        {
            "title": "Reflected XSS in /search",
            "severity": "HIGH",
            "status": "confirmed",
            "confidence": 0.9,
            "url": "https://app.example.com/search?q=1",
            "skill": "xss-reflected",
        },
        {
            "title": "Low-confidence SQLi hint",
            "severity": "CRITICAL",
            "status": "confirmed",
            "confidence": 0.25,
            "url": "https://app.example.com/items",
            "skill": "sqli-heuristic",
        },
    ]
    out_dir = _make_clean_output(tmp_path, findings=findings)

    # Confidence 0.8 filters out the 0.25 finding, but 0.9 HIGH triggers gate (exit 2).
    res = evaluate_gate(
        out_dir,
        GateConfig(min_severity="high", min_confidence=0.8, fail_on_confirmed=True),
    )
    assert res["exit_code"] == EXIT_GATE_TRIGGERED
    assert res["passed"] is False
    assert res["status"] == "gate_triggered"
    assert res["counts"]["triggering"] == 1
    assert res["triggering_findings"][0]["title"] == "Reflected XSS in /search"

    # Raising min_severity to critical with min_confidence=0.8 passes because critical item is 0.25.
    res_pass = evaluate_gate(
        out_dir,
        GateConfig(min_severity="critical", min_confidence=0.8, fail_on_confirmed=True),
    )
    assert res_pass["exit_code"] == EXIT_PASS


def test_ci_gate_fail_on_candidate_and_require_validation_cli(tmp_path, capsys):
    findings = [
        {
            "title": "Potential SSRF in webhook",
            "severity": "MEDIUM",
            "status": "candidate",
            "validation_status": "unverified",
            "confidence": "medium",
            "url": "https://app.example.com/webhook",
            "skill": "ssrf-identify",
        }
    ]
    out_dir = _make_clean_output(tmp_path, findings=findings)

    # Default (fail_on_candidate=False) passes
    rc_pass = ci_gate_main(["--output-dir", str(out_dir), "--min-severity", "medium"])
    assert rc_pass == EXIT_PASS
    capsys.readouterr()

    # --fail-on-candidate triggers exit code 2
    rc_cand = ci_gate_main([
        "--output-dir", str(out_dir),
        "--min-severity", "medium",
        "--fail-on-candidate",
    ])
    assert rc_cand == EXIT_GATE_TRIGGERED
    stdout_payload = json.loads(capsys.readouterr().out)
    assert stdout_payload["exit_code"] == EXIT_GATE_TRIGGERED
    assert stdout_payload["triggering_findings"][0]["gate_reason"] == "candidate_finding_blocked"

    # --require-validation also triggers exit code 2 on unvalidated candidates
    rc_req = ci_gate_main([
        "--output-dir", str(out_dir),
        "--min-severity", "medium",
        "--require-validation",
    ])
    assert rc_req == EXIT_GATE_TRIGGERED
    req_payload = json.loads(capsys.readouterr().out)
    assert req_payload["triggering_findings"][0]["gate_reason"] == "unvalidated_finding_requires_validation"


def test_ci_gate_invalid_config_and_missing_artifacts(tmp_path, capsys):
    # Missing output directory -> 4
    res_missing = evaluate_gate(tmp_path / "does-not-exist")
    assert res_missing["exit_code"] == EXIT_INVALID_CONFIG

    # Empty existing directory with zero artifacts -> 4
    empty_dir = tmp_path / "empty_artifacts"
    empty_dir.mkdir()
    res_no_artifacts = evaluate_gate(empty_dir)
    assert res_no_artifacts["exit_code"] == EXIT_INVALID_CONFIG

    # Invalid severity and confidence -> 4
    out_dir = _make_clean_output(tmp_path, findings=[])
    assert evaluate_gate(out_dir, GateConfig(min_severity="extreme"))["exit_code"] == EXIT_INVALID_CONFIG
    assert evaluate_gate(out_dir, GateConfig(min_confidence=1.5))["exit_code"] == EXIT_INVALID_CONFIG
    assert evaluate_gate(out_dir, GateConfig(min_confidence=-0.1))["exit_code"] == EXIT_INVALID_CONFIG

    # Missing config file -> 4
    rc_missing_cfg = ci_gate_main(["--output-dir", str(out_dir), "--config", str(tmp_path / "nope.yml")])
    assert rc_missing_cfg == EXIT_INVALID_CONFIG
    capsys.readouterr()

    # Valid YAML config file loads thresholds cleanly
    cfg_file = tmp_path / "gate.yml"
    cfg_file.write_text(
        yaml.safe_dump({
            "ci_gate": {
                "min-severity": "low",
                "fail-on-candidate": True,
                "min-confidence": 0.2,
            }
        }),
        encoding="utf-8",
    )
    out_cand = _make_clean_output(
        tmp_path / "cand_cfg",
        findings=[{"title": "Info leak", "severity": "LOW", "status": "candidate", "confidence": 0.5}],
    )
    rc_cfg = ci_gate_main(["--output-dir", str(out_cand), "--config", str(cfg_file)])
    assert rc_cfg == EXIT_GATE_TRIGGERED
    capsys.readouterr()


def test_ci_gate_scope_violation_and_pre_scan_scope_guard(tmp_path):
    # Case A: runtime scope deviation in scope-audit-latest.json -> exit 3
    out_dir = _make_clean_output(tmp_path / "scope_dev", findings=[])
    (out_dir / "logs" / "scope-audit-latest.json").write_text(
        json.dumps({
            "target": "app.example.com",
            "stopped_by_policy": True,
            "deviation_detected": True,
            "out_of_scope_hosts": {"evil.thirdparty.test": 2},
        }),
        encoding="utf-8",
    )
    res_scope = evaluate_gate(out_dir)
    assert res_scope["exit_code"] == EXIT_SCOPE_VIOLATION
    assert res_scope["status"] == "scope_violation"

    # Case B: orchestration-log BLOCKED_SCOPE -> exit 3
    out_dir_orch = _make_clean_output(tmp_path / "scope_orch", findings=[])
    (out_dir_orch / "logs" / "orchestration-log.json").write_text(
        json.dumps({"status": "BLOCKED_SCOPE"}),
        encoding="utf-8",
    )
    assert evaluate_gate(out_dir_orch)["exit_code"] == EXIT_SCOPE_VIOLATION

    # Case C: pre-scan scope guard requires scope-of-work for active scan
    target_dir = tmp_path / "targets" / "staging.example.com"
    target_dir.mkdir(parents=True)
    blocked = validate_authorized_scope("staging.example.com", target_dir=target_dir, scan_mode="quick")
    assert blocked["authorized"] is False
    assert blocked["exit_code"] == EXIT_SCOPE_VIOLATION

    # Passive mode allowed without scope-of-work, unsafe path rejected
    passive_ok = validate_authorized_scope("staging.example.com", target_dir=target_dir, scan_mode="passive")
    assert passive_ok["authorized"] is True
    assert passive_ok["exit_code"] == EXIT_PASS
    unsafe = validate_authorized_scope("../etc/passwd", target_dir=target_dir, scan_mode="passive")
    assert unsafe["authorized"] is False
    assert unsafe["exit_code"] == EXIT_SCOPE_VIOLATION

    # Authorized scope-of-work unlocks active scan
    (target_dir / "scope-of-work.md").write_text(
        "# Scope of Work\nAuthorized penetration testing for staging.example.com.\n## In Scope\n- staging.example.com\n",
        encoding="utf-8",
    )
    active_ok = validate_authorized_scope("staging.example.com", target_dir=target_dir, scan_mode="quick")
    assert active_ok["authorized"] is True
    assert active_ok["exit_code"] == EXIT_PASS


def test_sarif_validation_valid_and_invalid(tmp_path):
    findings = [
        {
            "title": "Reflected XSS",
            "severity": "HIGH",
            "url": "https://app.example.com/search",
            "notes": "Reflected parameter q",
            "status": "confirmed",
        }
    ]
    sarif_doc = build_sarif_report(findings, target="app.example.com")
    ok, errs = validate_sarif_document(sarif_doc)
    assert ok is True
    assert errs == []

    sarif_path = tmp_path / "valid.sarif"
    write_sarif_report(sarif_path, findings, target="app.example.com")
    ok_file, errs_file = validate_sarif_file(sarif_path)
    assert ok_file is True
    assert errs_file == []

    # Malformed SARIF with wrong version and unredacted secret
    fake_sk = "sk-" + "testkey9876543210abcdef"
    bad_sarif = {
        "version": "1.0",
        "runs": [
            {
                "tool": {"driver": {"name": ""}},
                "results": [
                    {
                        "ruleId": "",
                        "level": "critical",
                        "message": {"text": f"Leaked {fake_sk}"},
                        "locations": [],
                    }
                ],
            }
        ],
    }
    bad_ok, bad_errs = validate_sarif_document(bad_sarif)
    assert bad_ok is False
    assert len(bad_errs) >= 5

    # Strict SARIF check in evaluate_gate rejects malformed SARIF with exit 4
    out_dir = _make_clean_output(tmp_path, findings=findings)
    (out_dir / "report" / "findings.sarif").write_text(json.dumps(bad_sarif), encoding="utf-8")
    res_strict = evaluate_gate(out_dir, strict_sarif=True)
    assert res_strict["exit_code"] == EXIT_INVALID_CONFIG


def test_pr_summary_redacts_secrets_and_includes_links(tmp_path):
    # Assemble synthetic secrets dynamically so static scanners do not flag fixtures.
    syn_openai = "sk-" + "proj" + "AbCdEfGhIjKlMnOpQrStUvWx"
    syn_google = "AIza" + "SyDummyKeyForRedactionTest1234567890"
    syn_github = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    syn_aws = "AKIA" + "IOSFODNN7EXAMPLE"
    syn_bearer = "Bearer " + "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjMifQ." + "sig1234567890"

    findings = [
        {
            "title": f"Exposed token {syn_openai} and {syn_github}",
            "severity": "CRITICAL",
            "status": "confirmed",
            "confidence": 0.95,
            "url": f"https://app.example.com/cb?token={syn_google}&api_key={syn_aws}",
            "notes": f"Header Authorization: {syn_bearer} and Cookie: session=supersecretvalue123",
            "skill": "secret-scan",
        }
    ]
    out_dir = _make_clean_output(tmp_path, findings=findings)
    evaluation = evaluate_gate(out_dir, GateConfig(min_severity="high", fail_on_confirmed=True))
    summary = generate_pr_summary(
        evaluation,
        report_links={
            "Workflow Run": f"https://github.com/org/repo/actions/runs/42?token={syn_github}",
            "Security Tab": "https://github.com/org/repo/security/code-scanning",
        },
    )

    for leaked in (syn_openai, syn_google, syn_github, syn_aws, "supersecretvalue123", "eyJhbGciOiJIUzI1NiJ9"):
        assert leaked not in summary
    assert "[REDACTED" in summary
    assert "Moros AI Security Gate" in summary
    assert "FAIL" in summary
    assert "Markdown Report" in summary
    assert "SARIF 2.1.0" in summary
    assert "Security Tab" in summary
    assert redact_sensitive_text("Cookie: sid=abc123xyz") == "Cookie: [REDACTED]"


def _assert_uses_pinned_sha(uses_value: str, file_lines: list[str]) -> None:
    if uses_value.startswith("./"):
        return
    assert SHA_PIN_RE.match(uses_value), f"Action reference is not pinned to a 40-char SHA: {uses_value}"
    matching = [line for line in file_lines if uses_value in line]
    assert matching and "#" in matching[0], f"Pinned SHA must include a version comment: {uses_value}"


def test_github_workflows_and_action_yaml_valid_pinned_and_scoped():
    action_path = REPO_ROOT / ".github" / "actions" / "moros-scan" / "action.yml"
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    dast_path = REPO_ROOT / ".github" / "workflows" / "moros-dast-example.yml"
    retest_path = REPO_ROOT / ".github" / "workflows" / "moros-retest-example.yml"

    for path in (action_path, ci_path, dast_path, retest_path):
        assert path.is_file(), f"Missing required workflow/action file: {path}"

    # 1. Validate composite action.yml
    action_text = action_path.read_text(encoding="utf-8")
    action_doc = yaml.safe_load(action_text)
    assert action_doc["runs"]["using"] == "composite"
    required_inputs = {
        "target", "scan-mode", "budget", "min-severity",
        "fail-on-candidate", "fail-on-confirmed", "upload-sarif", "config-path",
    }
    assert required_inputs.issubset(set(action_doc["inputs"].keys()))
    required_outputs = {
        "exit-code", "sarif-path", "summary-markdown", "confirmed-count", "candidate-count",
    }
    assert required_outputs.issubset(set(action_doc["outputs"].keys()))
    action_lines = action_text.splitlines()
    for step in action_doc["runs"]["steps"]:
        if "uses" in step:
            _assert_uses_pinned_sha(step["uses"], action_lines)
        if "run" in step:
            assert "${{ inputs." not in step["run"], "Avoid direct ${{ inputs.* }} interpolation in run scripts"

    # 2. Validate workflows
    for wf_path in (ci_path, dast_path, retest_path):
        wf_text = wf_path.read_text(encoding="utf-8")
        wf_doc = yaml.safe_load(wf_text)
        assert isinstance(wf_doc, dict)
        perms = wf_doc.get("permissions")
        assert isinstance(perms, dict) and perms, f"{wf_path.name} must define least-privilege permissions"
        assert "write-all" not in perms
        wf_lines = wf_text.splitlines()

        for job in wf_doc.get("jobs", {}).values():
            for step in job.get("steps", []):
                if "uses" in step:
                    _assert_uses_pinned_sha(step["uses"], wf_lines)
                if "run" in step:
                    assert "${{ github.event." not in step["run"], (
                        f"{wf_path.name} must not interpolate untrusted github.event.* directly in run:"
                    )

    # 3. Specific checks on ci.yml
    ci_doc = yaml.safe_load(ci_path.read_text(encoding="utf-8"))
    assert ci_doc["permissions"] == {"contents": "read"}
    assert ci_doc["jobs"]["test"]["strategy"]["matrix"]["python-version"] == ["3.10", "3.12"]

    # 4. Explicit scope guard & SARIF upload checks on DAST and Retest example workflows
    for example_path in (dast_path, retest_path):
        text = example_path.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        assert doc["permissions"]["contents"] == "read"
        assert doc["permissions"]["security-events"] == "write"
        job = next(iter(doc["jobs"].values()))
        assert "fork" in str(job.get("if", "")) or "full_name == github.repository" in str(job.get("if", ""))
        assert "--check-scope" in text
        assert "upload-sarif" in text
