import json
import os
from pathlib import Path

from dashboard import server


def _handler():
    return server.DashboardHandler.__new__(server.DashboardHandler)


def test_gadget_duplicates_are_collapsed_and_local_paths_are_hidden(tmp_path, monkeypatch):
    target = tmp_path / "lastpass.com" / "output"
    (target / "js").mkdir(parents=True)
    source_path = r"D:\Moros Ai\targets\lastpass.com\output\js\raw\external\app.js"
    (target / "js" / "gadgets.json").write_text(json.dumps({
        "gadgets": [
            {"type": "innerHTML assignment", "source_file": "app.js"},
            {"type": "innerHTML assignment", "source_file": "app.js"},
        ]
    }), encoding="utf-8")
    (target / "js" / "endpoints.json").write_text(json.dumps({
        "endpoints": [{"url": "/api/items", "method": "GET", "source_file": source_path}]
    }), encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
    handler = _handler()

    findings = handler.get_target_findings("lastpass.com")
    endpoints = handler.get_target_endpoints("lastpass.com")

    assert len(findings) == 1
    assert findings[0]["raw_record_count"] == 2
    assert endpoints["endpoints"][0]["source_file"] == "js/raw/external/app.js"
    assert "D:\\Moros Ai" not in endpoints["endpoints"][0]["source_file"]


def test_report_warns_when_saved_snapshot_disagrees_with_current_findings(tmp_path, monkeypatch):
    target = tmp_path / "example.com" / "output"
    findings_dir = target / "findings" / "xss"
    report_dir = target / "report"
    findings_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    (findings_dir / "candidates-xss.json").write_text(json.dumps({
        "findings": [{"title": "Candidate XSS", "severity": "Triage Severity: LOW"}]
    }), encoding="utf-8")
    (report_dir / "hackbot-report-example.com-20261123.md").write_text(
        "# Assessment report\n\nThe saved snapshot contains three items.\n", encoding="utf-8"
    )
    (report_dir / "hackbot-report-example.com-20261123.json").write_text(json.dumps({
        "summary": {"triage_items": 3}, "findings": [{}, {}, {}]
    }), encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)

    report = _handler().get_target_report("example.com")

    assert "Report snapshot is out of date" in report["markdown"]
    assert "3 triage items" in report["markdown"]
    assert "current dashboard data contains 1" in report["markdown"]


def test_fresh_report_is_canonical_for_dashboard_findings(tmp_path, monkeypatch):
    target_dir = tmp_path / "example.com"
    output = target_dir / "output"
    finding_file = output / "findings" / "xss" / "candidates-xss.json"
    finding_file.parent.mkdir(parents=True)
    finding_file.write_text(json.dumps({"findings": [
        {"title": "Candidate XSS", "type": "XSS", "url": "https://example.com/a"},
        {"title": "Candidate XSS", "type": "XSS", "url": "https://example.com/a"},
    ]}), encoding="utf-8")
    report_dir = output / "report"
    report_dir.mkdir()
    manifest = {"output/findings/xss/candidates-xss.json": finding_file.stat().st_mtime}
    (report_dir / "hackbot-report-example.com-20261124.json").write_text(json.dumps({
        "source_artifact_mtimes": manifest,
        "findings": [{"title": "Candidate XSS", "type": "XSS", "url": "https://example.com/a", "raw_record_count": 2}],
    }), encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)

    findings = _handler().get_target_findings("example.com")

    assert len(findings) == 1
    assert findings[0]["raw_record_count"] == 2


def test_overlapping_dom_evidence_and_duplicate_secret_locations_group_into_unique_findings(tmp_path, monkeypatch):
    output = tmp_path / "example.com" / "output"
    (output / "findings" / "xss-dom").mkdir(parents=True)
    (output / "js").mkdir(parents=True)
    candidate = {
        "title": "Potential DOM XSS Sink 'innerHTML' in a.js",
        "type": "DOM XSS",
        "sink": "innerHTML",
        "line": 17,
        "snippet": "node.innerHTML = value",
        "url": "https://example.com/a.js#L17",
        "severity": "Triage Severity: UNASSESSED",
    }
    alias = {**candidate, "title": "Potential DOM XSS Sink 'innerHTML' in alias.js", "url": "https://example.com/alias.js#L17"}
    (output / "findings" / "xss-dom" / "candidates-xss-dom.json").write_text(json.dumps({
        "findings": [candidate, alias]
    }), encoding="utf-8")
    (output / "js" / "gadgets.json").write_text(json.dumps({"gadgets": [
        {"type": "innerHTML assignment", "source_file": "a.js"},
        {"type": "innerHTML assignment", "source_file": "a.js"},
        {"type": "innerHTML assignment", "source_file": "alias.js"},
    ]}), encoding="utf-8")
    (output / "js" / "secrets-findings.json").write_text(json.dumps({"findings": [
        {"type": "test_key", "value_fingerprint": "fingerprint-1", "value_preview": "abcd…wxyz", "source_file": "a.js"},
        {"type": "test_key", "value_fingerprint": "fingerprint-1", "value_preview": "abcd…wxyz", "source_file": "alias.js"},
    ]}), encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)

    findings = _handler().get_target_findings("example.com")

    assert len(findings) == 2
    assert sum(item["raw_record_count"] for item in findings) == 7
    dom_finding = next(item for item in findings if item["category"] == "xss-dom")
    secret_finding = next(item for item in findings if item["category"] == "secrets")
    assert dom_finding["raw_record_count"] == 5
    assert len(dom_finding["occurrences"]) == 2
    assert secret_finding["raw_record_count"] == 2
    assert len(secret_finding["occurrences"]) == 2


def test_skill_status_uses_latest_run_and_does_not_promote_old_logs_to_current_completion(tmp_path, monkeypatch):
    target = tmp_path / "example.com"
    runs = target / "output" / "runs" / "run-latest"
    logs = target / "output" / "logs"
    (runs).mkdir(parents=True)
    (logs / "review").mkdir(parents=True)
    (logs / "xss-dom").mkdir()
    (logs / "xss-dom" / "old.log").write_text("historical", encoding="utf-8")
    review_file = logs / "review" / "recon-subdomain-review-1.json"
    review_file.write_text(json.dumps({"overall_status": "PASS"}), encoding="utf-8")
    os.utime(review_file, (1, 1))
    (runs / "events.jsonl").write_text(json.dumps({
        "event": "SKILL_COMPLETED", "details": {"skill": "recon-subdomain"}
    }) + "\n", encoding="utf-8")

    class FakeRunManager:
        def __init__(self, _target):
            pass

        def get_latest_or_active_run(self):
            return {
                "run_id": "run-latest",
                "started_at": "2026-11-24T12:00:00+02:00",
                "skills_requested": ["recon-subdomain"],
                "skills_completed": [],
                "skills_failed": [],
            }

    class FakeSkillRegistry:
        def list_skills(self):
            return [{"id": "recon-subdomain"}, {"id": "xss-dom"}]

    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
    monkeypatch.setattr(server, "RunManager", FakeRunManager)
    monkeypatch.setattr(server, "SkillRegistry", FakeSkillRegistry)

    statuses = {item["skill"]: item for item in _handler().get_target_skills_status("example.com")}

    assert statuses["recon-subdomain"]["state"] == "completed"
    assert statuses["recon-subdomain"]["review_status"] == "historical"
    assert statuses["xss-dom"]["state"] == "not_run"
    assert statuses["xss-dom"]["review_status"] == "not_run"
    assert statuses["xss-dom"]["logs_count"] == 1
