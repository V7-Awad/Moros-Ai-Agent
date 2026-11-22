import json
import pytest
from pathlib import Path
from tools.run_manager import RunManager


def test_run_creation_and_persistence(tmp_path):
    rm = RunManager(tmp_path)
    run = rm.create_run(target="test.org", skills=["recon-subdomain", "js-discover"], dry_run=False)

    assert run["run_id"].startswith("run-")
    assert run["target"] == "test.org"
    assert run["status"] == "running"
    assert run["current_skill"] == "recon-subdomain"

    # Verify run.json exists on disk
    run_file = tmp_path / "output" / "runs" / run["run_id"] / "run.json"
    assert run_file.is_file()

    # List runs
    runs = rm.list_runs()
    assert len(runs) == 1
    assert runs[0]["run_id"] == run["run_id"]


def test_run_event_stream_and_progress(tmp_path):
    rm = RunManager(tmp_path)
    run = rm.create_run(target="test.org", skills=["js-discover", "js-analyze"])
    run_id = run["run_id"]

    rm.log_event(run_id, "TEST_EVENT", {"detail": "info"})
    rm.update_skill_progress(run_id, "js-discover", status="completed", summary="Found 5 JS files")

    # Read events.jsonl
    events_file = tmp_path / "output" / "runs" / run_id / "events.jsonl"
    assert events_file.is_file()
    lines = [json.loads(line) for line in events_file.read_text(encoding="utf-8").strip().split("\n")]
    assert any(ev["event"] == "TEST_EVENT" for ev in lines)
    assert any(ev["event"] == "SKILL_COMPLETED" for ev in lines)

    # Check updated run record
    run_rec = rm.get_run(run_id)
    assert "js-discover" in run_rec["skills_completed"]
    assert run_rec["current_skill"] == "js-analyze"


def test_finish_run(tmp_path):
    rm = RunManager(tmp_path)
    run = rm.create_run(target="test.org", skills=["recon-subdomain"])
    run_id = run["run_id"]

    finished = rm.finish_run(run_id, status="completed")
    assert finished["status"] == "completed"
    assert finished["completed_at"] is not None
