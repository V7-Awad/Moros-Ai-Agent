import json
from tools.hackbot_orchestrator import HackbotOrchestrator


def test_missing_dependency_unscheduled_is_blocked(tmp_path):
    # Initialize target with an authorized scope note so scope check passes
    scope_file = tmp_path / "scope-of-work.md"
    scope_file.write_text("Authorized testing for target.com. In scope of work.", encoding="utf-8")

    # Only request 'js-analyze' without 'js-discover' and without prior files on disk
    orchestrator = HackbotOrchestrator(
        target="target.com",
        target_dir=str(tmp_path),
        skills=["js-analyze"],
        models=["default"]
    )

    blocked = orchestrator.validate_dependencies()
    assert "js-analyze" in blocked
    assert "js-discover" in blocked["js-analyze"]


def test_dependency_with_disk_artifact_is_not_blocked(tmp_path):
    scope_file = tmp_path / "scope-of-work.md"
    scope_file.write_text("Authorized testing for target.com. In scope of work.", encoding="utf-8")

    # Simulate prior completion of js-discover by writing a collection-manifest.json
    js_dir = tmp_path / "output" / "js"
    js_dir.mkdir(parents=True, exist_ok=True)
    (js_dir / "collection-manifest.json").write_text(json.dumps({"files": ["bundle.js"]}), encoding="utf-8")

    orchestrator = HackbotOrchestrator(
        target="target.com",
        target_dir=str(tmp_path),
        skills=["js-analyze"],
        models=["default"]
    )

    blocked = orchestrator.validate_dependencies()
    # Since artifact is on disk, js-analyze is NOT blocked
    assert "js-analyze" not in blocked


def test_scheduled_prerequisites_are_not_blocked(tmp_path):
    scope_file = tmp_path / "scope-of-work.md"
    scope_file.write_text("Authorized testing for target.com. In scope of work.", encoding="utf-8")

    # Both js-discover and js-analyze are in the run schedule
    orchestrator = HackbotOrchestrator(
        target="target.com",
        target_dir=str(tmp_path),
        skills=["js-discover", "js-analyze"],
        models=["default"]
    )

    blocked = orchestrator.validate_dependencies()
    assert "js-analyze" not in blocked
