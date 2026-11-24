import tempfile
from pathlib import Path
import pytest

from learning_engine.engine import LearningEngine
from learning_engine.scoring.engine import score


def test_learning_engine_lifecycle(tmp_path):
    db_file = tmp_path / "memory" / "test_learning.db"
    engine = LearningEngine(root=tmp_path)
    engine.db_path = db_file
    engine.init_db()

    # 1. Hook: record_finding
    finding = engine.record_finding(
        target="example.com",
        vuln_class="xss",
        title="Reflected XSS on /search",
        severity="high",
        confidence=0.85,
        evidence="<script>alert(1)</script>",
        signals={"reflection": 0.1, "no_output_encoding": 0.1}
    )
    assert finding["finding_id"].startswith("f-")
    assert finding["target"] == "example.com"
    assert finding["vuln_class"] == "xss"

    # 2. Hook: record_triage
    triage = engine.record_triage(
        finding_id=finding["finding_id"],
        verdict="confirmed",
        reason="Verified in headless browser with alert triggered",
        reviewer="analyst-review"
    )
    assert triage["verdict"] == "confirmed"

    # 3. Hook: recall
    results = engine.recall("XSS")
    assert len(results) >= 1
    assert any(r.get("vuln_class") == "xss" for r in results)

    # 4. Hook: score
    scored_val = engine.score({"rce": 1, "auth_bypass": 1})
    assert 0.0 <= scored_val["score"] <= 1.0

    # 5. Hook: distill
    patterns = engine.distill()
    assert isinstance(patterns, dict)
    assert "summary" in patterns

    # Lifecycle hooks
    recon_ctx = engine.before_recon("example.com", ["nginx", "react"])
    assert "target" in recon_ctx

    test_score = engine.during_testing({"sql_injection": 1})
    assert test_score["score"] > 0.0

    finding_doc = engine.after_finding(
        target="example.com",
        endpoint="/api/login",
        vulnerability_class="sqli",
        signals={"sql_injection": 1},
        validation_state="confirmed",
        source_provenance="heuristic"
    )
    assert finding_doc["target"] == "example.com"

    summary_rank = engine.before_summary([finding_doc])
    assert summary_rank["count"] == 1
    assert len(summary_rank["ranked"]) == 1

    triage_doc = engine.after_triage(
        finding_id=finding_doc["finding_id"],
        feedback_type="accepted",
        notes="Automated verification passed",
        provenance="moros-agent"
    )
    assert triage_doc["verdict"] == "confirmed"
