from learning_engine.engine import LearningEngine


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
    engine.close()


def test_learning_engine_context_manager_and_pragmas(tmp_path):
    db_file = tmp_path / "memory" / "ctx.db"
    with LearningEngine(root=tmp_path) as engine:
        engine.db_path = db_file
        db1 = engine.init_db()
        assert db1.one("PRAGMA busy_timeout")["timeout"] == 5000
        db2 = engine.init_db()
        assert db2 is not db1
        # Calling init_db again must close db1 cleanly
        import pytest
        import sqlite3
        with pytest.raises(sqlite3.ProgrammingError):
            db1.execute("SELECT 1")
    assert engine.db is None


def test_learning_engine_none_guards_and_validation(tmp_path):
    import pytest
    from learning_engine.core.validation import normalize_vuln_class

    with pytest.raises(ValueError):
        normalize_vuln_class("!!!")
    with pytest.raises(ValueError):
        normalize_vuln_class("---")

    with LearningEngine(root=tmp_path) as engine:
        engine.db_path = tmp_path / "memory" / "none_guards.db"
        engine.init_db()
        doc = engine.after_finding(
            target="Example.COM/",
            endpoint="/api/test",
            vulnerability_class="xss",
            validation_state=None,
        )
        assert doc["target"] == "example.com"
        triage = engine.after_triage(finding_id=doc["finding_id"], feedback_type=None)
        assert triage["verdict"] == "unverified"

        summary = engine.before_summary([
            {"title": "a", "severity": None, "confidence": None, "score": None},
            {"title": "b", "severity": "high", "confidence": 0.9, "score": 0.8},
        ])
        assert summary["ranked"][0]["title"] == "b"


def test_learning_engine_corrupt_signals_unexpected_verdict_and_integrity_race(tmp_path):
    import sqlite3
    from unittest.mock import patch
    from learning_engine.analytics.patterns import (
        duplicate_heavy_patterns,
        fp_pattern_candidates,
        per_class_stats,
        signal_heatmap,
        target_summary,
    )
    from learning_engine.graph.builder import build_graph
    from learning_engine.ingestion.finding import normalize_finding, persist_finding

    with LearningEngine(root=tmp_path) as engine:
        engine.db_path = tmp_path / "memory" / "edge.db"
        db = engine.init_db()
        doc = engine.record_finding(
            target="Example.COM/",
            vuln_class="idor",
            title="IDOR on /orders",
            signals={"no_authorization_check": 1},
        )
        # Inject malformed JSON / "null" signals and an unexpected verdict row directly
        db.execute(
            "INSERT INTO findings (finding_id, target, vuln_class, title, severity, confidence, evidence, signals, source, created_at) "
            "VALUES ('f-bad1', 'example.com', 'idor', 'Bad JSON', 'medium', 0.5, NULL, '{bad', 'test', '2026-01-01T00:00:00Z')"
        )
        db.execute(
            "INSERT INTO findings (finding_id, target, vuln_class, title, severity, confidence, evidence, signals, source, created_at) "
            "VALUES ('f-null1', 'example.com', 'idor', 'Null JSON', 'medium', 0.5, NULL, 'null', 'test', '2026-01-01T00:00:00Z')"
        )
        db.execute(
            "INSERT INTO triage (finding_id, verdict, reason, reviewer, created_at) "
            "VALUES ('f-bad1', 'custom_verdict', 'test', 'rev', '2026-01-01T00:00:00Z')"
        )
        db.commit()

        stats = per_class_stats(db)
        assert stats[0]["custom_verdict"] == 1
        assert fp_pattern_candidates(db, min_occurrences=1) == []
        assert isinstance(signal_heatmap(db), dict)
        assert isinstance(duplicate_heavy_patterns(db, min_occurrences=1), list)
        ts = target_summary(db, "Example.COM/")
        assert ts["target"] == "example.com"
        assert ts["total_findings"] == 3
        graph = build_graph(db)
        assert graph["stats"]["targets"] == 1

        # Simulate IntegrityError race in persist_finding
        dup_doc = normalize_finding(
            target="example.com",
            vuln_class="idor",
            title="Race",
            finding_id=doc["finding_id"],
        )
        with patch.object(db, "one", side_effect=[None, {"finding_id": doc["finding_id"]}]), \
             patch.object(db, "execute", side_effect=sqlite3.IntegrityError("UNIQUE constraint failed")):
            res = persist_finding(db, dup_doc)
        assert res["status"] == "existing"


def test_learning_engine_fts_skip_rebuild_and_like_fallback(tmp_path):
    from unittest.mock import patch
    from learning_engine.core.schema import apply_schema
    from learning_engine.retrieval.search import search_findings

    with LearningEngine(root=tmp_path) as engine:
        engine.db_path = tmp_path / "memory" / "fts.db"
        db = engine.init_db()
        engine.record_finding(target="example.com", vuln_class="ssrf", title="SSRF on /fetch")

        # Repeated apply_schema should not drop/recreate/backfill FTS tables
        with patch("learning_engine.core.schema._backfill_fts") as backfill_spy:
            apply_schema(db.conn)
            backfill_spy.assert_not_called()

        # Simulate FTS5 unavailable: drop FTS tables and verify LIKE fallback works
        db.conn.executescript("DROP TRIGGER IF EXISTS findings_fts_ai; DROP TABLE IF EXISTS findings_fts;")
        rows = search_findings(db, "fetch")
        assert len(rows) == 1
        assert rows[0]["vuln_class"] == "ssrf"
