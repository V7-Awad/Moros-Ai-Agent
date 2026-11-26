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


def test_distill_persists_lessons_and_patterns_across_instances(tmp_path):
    from learning_engine.retrieval.search import search_lessons

    with LearningEngine(root=tmp_path) as engine1:
        f1 = engine1.record_finding(
            target="example.com",
            vuln_class="xss",
            title="Reflected XSS on /search",
            severity="high",
            confidence=0.8,
            signals={"reflection": 0.2, "no_output_encoding": 0.2},
        )
        engine1.record_triage(
            finding_id=f1["finding_id"],
            verdict="confirmed",
            reason="Verified reflection",
        )
        f2 = engine1.record_finding(
            target="example.com",
            vuln_class="sqli",
            title="SQLi heuristic on /items",
            severity="medium",
            confidence=0.4,
            signals={"sql_error": 0.25},
        )
        engine1.record_triage(
            finding_id=f2["finding_id"],
            verdict="false_positive",
            reason="Benign 500 error",
        )

        res1 = engine1.distill(min_support=1)
        assert res1["summary"]["classes"] == 2
        assert res1["summary"]["fp_patterns"] == 1

        # Add another finding and distill again; UPSERT must update in place without duplicates
        engine1.record_finding(
            target="example.com",
            vuln_class="xss",
            title="Reflected XSS on /profile",
            severity="high",
            confidence=0.85,
            signals={"reflection": 0.2},
        )
        engine1.distill(min_support=1)

        db1 = engine1._db()
        lesson_rows = db1.rows("SELECT * FROM lessons ORDER BY vuln_class")
        assert len(lesson_rows) == 2
        xss_lesson = next(r for r in lesson_rows if r["vuln_class"] == "xss")
        assert xss_lesson["support"] == 2
        assert "2 total" in xss_lesson["lesson"]

        pattern_rows = db1.rows("SELECT * FROM patterns ORDER BY pattern")
        pattern_names = {r["pattern"] for r in pattern_rows}
        assert {"class:xss", "class:sqli", "fp:sqli:sql_error"}.issubset(pattern_names)
        assert len(pattern_rows) == 3

    assert engine1.db is None

    # Open a brand-new instance against the same DB and verify persistence + recall
    with LearningEngine(root=tmp_path) as engine2:
        stats = engine2.stats()
        assert stats["lessons"] == 2
        assert stats["patterns"] == 3

        by_class = search_lessons(engine2._db(), "xss")
        assert len(by_class) == 1
        assert by_class[0]["support"] == 2

        by_target = search_lessons(engine2._db(), "example.com")
        assert len(by_target) == 2

        recon_target = engine2.before_recon("example.com")
        assert recon_target["ok"] is True
        assert len(recon_target["relevant_lessons"]) == 2
        assert set(recon_target["suggested_classes"]) == {"sqli", "xss"}

        # Tech stack miss still falls back to target/top lessons
        recon_techs = engine2.before_recon("example.com", ["nginx", "react"])
        assert len(recon_techs["relevant_lessons"]) == 2
    assert engine2.db is None


def test_hackbot_orchestrator_max_subagents_and_parallel_workers(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    import concurrent.futures
    from tools.hackbot_orchestrator import HackbotOrchestrator

    (tmp_path / "scope-of-work.md").write_text(
        "Authorized testing for example.com. In scope of work.", encoding="utf-8"
    )
    js_dir = tmp_path / "output" / "js"
    js_dir.mkdir(parents=True, exist_ok=True)
    (js_dir / "endpoints.json").write_text('{"endpoints": []}', encoding="utf-8")

    default_orch = HackbotOrchestrator(
        target="example.com", target_dir=str(tmp_path), skills=["xss-reflected"]
    )
    assert default_orch.max_subagents == 5

    clamped_orch = HackbotOrchestrator(
        target="example.com", target_dir=str(tmp_path), skills=["xss-reflected"], max_subagents=0
    )
    assert clamped_orch.max_subagents == 1

    orch = HackbotOrchestrator(
        target="example.com",
        target_dir=str(tmp_path),
        skills=["xss-reflected", "xss-dom", "ssrf-identify"],
        parallel=True,
        max_subagents=2,
        enable_tracing=False,
    )
    assert orch.max_subagents == 2

    monkeypatch.setattr(orch.runner.http, "request", lambda *a, **kw: {"status": "error"})
    monkeypatch.setattr(
        orch.runner,
        "run_vuln_skill",
        lambda skill: {"status": "COMPLETED", "findings_count": 0, "summary": f"ok {skill}"},
    )
    monkeypatch.setattr(
        orch.runner,
        "run_review_skill",
        lambda skill: {"overall_status": "PASS", "non_zero_logs_count": 1},
    )

    observed_max_workers = []
    real_executor = concurrent.futures.ThreadPoolExecutor

    class SpyExecutor(real_executor):
        def __init__(self, max_workers=None, *args, **kwargs):
            observed_max_workers.append(max_workers)
            super().__init__(max_workers=max_workers, *args, **kwargs)

    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", SpyExecutor)
    res = orch.run()
    assert res["status"] == "SUCCESS"
    assert observed_max_workers == [2]
    assert orch.learning_engine is None


def test_hackbot_orchestrator_learning_engine_hooks_and_persistence(tmp_path, monkeypatch):
    from tools.hackbot_orchestrator import HackbotOrchestrator

    (tmp_path / "scope-of-work.md").write_text(
        "Authorized testing for example.com. In scope of work.", encoding="utf-8"
    )
    js_dir = tmp_path / "output" / "js"
    js_dir.mkdir(parents=True, exist_ok=True)
    (js_dir / "endpoints.json").write_text('{"endpoints": []}', encoding="utf-8")

    orch = HackbotOrchestrator(
        target="example.com",
        target_dir=str(tmp_path),
        skills=["xss-reflected"],
        enable_tracing=False,
    )

    monkeypatch.setattr(orch.runner.http, "request", lambda *a, **kw: {"status": "error"})
    monkeypatch.setattr(
        orch.runner,
        "run_vuln_skill",
        lambda skill: {
            "status": "COMPLETED",
            "findings_count": 1,
            "summary": "Found 1 candidate",
            "findings": [
                {
                    "title": "Reflected XSS on /search",
                    "url": "https://example.com/search?q=test",
                    "type": "xss",
                    "severity": "high",
                    "confidence": "medium",
                    "validation_status": "unverified",
                    "signals": {"reflection": 0.2},
                }
            ],
        },
    )
    monkeypatch.setattr(
        orch.runner,
        "run_review_skill",
        lambda skill: {"overall_status": "PASS", "non_zero_logs_count": 1},
    )

    res = orch.run()
    assert res["status"] == "SUCCESS"
    # LearningEngine must be closed and cleared in finally
    assert orch.learning_engine is None
    assert orch.learning_summary["summary"]["count"] == 1
    assert orch.learning_summary["distill"]["summary"]["classes"] == 1

    # A subsequent LearningEngine instance sees the persisted finding + distilled lesson + pattern
    with LearningEngine(root=tmp_path) as next_engine:
        stats = next_engine.stats()
        assert stats["findings"] == 1
        assert stats["lessons"] == 1
        assert stats["patterns"] >= 1
        recon = next_engine.before_recon("example.com")
        assert "xss" in recon["suggested_classes"]
        assert len(recon["relevant_lessons"]) == 1


def test_hackbot_orchestrator_learning_engine_failure_resilience_and_early_abort_close(tmp_path, monkeypatch):
    import tools.hackbot_orchestrator as orch_mod
    from tools.hackbot_orchestrator import HackbotOrchestrator

    close_calls = []

    class FailingLearningEngine:
        def __init__(self, root=None):
            self.root = root

        def before_recon(self, target, techs=None):
            raise RuntimeError("before_recon failed")

        def after_finding(self, **kwargs):
            raise RuntimeError("after_finding failed")

        def before_summary(self, findings):
            raise RuntimeError("before_summary failed")

        def distill(self, min_support=2):
            raise RuntimeError("distill failed")

        def close(self):
            close_calls.append("closed")
            raise RuntimeError("close failed")

    monkeypatch.setattr(orch_mod, "LearningEngine", FailingLearningEngine)

    # 1. Early abort (no scope file) still closes LearningEngine in finally
    abort_orch = HackbotOrchestrator(
        target="example.com",
        target_dir=str(tmp_path / "no_scope"),
        skills=["xss-reflected"],
        enable_tracing=False,
    )
    abort_res = abort_orch.run()
    assert abort_res["status"] == "FAILED"
    assert len(close_calls) == 1
    assert abort_orch.learning_engine is None

    # 2. Normal scan with every LearningEngine hook raising still succeeds
    scan_dir = tmp_path / "with_scope"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scope-of-work.md").write_text(
        "Authorized testing for example.com. In scope of work.", encoding="utf-8"
    )
    js_dir = scan_dir / "output" / "js"
    js_dir.mkdir(parents=True, exist_ok=True)
    (js_dir / "endpoints.json").write_text('{"endpoints": []}', encoding="utf-8")

    orch = HackbotOrchestrator(
        target="example.com",
        target_dir=str(scan_dir),
        skills=["xss-reflected"],
        enable_tracing=False,
    )
    monkeypatch.setattr(orch.runner.http, "request", lambda *a, **kw: {"status": "error"})
    monkeypatch.setattr(
        orch.runner,
        "run_vuln_skill",
        lambda skill: {
            "status": "COMPLETED",
            "findings_count": 1,
            "findings": [{"title": "XSS", "url": "https://example.com/", "type": "xss"}],
        },
    )
    monkeypatch.setattr(
        orch.runner,
        "run_review_skill",
        lambda skill: {"overall_status": "PASS", "non_zero_logs_count": 1},
    )

    res = orch.run()
    assert res["status"] == "SUCCESS"
    assert len(close_calls) == 2
    assert orch.learning_engine is None
