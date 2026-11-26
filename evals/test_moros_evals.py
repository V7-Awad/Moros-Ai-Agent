#!/usr/bin/env python3
"""Regression eval suite executable via pytest evals/."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from eval_harness import EvalHarness


def test_moros_eval_suite_passes():
    report = EvalHarness().run_all()
    failures = [c for c in report["cases"] if not c["passed"]]
    assert report["failed"] == 0, f"Eval failures: {failures}"
    assert report["pass_rate"] == 100.0
