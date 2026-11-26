#!/usr/bin/env python3
"""Tests for trace_logger.py — Observability & Structured Tracing."""

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from trace_logger import TraceLogger, Span


class TestSpan:
    def test_span_creation(self):
        s = Span(name="test-span", trace_id="abc123")
        assert s.name == "test-span"
        assert s.trace_id == "abc123"
        assert s.status == "running"
        assert s.span_id

    def test_span_end(self):
        s = Span(name="test", trace_id="abc")
        time.sleep(0.01)
        s.end(status="ok")
        assert s.status == "ok"
        assert s.end_time
        assert s.duration_ms > 0

    def test_span_end_with_error(self):
        s = Span(name="test", trace_id="abc")
        s.end(status="error", error="Connection timeout")
        assert s.attributes["error.message"] == "Connection timeout"

    def test_span_add_event(self):
        s = Span(name="test", trace_id="abc")
        s.add_event("http_request", {"url": "/login"})
        assert len(s.events) == 1
        assert s.events[0]["name"] == "http_request"

    def test_span_to_dict(self):
        s = Span(name="test", trace_id="abc", span_type="tool",
                 attributes={"tool.name": "http_get"})
        s.end()
        d = s.to_dict()
        assert d["name"] == "test"
        assert d["type"] == "tool"
        assert d["attributes"]["tool.name"] == "http_get"


class TestTraceLogger:
    def test_start_trace(self):
        tracer = TraceLogger()
        trace_id = tracer.start_trace("test-scan")
        assert trace_id
        assert len(tracer.get_trace(trace_id)) == 1  # root span

    def test_start_and_end_span(self):
        tracer = TraceLogger()
        trace_id = tracer.start_trace("scan")
        span = tracer.start_span("xss-reflected", trace_id, span_type="skill")
        assert span.status == "running"
        tracer.end_span(span, status="ok")
        assert span.status == "ok"
        assert len(tracer.get_trace(trace_id)) == 2

    def test_nested_spans(self):
        tracer = TraceLogger()
        trace_id = tracer.start_trace("scan")
        skill_span = tracer.start_span("recon", trace_id, span_type="skill")
        tool_span = tracer.start_span("http_get", trace_id,
                                       parent_id=skill_span.span_id, span_type="tool")
        tracer.end_span(tool_span)
        tracer.end_span(skill_span)
        spans = tracer.get_trace(trace_id)
        assert len(spans) == 3
        assert spans[2]["parent_id"] == skill_span.span_id

    def test_end_trace(self):
        tracer = TraceLogger()
        trace_id = tracer.start_trace("scan")
        tracer.start_span("skill", trace_id)
        tracer.end_trace(trace_id)
        spans = tracer.get_trace(trace_id)
        assert all(s["status"] != "running" for s in spans)

    def test_record_llm_call(self):
        tracer = TraceLogger()
        trace_id = tracer.start_trace("scan")
        span = tracer.record_llm_call(
            trace_id, provider="openai", model="gpt-4o",
            input_tokens=500, output_tokens=200, cost_usd=0.01, duration_ms=350.0,
        )
        assert span.status == "ok"
        assert span.duration_ms == 350.0
        d = span.to_dict()
        assert d["attributes"]["llm.provider"] == "openai"
        assert d["attributes"]["llm.input_tokens"] == 500

    def test_record_tool_call(self):
        tracer = TraceLogger()
        trace_id = tracer.start_trace("scan")
        span = tracer.record_tool_call(
            trace_id, tool_name="http_get",
            args_summary="url=/login", result_summary="200 OK",
            duration_ms=100.0,
        )
        assert span.status == "ok"
        assert span.duration_ms == 100.0
        d = span.to_dict()
        assert d["attributes"]["tool.name"] == "http_get"

    def test_export_to_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir)
            tracer = TraceLogger(target_dir=target_dir)
            trace_id = tracer.start_trace("scan")
            tracer.record_tool_call(trace_id, tool_name="test")
            tracer.end_trace(trace_id)
            path = tracer.export(trace_id)
            assert path.exists()
            data = json.loads(path.read_text())
            assert len(data) >= 2

    def test_export_all_traces(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tracer = TraceLogger(target_dir=Path(tmpdir))
            t1 = tracer.start_trace("scan1")
            t2 = tracer.start_trace("scan2")
            tracer.end_trace(t1)
            tracer.end_trace(t2)
            path = tracer.export()
            assert path.exists()
            data = json.loads(path.read_text())
            assert len(data) == 2

    def test_get_timeline(self):
        tracer = TraceLogger()
        trace_id = tracer.start_trace("scan")
        tracer.record_llm_call(trace_id, provider="openai", model="gpt-4o",
                               input_tokens=100, output_tokens=50, cost_usd=0.001)
        tracer.record_tool_call(trace_id, tool_name="http_get")
        timeline = tracer.get_timeline(trace_id)
        assert len(timeline) >= 3
        assert all("timestamp" in entry for entry in timeline)

    def test_get_stats(self):
        tracer = TraceLogger()
        t1 = tracer.start_trace("scan")
        tracer.start_span("skill", t1)
        stats = tracer.get_stats()
        assert stats["total_traces"] == 1
        assert stats["total_spans"] == 2
        assert stats["active_spans"] == 2

    def test_no_target_dir_export_returns_none(self):
        tracer = TraceLogger()
        trace_id = tracer.start_trace("scan")
        tracer.end_trace(trace_id)
        result = tracer.export(trace_id)
        assert result is None
