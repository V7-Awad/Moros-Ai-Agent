#!/usr/bin/env python3
"""
trace_logger.py — Observability & Structured Tracing for Moros.

Emits OpenTelemetry-compatible structured traces for every agent step:
tool calls, LLM requests, findings, and errors. Supports:
- Per-step span recording (start/end, duration, tokens, cost)
- Hierarchical trace structure (scan -> skill -> step)
- JSON export to targets/<target>/output/traces/
- Dashboard "show your work" data feed
- Integration with run_manager event stream
"""

import json
import logging
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("trace-logger")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_id() -> str:
    return uuid.uuid4().hex[:16]


class Span:
    """
    A single unit of work in a trace.
    Roughly models an OpenTelemetry Span.
    """

    def __init__(self, name: str, trace_id: str, parent_id: str = "",
                 span_type: str = "generic", attributes: Dict[str, Any] = None):
        self.span_id = _gen_id()
        self.trace_id = trace_id
        self.parent_id = parent_id
        self.name = name
        self.span_type = span_type  # "scan", "skill", "step", "tool", "llm"
        self.status = "running"
        self.start_time = _now_iso()
        self.end_time: Optional[str] = None
        self.duration_ms: float = 0.0
        self.attributes: Dict[str, Any] = dict(attributes) if attributes else {}
        self.events: List[Dict[str, Any]] = []
        self._start_mono = time.monotonic()

    def add_event(self, name: str, attributes: Dict[str, Any] = None):
        self.events.append({
            "name": name,
            "timestamp": _now_iso(),
            "attributes": dict(attributes) if attributes else {},
        })

    def end(self, status: str = "ok", error: str = "", duration_ms: Optional[float] = None):
        self.end_time = _now_iso()
        if duration_ms is not None:
            self.duration_ms = round(duration_ms, 1)
        else:
            self.duration_ms = round((time.monotonic() - self._start_mono) * 1000, 1)
        self.status = status
        if error:
            self.attributes["error.message"] = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "type": self.span_type,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "events": self.events,
        }


class TraceLogger:
    """
    Hierarchical trace logger for the entire scan lifecycle.

    Usage:
        tracer = TraceLogger(target_dir)
        trace_id = tracer.start_trace("full-scan")

        skill_span = tracer.start_span("xss-reflected", trace_id, span_type="skill")
        step_span = tracer.start_span("http_get /login", trace_id,
                                       parent_id=skill_span.span_id, span_type="tool")
        step_span.attributes["http.url"] = "https://target.com/login"
        tracer.end_span(step_span)
        tracer.end_span(skill_span)

        tracer.end_trace(trace_id)
        tracer.export(trace_id)
    """

    def __init__(self, target_dir: Path = None):
        self._target_dir = Path(target_dir) if target_dir else None
        self._traces: Dict[str, List[Span]] = {}
        self._active_spans: Dict[str, Span] = {}
        self._lock = threading.Lock()

    def start_trace(self, name: str = "scan") -> str:
        """Begin a new trace and return the trace_id."""
        trace_id = _gen_id()
        root_span = Span(name=name, trace_id=trace_id, span_type="scan")
        with self._lock:
            self._traces[trace_id] = [root_span]
            self._active_spans[root_span.span_id] = root_span
        logger.info("Trace started: %s (%s)", name, trace_id)
        return trace_id

    def start_span(self, name: str, trace_id: str, parent_id: str = "",
                   span_type: str = "generic",
                   attributes: Dict[str, Any] = None) -> Span:
        """Create and register a new span within a trace."""
        span = Span(
            name=name, trace_id=trace_id, parent_id=parent_id,
            span_type=span_type, attributes=attributes,
        )
        with self._lock:
            if trace_id in self._traces:
                self._traces[trace_id].append(span)
            else:
                self._traces[trace_id] = [span]
            self._active_spans[span.span_id] = span
        return span

    def end_span(self, span: Span, status: str = "ok", error: str = "",
                 duration_ms: Optional[float] = None):
        """Mark a span as completed."""
        span.end(status=status, error=error, duration_ms=duration_ms)
        with self._lock:
            self._active_spans.pop(span.span_id, None)

    def end_trace(self, trace_id: str):
        """End all remaining spans in a trace."""
        with self._lock:
            spans = self._traces.get(trace_id, [])
            for span in spans:
                if span.status == "running":
                    span.end(status="ok")
                self._active_spans.pop(span.span_id, None)

    def record_llm_call(self, trace_id: str, parent_id: str = "",
                        provider: str = "", model: str = "",
                        input_tokens: int = 0, output_tokens: int = 0,
                        cost_usd: float = 0.0, duration_ms: float = 0.0,
                        prompt_preview: str = "") -> Span:
        """Convenience: record an LLM call as a span."""
        span = self.start_span(
            name=f"llm/{provider}/{model}",
            trace_id=trace_id,
            parent_id=parent_id,
            span_type="llm",
            attributes={
                "llm.provider": provider,
                "llm.model": model,
                "llm.input_tokens": input_tokens,
                "llm.output_tokens": output_tokens,
                "llm.cost_usd": round(cost_usd, 6),
                "llm.prompt_preview": prompt_preview[:200] if prompt_preview else "",
            },
        )
        self.end_span(span, duration_ms=duration_ms)
        return span

    def record_tool_call(self, trace_id: str, parent_id: str = "",
                         tool_name: str = "", args_summary: str = "",
                         result_summary: str = "", duration_ms: float = 0.0,
                         success: bool = True) -> Span:
        """Convenience: record a tool invocation as a span."""
        span = self.start_span(
            name=f"tool/{tool_name}",
            trace_id=trace_id,
            parent_id=parent_id,
            span_type="tool",
            attributes={
                "tool.name": tool_name,
                "tool.args": args_summary[:500] if args_summary else "",
                "tool.result": result_summary[:500] if result_summary else "",
            },
        )
        self.end_span(span, status="ok" if success else "error", duration_ms=duration_ms)
        return span

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """Return all spans in a trace as dicts."""
        with self._lock:
            spans = list(self._traces.get(trace_id, []))
        return [s.to_dict() for s in spans]

    def get_all_traces(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return all traces."""
        with self._lock:
            return {
                tid: [s.to_dict() for s in spans]
                for tid, spans in self._traces.items()
            }

    def export(self, trace_id: str = None) -> Optional[Path]:
        """Export trace(s) to JSON files on disk."""
        if not self._target_dir:
            return None

        traces_dir = self._target_dir / "output" / "traces"
        traces_dir.mkdir(parents=True, exist_ok=True)

        if trace_id:
            trace_data = self.get_trace(trace_id)
            if not trace_data:
                return None
            safe_trace_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", trace_id)
            out_path = traces_dir / f"trace-{safe_trace_id}.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(trace_data, f, indent=2, ensure_ascii=False)
            logger.info("Trace exported: %s", out_path)
            return out_path

        # Export all traces
        all_traces = self.get_all_traces()
        out_path = traces_dir / f"traces-{_gen_id()}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(all_traces, f, indent=2, ensure_ascii=False)
        return out_path

    def get_timeline(self, trace_id: str) -> List[Dict[str, Any]]:
        """
        Return a simplified timeline suitable for dashboard display.
        Each entry has: timestamp, name, type, duration_ms, status.
        """
        spans = self.get_trace(trace_id)
        timeline = []
        for s in spans:
            timeline.append({
                "timestamp": s["start_time"],
                "name": s["name"],
                "type": s["type"],
                "duration_ms": s["duration_ms"],
                "status": s["status"],
                "tokens": s["attributes"].get("llm.input_tokens", 0) + s["attributes"].get("llm.output_tokens", 0),
                "cost_usd": s["attributes"].get("llm.cost_usd", 0),
            })
        return sorted(timeline, key=lambda x: x["timestamp"])

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate stats across all traces."""
        with self._lock:
            total_spans = sum(len(spans) for spans in self._traces.values())
            total_traces = len(self._traces)
            active = len(self._active_spans)
        return {
            "total_traces": total_traces,
            "total_spans": total_spans,
            "active_spans": active,
        }
