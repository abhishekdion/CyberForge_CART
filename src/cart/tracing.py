"""Agent tracing (judge requirement 4).

Standardised span tracing for multi-agent coordination:
- Zero-dependency offline mode: span traces are appended as JSON objects to
  `traces/agent_traces.jsonl` (one line per completed span).
- Optional LangSmith export: if LANGSMITH_API_KEY (or LANGCHAIN_API_KEY)
  is present in the environment, completed spans are also posted to the
  LangSmith runs API (best-effort, never raises).

Tracing is observability only — it never affects task state, scheduling or
finding lifecycles.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass
class Span:
    """One timed agent-task invocation."""

    span_id: str
    task_id: str
    agent_name: str
    task_type: str
    run_id: str
    start_time: str
    end_time: str | None = None
    status: str = "running"
    result_summary: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class AgentTracer:
    """Traces agent task workflows, tool events, and decisions.

    If LANGSMITH_API_KEY (or LANGCHAIN_API_KEY) is present in the environment,
    completed spans are also emitted to LangSmith. Otherwise (and always, as a
    durable local record) they are appended to `traces/agent_traces.jsonl`.
    """

    LANGSMITH_ENV_KEYS = ("LANGSMITH_API_KEY", "LANGCHAIN_API_KEY")
    LANGSMITH_ENDPOINT = "https://api.smith.langchain.com/runs"

    def __init__(self, run_id: str, output_dir: str | Path = "traces"):
        self.run_id = run_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._trace_path = self.output_dir / "agent_traces.jsonl"
        self._lock = threading.Lock()
        self._api_key = self._resolve_langsmith_key()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_span(self, task_id: str, agent_name: str, task_type: str) -> Span:
        """Open a span for one agent task invocation."""
        return Span(
            span_id=f"span_{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            agent_name=agent_name,
            task_type=task_type,
            run_id=self.run_id,
            start_time=_utc_now(),
        )

    def end_span(self, span: Span, status: str, result_summary: str = "") -> None:
        """Close a span, persist it to the JSONL trace and (optionally) LangSmith.

        Tracing must never break an assessment run: all persistence failures
        are swallowed.
        """
        if not isinstance(span, Span):
            raise TypeError(f"end_span expects a Span, got {type(span).__name__}")

        span.end_time = _utc_now()
        span.status = status
        span.result_summary = result_summary

        try:
            self._append_local(span)
        except Exception:  # noqa: S110 BLE001 - traces never break runs
            pass

        if self._api_key:
            try:
                self._post_langsmith(span)
            except Exception:  # noqa: S110 BLE001 - remote export is best-effort
                pass

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve_langsmith_key(self) -> str | None:
        for key in self.LANGSMITH_ENV_KEYS:
            value = os.environ.get(key)
            if value:
                return value
        return None

    def _append_local(self, span: Span) -> None:
        """Append one JSON line for the completed span (thread-safe)."""
        # Lock is held across open+append so concurrent worker threads cannot
        # interleave partial JSON lines; file handle is scoped by the with-block.
        with self._lock, open(self._trace_path, "a", encoding="utf-8") as fh:
            fh.write(span.to_json() + "\n")

    def _post_langsmith(self, span: Span) -> None:
        """Best-effort export to the LangSmith runs API (never raises upstream)."""
        duration_ms = None
        if span.end_time:
            try:
                start = datetime.fromisoformat(span.start_time)
                end = datetime.fromisoformat(span.end_time)
                duration_ms = int((end - start).total_seconds() * 1000)
            except ValueError:
                pass

        payload = {
            "id": span.span_id.removeprefix("span_"),
            "name": f"{span.agent_name}:{span.task_type}",
            "run_type": "chain",
            "session_name": self.run_id,
            "run_id": span.task_id,
            "inputs": {"task_id": span.task_id, "agent": span.agent_name},
            "outputs": {"status": span.status, "summary": span.result_summary},
            "status": span.status,
            "error": span.status not in ("ok", "succeeded"),
            "extra": {"metadata": {"span": asdict(span), "duration_ms": duration_ms}},
        }
        req = urllib.request.Request(
            self.LANGSMITH_ENDPOINT,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self._api_key or "",
            },
            method="POST",
        )
        # Bounded timeout; failures are already caught by the caller.
        urllib.request.urlopen(req, timeout=5).close()
