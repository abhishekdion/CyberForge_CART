"""Unified report generator + local findings API (spec section 5.10, FR-7)."""

from __future__ import annotations


class ReportGenerator:
    """One consolidated report per run.

    Contents (spec Phase H): exec summary + run metadata, scope + exclusions,
    inventory, findings with severity/status/PTES/evidence/remediation,
    evidence-backed attack path, coverage/verification/false-alarm/scope/
    runtime/autonomy metrics, tool/agent summary and limitations.

    Judge path: README -> one launch command -> select lab -> one report.
    """

    def generate(self, run_id: str) -> dict:  # noqa: ARG002
        raise NotImplementedError("integrated in build-order step 8")
