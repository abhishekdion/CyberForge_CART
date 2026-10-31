"""Network specialist (spec section 5.5, PRD FR-1)."""

from __future__ import annotations

from ..models import Task


class NetworkWorker:
    """In-scope live host / port / service discovery.

    Suggested adapter: Nmap with machine-readable XML output (per Phase 3
    research). Masscan stays optional until benchmark evidence demands it.

    Input contract: run_id, scope_version, bounded target, PTES phase
    (intelligence-gathering), permitted adapter, timeout/retry/output budget.
    Output contract: canonical Asset/Service records, candidate findings with
    concrete observations only, evidence refs, suggested follow-up tasks using
    REGISTERED task types (e.g. web_task for in-scope web services).
    """

    def run(self, task: Task) -> dict:  # noqa: ARG002
        raise NotImplementedError("integrated in build-order step 5")
