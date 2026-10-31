"""Verification service (spec section 5.8, PRD FR-6)."""

from __future__ import annotations

from .models import FindingStatus


class VerificationService:
    """Turns candidate findings into CONFIRMED / REJECTED / INCONCLUSIVE.

    Rules:
    - deterministic procedures first; LLM may explain evidence or suggest a
      check, but never upgrades a candidate on its own say-so
    - verdict must be grounded in tool output + a repeatable rule
    - verification unavailable => INCONCLUSIVE, never CONFIRMED silently
    - NEEDS_REVIEW is exceptional and must not silently become CONFIRMED
    """

    def queue(self, finding_ids: list[str]) -> None:  # noqa: ARG002
        raise NotImplementedError("integrated in build-order step 7")

    def verify_one(self) -> FindingStatus:  # noqa: ARG002
        raise NotImplementedError
