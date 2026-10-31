"""Evidence-backed attack-path builder (spec section 5.9, bonus B-2)."""

from __future__ import annotations


class AttackPathBuilder:
    """Builds graph paths ONLY from validated Relationships.

    Distinguishes:
    - discovered adjacency (same network is NOT enough)
    - demonstrated reachability (a permitted test result)
    - demonstrated weakness (a verified finding)

    Every edge must point at the evidence that justifies it. The builder
    never invents edges to make a path look complete.
    """

    def build(self) -> list[list[str]]:  # noqa: ARG002
        raise NotImplementedError("integrated in build-order step 8")
