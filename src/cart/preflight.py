"""Candidate network discovery preflight (spec section 5.2, Phase A).

Phases A/B are candidate IDENTIFICATION only - not scanning. The user's
confirmed workflow: CART shows candidate networks, organisers pick the lab.
Active assessment starts only after that selection and scope lock.

It may read local interface/address/route metadata but must NOT:
- decide which network is authorised,
- automatically scan discovered networks,
- expand scope via gateways or routes.
"""

from __future__ import annotations


def list_candidate_networks() -> list[dict]:
    """Read interfaces, addresses, prefixes, routes and present candidates.

    Must explain uncertainty (ambiguous/overlapping/virtual interfaces)
    rather than silently picking one. Uses local OS metadata only.
    """
    raise NotImplementedError("integrated in build-order step 2")
