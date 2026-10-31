"""Web specialist (spec section 5.6, PRD FR-2)."""

from __future__ import annotations

from ..models import Task


class WebWorker:
    """Crawl permitted in-scope web apps; run configured checks within policy.

    Suggested adapters: Katana (endpoint discovery), OWASP ZAP (controlled
    checks). Discovery and verification are distinct: crawler output alone is
    never proof of a vulnerability.

    Hard rules:
    - receives ONLY in-scope web service tasks (created by Network Worker)
    - the policy gate checks every request AND every redirect destination
      so crawling cannot follow links out of scope (fail closed)
    - record request/response evidence with source provenance
    """

    def run(self, task: Task) -> dict:  # noqa: ARG002
        raise NotImplementedError("integrated in build-order step 6")
