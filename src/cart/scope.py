"""Scope registry and execution policy gate (spec section 5.3, 10).

SECURITY BOUNDARY: this module is deterministic code, not an LLM prompt.
Every tool action must pass the gate immediately before execution. The gate
fails closed: missing, ambiguous or unresolvable scope means DENY.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import ScopeDecision, ScopeManifest


class ScopeNotLockedError(RuntimeError):
    pass


@dataclass
class ScopeDecisionResult:
    decision: ScopeDecision
    reason: str
    resolved_target: str


class PolicyGate:
    """Shared gate used by the controller and every specialist worker."""

    def __init__(self, manifest: ScopeManifest):
        if manifest.locked_at is None:
            raise ScopeNotLockedError(
                "Scope manifest is not locked. No tool action may run until the "
                "organiser-selected scope is locked and versioned."
            )
        self.manifest = manifest
        self._nets = [
            ipaddress.ip_network(p, strict=False) for p in manifest.included_prefixes
        ]
        self._hosts = [ipaddress.ip_address(h) for h in manifest.included_hosts]
        self._excluded_nets = [
            ipaddress.ip_network(e, strict=False) for e in manifest.exclusions
        ]

    def check_destination(self, target: str) -> ScopeDecisionResult:
        """Check one network destination (IP or CIDR) against the locked scope."""
        try:
            net = ipaddress.ip_network(target, strict=False)
            # .hosts() is empty for /32 and /128; fall back to the network address itself.
            all_addrs: list = list(net.hosts()) or [net.network_address]
        except ValueError:
            return ScopeDecisionResult(
                ScopeDecision.DENY, f"unparseable destination: {target!r}", target
            )
        for addr in all_addrs:
            result = self.check_ip(addr)
            if result.decision is ScopeDecision.DENY:
                return result
        return ScopeDecisionResult(ScopeDecision.ALLOW, "in locked scope", target)

    def check_ip(self, ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> ScopeDecisionResult:
        addr = ipaddress.ip_address(ip)
        presented = str(addr)
        # Exclusions always win.
        for net in self._excluded_nets:
            if addr in net:
                return ScopeDecisionResult(
                    ScopeDecision.DENY, f"{presented} is excluded by scope", presented
                )
        for net in self._nets:
            if addr in net:
                return ScopeDecisionResult(
                    ScopeDecision.ALLOW, f"{presented} in {net}", presented
                )
        if addr in self._hosts:
            return ScopeDecisionResult(
                ScopeDecision.ALLOW, f"{presented} in included host list", presented
            )
        return ScopeDecisionResult(
            ScopeDecision.DENY, f"{presented} not resolvable to locked scope", presented
        )

    def check_url(self, url: str) -> ScopeDecisionResult:  # noqa: ARG002
        """Web URL check incl. redirect destinations. Implemented with web worker."""
        raise NotImplementedError("URL/redirect gate lands with the Web Worker (FR-2)")

    def check_binary_file(self, path: str) -> ScopeDecisionResult:
        sha256 = self.manifest.binary_hashes.get(path)
        if sha256 is None:
            return ScopeDecisionResult(
                ScopeDecision.DENY,
                f"{path!r} is not an organiser-registered binary",
                path,
            )
        return ScopeDecisionResult(ScopeDecision.ALLOW, "registered binary hash", path)

    def record_decision(self, requested: str, result: ScopeDecisionResult, run_id: str | None = None) -> None:
        """Persist allow/deny decisions in scope_decisions_log (audit requirement)."""
        # Implemented with store.py wiring in build-order step 3.
        raise NotImplementedError
