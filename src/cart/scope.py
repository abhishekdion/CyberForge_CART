"""Scope registry and execution policy gate (spec section 5.3, 10).

SECURITY BOUNDARY: this module is deterministic code, not an LLM prompt.
Every tool action must pass the gate immediately before execution. The gate
fails closed: missing, ambiguous or unresolvable scope means DENY.
"""

from __future__ import annotations

import ipaddress
import socket
import sqlite3
import threading
from dataclasses import dataclass
from urllib.parse import urlparse

from .models import ScopeDecision, ScopeManifest, new_id, utc_now


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
        self._conn: sqlite3.Connection | None = None
        self._thread_store = threading.local()
        self._record_lock = threading.Lock()
        # In-run downloaded copies of in-scope content (web→binary hand-off).
        # NEVER writes to the locked manifest; targets themselves never grow.
        self._dynamic_binaries: dict[str, str] = {}  # path -> sha256

    def bind_store(self, conn: sqlite3.Connection) -> None:
        """Attach a DB connection for audit writes in the current thread."""
        self._conn = conn
        self._thread_store.conn = conn

    # ------------------------------------------------------------------
    # Core IP/network checks
    # ------------------------------------------------------------------

    def check_destination(self, target: str) -> ScopeDecisionResult:
        """Check one network destination (IP or CIDR) against the locked scope."""
        try:
            net = ipaddress.ip_network(target, strict=False)
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

    # ------------------------------------------------------------------
    # URL / web check (resolves hostname → IP, then delegates to check_ip)
    # ------------------------------------------------------------------

    def check_url(self, url: str) -> ScopeDecisionResult:
        """Check a web URL incl. hostname resolution against the locked scope.

        Steps:
        1. Parse the URL — if unparseable, DENY immediately.
        2. Resolve the hostname to IP(s) — resolution failure → DENY.
        3. Every resolved IP must pass check_ip (exclusions win).
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
        except Exception:  # noqa: BLE001
            return ScopeDecisionResult(ScopeDecision.DENY, f"unparseable URL: {url!r}", url)

        if not hostname:
            return ScopeDecisionResult(
                ScopeDecision.DENY, f"no hostname in URL: {url!r}", url
            )

        # Resolve hostname → IPs
        try:
            addr_infos = socket.getaddrinfo(hostname, None)
            resolved_ips = list({info[4][0] for info in addr_infos})
        except socket.gaierror as exc:
            return ScopeDecisionResult(
                ScopeDecision.DENY,
                f"hostname {hostname!r} could not be resolved: {exc}",
                url,
            )

        for ip_str in resolved_ips:
            result = self.check_ip(ip_str)
            if result.decision is ScopeDecision.DENY:
                return ScopeDecisionResult(
                    ScopeDecision.DENY,
                    f"URL {url!r} resolves to {ip_str} which is {result.reason}",
                    url,
                )

        return ScopeDecisionResult(
            ScopeDecision.ALLOW,
            f"URL hostname {hostname!r} resolves to in-scope IPs",
            url,
        )

    # ------------------------------------------------------------------
    # Binary file check
    # ------------------------------------------------------------------

    def register_dynamic_binary(
        self,
        path: str,
        sha256: str,
        *,
        reason: str = "",
        run_id: str | None = None,
    ) -> None:
        """Authorise *static analysis only* of a downloaded copy of content
        that was fetched from an already-authorised, gate-allowed in-scope URL
        (web→binary hand-off).

        This does NOT touch the locked manifest and does NOT widen the target
        scope — the destination was already validated. Every registration is
        recorded in the audit log with the reason.
        """
        self._dynamic_binaries[path] = sha256
        result = ScopeDecisionResult(
            ScopeDecision.ALLOW,
            reason or "downloaded copy of in-scope URL content (static analysis only)",
            path,
        )
        self.record_decision(path, result, run_id)

    def check_binary_file(self, path: str) -> ScopeDecisionResult:
        sha256 = self.manifest.binary_hashes.get(path)
        if sha256 is None:
            # Fall back to in-run downloaded copies (fail closed for anything else)
            sha256 = self._dynamic_binaries.get(path)
        if sha256 is None:
            return ScopeDecisionResult(
                ScopeDecision.DENY,
                f"{path!r} is not an organiser-registered binary",
                path,
            )
        return ScopeDecisionResult(ScopeDecision.ALLOW, "registered binary hash", path)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def record_decision(
        self,
        requested: str,
        result: ScopeDecisionResult,
        run_id: str | None = None,
    ) -> None:
        """Persist allow/deny decisions in scope_decisions_log (audit requirement)."""
        if self._conn is None:
            return  # store not bound yet (e.g. during preflight / unit tests)
        conn = getattr(self._thread_store, "conn", self._conn)
        event_id = new_id("sdl")
        values = (
            event_id,
            run_id,
            requested,
            result.decision.value,
            result.reason,
            utc_now(),
        )
        query = """
            INSERT INTO scope_decisions_log
                (event_id, run_id, requested_target, decision, reason, at)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        with self._record_lock:
            conn.execute(query, values)
            conn.commit()

    # ------------------------------------------------------------------
    # Convenience: check + record in one call
    # ------------------------------------------------------------------

    def gate(
        self,
        target: str,
        run_id: str | None = None,
        *,
        is_url: bool = False,
        is_binary: bool = False,
    ) -> ScopeDecisionResult:
        """All-in-one gate: check + record decision. Raises nothing — callers
        must inspect result.decision and refuse action on DENY."""
        if is_url:
            result = self.check_url(target)
        elif is_binary:
            result = self.check_binary_file(target)
        else:
            result = self.check_destination(target)
        self.record_decision(target, result, run_id)
        return result
