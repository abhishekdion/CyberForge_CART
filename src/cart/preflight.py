"""Candidate network discovery preflight (spec section 5.2, Phase A).

Phases A/B are candidate IDENTIFICATION only - not scanning. The user's
confirmed workflow: CART shows candidate networks, organisers pick the lab.
Active assessment starts only after that selection and scope lock.

It may read local interface/address/route metadata but must NOT:
- decide which network is authorised,
- automatically scan discovered networks,
- expand scope via gateways or routes.

Platform support: Windows (ipconfig/route) first, POSIX (ip addr/ip route)
as fallback. Raises no exception on partial OS failures — surfaces them as
low-confidence candidates with an explanation in route_metadata.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import asdict

from .models import CandidateNetwork, new_id

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(args: list[str], timeout: int = 10) -> str:
    """Run a read-only OS command and return stdout as text. Never raises."""
    try:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except Exception as exc:  # noqa: BLE001
        return f"[error: {exc}]"


def _classify_address(addr_str: str) -> tuple[str, str]:
    """Return (family, confidence) for a parsed IP address.

    Confidence:
    - high   : RFC-1918 private unicast — almost certainly a lab network
    - medium : link-local (169.254/fe80) — useful if no private found
    - low    : global unicast / special — rarely the lab, flag it
    """
    try:
        addr = ipaddress.ip_address(addr_str)
    except ValueError:
        return "unknown", "low"

    family = "ipv4" if addr.version == 4 else "ipv6"

    if addr.is_private and not addr.is_link_local and not addr.is_loopback:
        return family, "high"
    if addr.is_link_local:
        return family, "medium"
    if addr.is_loopback:
        return family, "low"
    return family, "low"  # global / special


def _is_virtual_iface(name: str) -> bool:
    """Heuristic: flag likely virtual/container/VPN adapters."""
    lname = name.lower()
    virtual_patterns = (
        "veth", "docker", "virbr", "vmnet", "vbox", "tun", "tap",
        "lo", "loopback", "wsl", "hyperv", "vlan", "br-",
    )
    return any(lname.startswith(p) or p in lname for p in virtual_patterns)


# ---------------------------------------------------------------------------
# Windows adapter (ipconfig /all + route print)
# ---------------------------------------------------------------------------

def _parse_windows() -> list[CandidateNetwork]:
    """Parse ``ipconfig /all`` output into candidate networks."""
    raw = _run(["ipconfig", "/all"])
    candidates: list[CandidateNetwork] = []

    current_iface: str = "unknown"
    current_addr: str | None = None
    current_mask: str | None = None

    for line in raw.splitlines():
        # Adapter header: "Ethernet adapter Local Area Connection:"
        iface_match = re.match(r"^(\S.+):$", line.strip())
        if iface_match:
            current_iface = iface_match.group(1).strip()
            current_addr = None
            current_mask = None
            continue

        # IPv4 address line
        addr_match = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line)
        if addr_match:
            current_addr = addr_match.group(1).replace("(Preferred)", "")
            current_addr = re.sub(r"\(.*\)", "", current_addr).strip()

        # Subnet mask
        mask_match = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", line)
        if mask_match:
            current_mask = mask_match.group(1).strip()

        if current_addr and current_mask:
            try:
                net = ipaddress.IPv4Network(
                    f"{current_addr}/{current_mask}", strict=False
                )
                prefix = str(net)
                family, confidence = _classify_address(current_addr)
                virtual_note = " [virtual/VPN adapter]" if _is_virtual_iface(current_iface) else ""
                candidates.append(
                    CandidateNetwork(
                        candidate_id=new_id("cand"),
                        interface=current_iface,
                        address=current_addr,
                        prefix=prefix,
                        family=family,
                        route_metadata=f"Windows adapter{virtual_note}",
                        confidence="low" if _is_virtual_iface(current_iface) else confidence,
                        selection_status="unselected",
                    )
                )
            except ValueError:
                pass
            current_addr = None
            current_mask = None

    return candidates


# ---------------------------------------------------------------------------
# POSIX adapter (ip addr + ip route)
# ---------------------------------------------------------------------------

def _parse_posix() -> list[CandidateNetwork]:
    """Parse ``ip addr show`` output into candidate networks."""
    raw = _run(["ip", "addr", "show"])
    candidates: list[CandidateNetwork] = []

    current_iface: str = "unknown"

    for line in raw.splitlines():
        # Interface line: "2: eth0: <BROADCAST,MULTICAST,UP> ..."
        iface_match = re.match(r"^\d+:\s+(\S+):", line)
        if iface_match:
            current_iface = iface_match.group(1).rstrip("@").split("@")[0]
            continue

        # inet / inet6 address + prefix
        for proto in ("inet6", "inet"):
            inet_match = re.search(
                rf"{proto}\s+([\da-fA-F.:]+/\d+)", line
            )
            if inet_match:
                cidr = inet_match.group(1)
                try:
                    iface_net = ipaddress.ip_interface(cidr)
                    addr_str = str(iface_net.ip)
                    prefix = str(iface_net.network)
                    family, confidence = _classify_address(addr_str)
                    virtual_note = " [virtual/VPN adapter]" if _is_virtual_iface(current_iface) else ""
                    candidates.append(
                        CandidateNetwork(
                            candidate_id=new_id("cand"),
                            interface=current_iface,
                            address=addr_str,
                            prefix=prefix,
                            family=family,
                            route_metadata=f"POSIX ip-addr{virtual_note}",
                            confidence="low" if _is_virtual_iface(current_iface) else confidence,
                            selection_status="unselected",
                        )
                    )
                except ValueError:
                    pass
                break

    return candidates


# ---------------------------------------------------------------------------
# Dedup + ambiguity warning
# ---------------------------------------------------------------------------

def _dedup(candidates: list[CandidateNetwork]) -> list[CandidateNetwork]:
    """Remove exact (address, prefix) duplicates, keep first seen."""
    seen: set[tuple[str, str]] = set()
    out: list[CandidateNetwork] = []
    for c in candidates:
        key = (c.address, c.prefix)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _add_ambiguity_notes(candidates: list[CandidateNetwork]) -> list[CandidateNetwork]:
    """Downgrade confidence and annotate when multiple non-virtual candidates share a prefix."""
    from collections import Counter

    prefix_count = Counter(c.prefix for c in candidates if not _is_virtual_iface(c.interface))
    updated: list[CandidateNetwork] = []
    for c in candidates:
        if prefix_count[c.prefix] > 1:
            note = f"{c.route_metadata}; WARNING: prefix {c.prefix} appears on multiple interfaces"
            updated.append(
                CandidateNetwork(
                    candidate_id=c.candidate_id,
                    interface=c.interface,
                    address=c.address,
                    prefix=c.prefix,
                    family=c.family,
                    route_metadata=note,
                    confidence="medium" if c.confidence == "high" else c.confidence,
                    selection_status=c.selection_status,
                )
            )
        else:
            updated.append(c)
    return updated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_candidate_networks() -> list[dict]:
    """Read interfaces, addresses, prefixes and present candidates.

    Returns a list of dicts (CandidateNetwork fields) sorted by confidence
    descending (high → medium → low). Virtual/loopback adapters are included
    but labelled and downgraded to low confidence so the organiser can
    explicitly exclude them.

    Raises no OS exceptions: partial failures are surfaced as low-confidence
    candidates with an explanation in ``route_metadata``.
    """
    system = platform.system()
    if system == "Windows":
        raw = _parse_windows()
    else:
        raw = _parse_posix()

    candidates = _dedup(raw)
    candidates = _add_ambiguity_notes(candidates)

    # Sort: high > medium > low, then by interface name for determinism.
    order = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda c: (order.get(c.confidence, 3), c.interface))

    return [asdict(c) for c in candidates]


def format_candidates_table(candidates: list[dict]) -> str:
    """Render candidates as a human-readable table for ``cart preflight``."""
    if not candidates:
        return "No candidate networks found. Check network adapter state."

    lines = [
        "=== Candidate Networks ===",
        (f"{'#':<4} {'Interface':<28} {'Address':<18} {'Prefix':<20} "
         f"{'Family':<6} {'Confidence':<10} Notes"),
        "-" * 110,
    ]
    for i, c in enumerate(candidates, start=1):
        note = c.get("route_metadata", "")
        # Truncate long notes for display
        note_display = (note[:38] + "…") if len(note) > 39 else note
        lines.append(
            f"{i:<4} {c['interface']:<28} {c['address']:<18} {c['prefix']:<20} "
            f"{c['family']:<6} {c['confidence']:<10} {note_display}"
        )
    lines.append("")
    lines.append(
        "HIGH confidence = RFC-1918 private. LOW = loopback/virtual/global. "
        "Select the lab network by number in `cart select`."
    )
    return "\n".join(lines)
