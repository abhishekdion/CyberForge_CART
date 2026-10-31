"""Network specialist (spec section 5.5, PRD FR-1).

Nmap-based host/port/service discovery. All targets must pass PolicyGate
before any packet is sent. Output is normalised to canonical Asset + Service
records. Never decides to attack — only discovers and proposes follow-up tasks.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import (
    Asset,
    ScopeDecision,
    Service,
    Task,
    ToolEvent,
    new_id,
    utc_now,
)
from ..scope import PolicyGate, ScopeDecisionResult

# Minimum supported Nmap version
_MIN_NMAP_MAJOR = 7


def _check_nmap() -> str:
    """Return path to nmap binary or raise RuntimeError."""
    nmap = shutil.which("nmap")
    if nmap is None:
        raise RuntimeError(
            "nmap not found in PATH. Install nmap >= 7 and ensure it is on PATH."
        )
    try:
        out = subprocess.run(
            [nmap, "--version"], check=False, capture_output=True, text=True, timeout=10
        ).stdout
        # "Nmap 7.94 ..."
        import re
        m = re.search(r"Nmap (\d+)\.", out)
        if m and int(m.group(1)) < _MIN_NMAP_MAJOR:
            raise RuntimeError(f"nmap version too old: {out.splitlines()[0]}")
    except FileNotFoundError as exc:
        raise RuntimeError(f"nmap not executable: {exc}") from exc
    return nmap


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_nmap(nmap: str, args: list[str], timeout: int = 300) -> bytes:
    """Run nmap, return raw XML bytes. Raises on non-zero exit."""
    result = subprocess.run(
        [nmap, *args],
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode not in (0, 1):  # nmap exits 1 for "host down" runs
        raise RuntimeError(
            f"nmap exited {result.returncode}: {result.stderr.decode(errors='replace')}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# XML normaliser
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_bytes: bytes, run_id: str) -> tuple[list[Asset], list[Service]]:
    """Parse Nmap XML output → (assets, services)."""
    root = ET.fromstring(xml_bytes)
    assets: list[Asset] = []
    services: list[Service] = []

    for host_el in root.findall("host"):
        # Status check — only process hosts reported up
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        # Canonical IP
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        asset = Asset(
            asset_id=new_id("asset"),
            run_id=run_id,
            asset_type="host",
            canonical_key=ip,
        )
        assets.append(asset)

        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port_num = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            version = ""
            if svc_el is not None:
                parts = [svc_el.get("product", ""), svc_el.get("version", "")]
                version = " ".join(p for p in parts if p).strip()

            services.append(
                Service(
                    service_id=new_id("svc"),
                    asset_id=asset.asset_id,
                    protocol=proto,
                    port=port_num,
                    service_name=svc_name,
                    version=version,
                    state="open",
                )
            )

    return assets, services


# ---------------------------------------------------------------------------
# DB persistence helpers
# ---------------------------------------------------------------------------

def _persist_asset(conn: sqlite3.Connection, asset: Asset) -> str:
    """Upsert asset, return actual asset_id (existing or new)."""
    try:
        conn.execute(
            "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (asset.asset_id, asset.run_id, asset.asset_type, asset.canonical_key,
             asset.first_seen, asset.last_seen),
        )
        conn.commit()
        return asset.asset_id
    except sqlite3.IntegrityError:
        # Already exists — return existing id, update last_seen
        row = conn.execute(
            "SELECT asset_id FROM assets WHERE run_id=? AND asset_type=? AND canonical_key=?",
            (asset.run_id, asset.asset_type, asset.canonical_key),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE assets SET last_seen=? WHERE asset_id=?",
                (utc_now(), row[0]),
            )
            conn.commit()
            return row[0]
        return asset.asset_id


def _persist_service(conn: sqlite3.Connection, svc: Service) -> None:
    try:
        conn.execute(
            "INSERT INTO services (service_id, asset_id, protocol, port, service_name, version, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (svc.service_id, svc.asset_id, svc.protocol, svc.port,
             svc.service_name, svc.version, svc.state),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # duplicate service — idempotent


def _persist_tool_event(conn: sqlite3.Connection, event: ToolEvent) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO tool_events "
        "(event_id, task_id, tool, target, scope_decision, started_at, finished_at, exit_status, output_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event.event_id, event.task_id, event.tool, event.target,
         event.scope_decision.value, event.started_at, event.finished_at,
         event.exit_status, event.output_hash),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

_WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}


class NetworkWorker:
    """In-scope live host / port / service discovery."""

    def __init__(self, conn: sqlite3.Connection, gate: PolicyGate, run_id: str):
        self.conn = conn
        self.gate = gate
        self.run_id = run_id
        self._nmap = _check_nmap()

    def run(self, task: Task) -> dict:
        """Execute host + port discovery for task.target_id (an IP/CIDR).

        Returns dict with keys: assets, services, web_asset_ids, findings.
        """
        target = task.target_id

        # SCOPE GATE — must pass before any packet
        result: ScopeDecisionResult = self.gate.gate(target, self.run_id)
        event = ToolEvent(
            event_id=new_id("evt"),
            task_id=task.task_id,
            tool="nmap",
            target=target,
            scope_decision=result.decision,
            started_at=utc_now(),
        )

        if result.decision is ScopeDecision.DENY:
            event.finished_at = utc_now()
            event.exit_status = "scope_denied"
            _persist_tool_event(self.conn, event)
            raise PermissionError(f"Scope DENY for target {target!r}: {result.reason}")

        # Run Nmap — host discovery first, then service scan
        with tempfile.TemporaryDirectory() as tmpdir:
            xml_path = Path(tmpdir) / "scan.xml"
            nmap_args = [
                "-sV",            # version detection
                "--open",         # only open ports
                "-T4",            # aggressive timing (lab environment)
                "--max-retries", "2",
                "--host-timeout", str(task.budget.get("timeout_s", 120)) + "s",
                "-oX", str(xml_path),
                target,
            ]
            try:
                xml_bytes = _run_nmap(self._nmap, nmap_args, timeout=task.budget.get("timeout_s", 300))
                if xml_path.exists():
                    xml_bytes = xml_path.read_bytes()
            except RuntimeError as exc:
                event.finished_at = utc_now()
                event.exit_status = f"error:{exc}"
                _persist_tool_event(self.conn, event)
                raise

        output_hash = _sha256_bytes(xml_bytes)
        event.finished_at = utc_now()
        event.exit_status = "0"
        event.output_hash = output_hash
        _persist_tool_event(self.conn, event)

        # Normalise XML
        assets, services = _parse_nmap_xml(xml_bytes, self.run_id)

        # Persist + track web assets
        web_asset_ids: list[str] = []
        for asset in assets:
            actual_id = _persist_asset(self.conn, asset)
            asset.asset_id = actual_id  # update for service FK

        for svc in services:
            # Re-map asset_id to persisted value
            for asset in assets:
                if svc.asset_id == asset.asset_id:
                    break
            _persist_service(self.conn, svc)
            if svc.port in _WEB_PORTS:
                # Scope-check the specific web service before marking web
                web_result = self.gate.gate(asset.canonical_key, self.run_id, is_url=False)
                if web_result.decision is ScopeDecision.ALLOW:
                    web_asset_ids.append(asset.asset_id)

        return {
            "assets": [a.asset_id for a in assets],
            "services": len(services),
            "web_asset_ids": list(set(web_asset_ids)),
            "findings": [],
        }
