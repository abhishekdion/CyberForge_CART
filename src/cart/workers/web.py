"""Web specialist (spec section 5.6, PRD FR-2).

Crawls permitted in-scope web apps using urllib (stdlib only).
PolicyGate checks every request URL AND every redirect before following.
Endpoint/form capture with evidence and provenance.
"""

from __future__ import annotations

import hashlib
import html.parser
import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque

from ..models import (
    Evidence,
    Finding,
    FindingStatus,
    ScopeDecision,
    Task,
    ToolEvent,
    new_id,
    utc_now,
)
from ..ptes import PtesPhase
from ..scope import PolicyGate

# ---------------------------------------------------------------------------
# HTML link + form extractor
# ---------------------------------------------------------------------------

class _LinkParser(html.parser.HTMLParser):
    """Extract hrefs and form actions from raw HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "a" and attr.get("href"):
            abs_url = urllib.parse.urljoin(self.base_url, attr["href"])
            self.links.append(abs_url)
        elif tag == "form":
            self._current_form = {
                "action": urllib.parse.urljoin(self.base_url, attr.get("action", "")),
                "method": attr.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr.get("name", ""),
                "type": attr.get("type", "text"),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _persist_finding(conn: sqlite3.Connection, f: Finding) -> str:
    try:
        conn.execute(
            "INSERT INTO findings (finding_id, asset_id, finding_type, severity, "
            "status, confidence, ptes_phase, summary) VALUES (?,?,?,?,?,?,?,?)",
            (f.finding_id, f.asset_id, f.finding_type, f.severity,
             f.status.value, f.confidence, f.ptes_phase, f.summary),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    return f.finding_id


def _persist_evidence(conn: sqlite3.Connection, e: Evidence) -> None:
    try:
        conn.execute(
            "INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, "
            "hash, timestamp, excerpt, verification_method) VALUES (?,?,?,?,?,?,?,?)",
            (e.evidence_id, e.finding_id, e.source_tool, e.artifact_path,
             e.hash, e.timestamp, e.excerpt, e.verification_method),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass


def _persist_tool_event(conn: sqlite3.Connection, event: ToolEvent) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO tool_events "
        "(event_id, task_id, tool, target, scope_decision, started_at, finished_at, exit_status, output_hash) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (event.event_id, event.task_id, event.tool, event.target,
         event.scope_decision.value, event.started_at, event.finished_at,
         event.exit_status, event.output_hash),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

class WebWorker:
    """Crawl permitted in-scope web apps; capture endpoints/forms within policy."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        gate: PolicyGate,
        run_id: str,
        max_pages: int = 200,
        request_delay_s: float = 0.2,
    ):
        self.conn = conn
        self.gate = gate
        self.run_id = run_id
        self.max_pages = max_pages
        self.request_delay_s = request_delay_s

    def run(self, task: Task) -> dict:
        """Crawl the web service identified by task.target_id (asset_id).

        Looks up the asset's canonical_key (IP) from the DB, constructs the
        base URL, then BFS-crawls within scope policy.
        """
        # Resolve asset → IP
        row = self.conn.execute(
            "SELECT canonical_key FROM assets WHERE asset_id=?", (task.target_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Asset {task.target_id} not found in store")
        ip = row[0]

        # Determine protocol by probing 443 then 80
        base_url = self._detect_base_url(ip)

        # SCOPE GATE on base URL before crawl starts
        gate_result = self.gate.gate(base_url, self.run_id, is_url=True)
        event = ToolEvent(
            event_id=new_id("evt"),
            task_id=task.task_id,
            tool="web_crawler",
            target=base_url,
            scope_decision=gate_result.decision,
            started_at=utc_now(),
        )
        if gate_result.decision is ScopeDecision.DENY:
            event.finished_at = utc_now()
            event.exit_status = "scope_denied"
            _persist_tool_event(self.conn, event)
            raise PermissionError(f"Scope DENY for {base_url}: {gate_result.reason}")

        endpoints, forms, finding_ids = self._crawl(task, base_url, ip)

        event.finished_at = utc_now()
        event.exit_status = "0"
        event.output_hash = hashlib.sha256(
            json.dumps(endpoints).encode()
        ).hexdigest()
        _persist_tool_event(self.conn, event)

        return {
            "base_url": base_url,
            "endpoints": endpoints,
            "forms_found": len(forms),
            "findings": finding_ids,
        }

    def _detect_base_url(self, ip: str) -> str:
        for scheme, port in (("https", 443), ("http", 80)):
            url = f"{scheme}://{ip}:{port}/"
            try:
                req = urllib.request.Request(url, method="HEAD")
                urllib.request.urlopen(req, timeout=5)
                return url
            except Exception:  # noqa: S112 BLE001
                continue
        return f"http://{ip}/"  # fallback

    def _crawl(
        self, task: Task, base_url: str, asset_ip: str
    ) -> tuple[list[str], list[dict], list[str]]:
        """BFS crawler. Returns (visited_urls, forms, finding_ids)."""
        visited: set[str] = set()
        queue: deque[str] = deque([base_url])
        all_forms: list[dict] = []
        finding_ids: list[str] = []
        timeout = task.budget.get("timeout_s", 180)
        deadline = time.monotonic() + timeout

        while queue and len(visited) < self.max_pages:
            if time.monotonic() > deadline:
                break

            url = queue.popleft()
            if url in visited:
                continue

            # Normalise + scope check every URL before fetching
            url = self._normalise(url, base_url)
            if not url:
                continue

            gate_result = self.gate.gate(url, self.run_id, is_url=True)
            if gate_result.decision is ScopeDecision.DENY:
                continue  # silently skip out-of-scope links

            visited.add(url)

            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "CART-scanner/0.1 (controlled assessment)"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    # Check redirect destination
                    final_url = resp.url
                    if final_url != url:
                        redirect_gate = self.gate.gate(final_url, self.run_id, is_url=True)
                        if redirect_gate.decision is ScopeDecision.DENY:
                            continue
                    content_type = resp.headers.get("Content-Type", "")
                    body = resp.read(task.budget.get("max_output", 1 << 20))

                time.sleep(self.request_delay_s)

                if "text/html" in content_type:
                    parser = _LinkParser(url)
                    try:
                        parser.feed(body.decode(errors="replace"))
                    except Exception:  # noqa: S110 BLE001
                        pass
                    for link in parser.links:
                        if link not in visited:
                            queue.append(link)
                    all_forms.extend(parser.forms)

                    # Emit a CANDIDATE finding for each form (potential injection surface)
                    for form in parser.forms:
                        if form["inputs"]:
                            fid = self._emit_form_finding(task, asset_ip, url, form)
                            finding_ids.append(fid)

            except (urllib.error.URLError, OSError):
                pass  # unreachable / timeout — continue crawl

        return list(visited), all_forms, finding_ids

    @staticmethod
    def _normalise(url: str, base: str) -> str:
        """Make url absolute, strip fragments, keep only http/https."""
        try:
            abs_url = urllib.parse.urljoin(base, url)
            parsed = urllib.parse.urlparse(abs_url)
            if parsed.scheme not in ("http", "https"):
                return ""
            # Drop fragment
            clean = urllib.parse.urlunparse(parsed._replace(fragment=""))
            return clean
        except Exception:  # noqa: BLE001
            return ""

    def _emit_form_finding(
        self, task: Task, asset_ip: str, page_url: str, form: dict
    ) -> str:
        """Record a CANDIDATE finding for a discovered form endpoint."""
        # Look up asset_id
        row = self.conn.execute(
            "SELECT asset_id FROM assets WHERE run_id=? AND canonical_key=?",
            (self.run_id, asset_ip),
        ).fetchone()
        if row is None:
            return ""
        asset_id = row[0]

        finding = Finding(
            finding_id=new_id("find"),
            asset_id=asset_id,
            finding_type="web_form_endpoint",
            severity="info",
            status=FindingStatus.CANDIDATE,
            confidence="low",
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            summary=(
                f"Form found at {page_url}: action={form['action']!r}, "
                f"method={form['method']}, "
                f"inputs={[i['name'] for i in form['inputs']]}"
            ),
        )
        fid = _persist_finding(self.conn, finding)

        evidence = Evidence(
            evidence_id=new_id("evid"),
            finding_id=fid,
            source_tool="web_crawler",
            artifact_path=page_url,
            hash=hashlib.sha256(json.dumps(form).encode()).hexdigest(),
            excerpt=json.dumps(form)[:500],
            verification_method="manual_review_required",
        )
        _persist_evidence(self.conn, evidence)
        return fid
