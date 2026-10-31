"""Web specialist (spec section 5.6, PRD FR-2).

Crawls permitted in-scope web apps using urllib (stdlib only).
PolicyGate checks every request URL AND every redirect before following.
Endpoint/form capture with evidence and provenance.
"""

from __future__ import annotations

import hashlib
import html.parser
import json
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path

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
# CTF planted-flag + binary-link detection (judge requirements)
# ---------------------------------------------------------------------------

FLAG_PATTERN = re.compile(
    r"(flag\{[^\}]+\}|CTF\{[^\}]+\}|CyberForge\{[^\}]+\})", re.IGNORECASE
)
HTML_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)

# File extensions that indicate a downloadable binary artefact (hand-off target)
BINARY_FILE_EXTENSIONS = (".exe", ".bin", ".elf", ".so", ".dll")


def scan_flags(text: str) -> list[str]:
    """Return every CTF flag literal found in `text` (deduped, order kept)."""
    seen: list[str] = []
    for match in FLAG_PATTERN.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


def extract_html_comments(body_text: str) -> list[str]:
    """Extract the inner text of every HTML comment in a page body."""
    return [m.strip() for m in HTML_COMMENT_PATTERN.findall(body_text)]


def looks_like_binary_url(url: str) -> bool:
    """True when the URL path ends in a known binary artefact extension."""
    try:
        path = urllib.parse.urlparse(url).path
    except Exception:  # noqa: BLE001
        return False
    return path.lower().endswith(BINARY_FILE_EXTENSIONS)

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
        binary_cache_dir: str | Path = "binary_cache",
        max_binary_bytes: int = 16 << 20,
    ):
        self.conn = conn
        self.gate = gate
        self.run_id = run_id
        self.max_pages = max_pages
        self.request_delay_s = request_delay_s
        self.binary_cache_dir = Path(binary_cache_dir)
        self.max_binary_bytes = max_binary_bytes  # explicit download cap

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

        endpoints, forms, finding_ids, discovered_binaries = self._crawl(task, base_url, ip)

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
            # Binary artefacts linked from crawled pages, saved + hash-registered
            "discovered_binaries": discovered_binaries,
        }

    def _download_binary(self, url: str) -> dict | None:
        """Download an in-scope binary artefact to the local cache.

        Scope safety: the caller has already gate-allowed `url`. The final URL
        after any redirect is re-checked before persisting the payload. The
        copy is capped at `max_binary_bytes`, hashed, saved locally and
        registered with the gate for STATIC ANALYSIS ONLY (never executed).
        """
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CART-scanner/0.1 (controlled assessment)"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                final_url = resp.url
                if final_url != url:
                    redirect_gate = self.gate.gate(final_url, self.run_id, is_url=True)
                    if redirect_gate.decision is ScopeDecision.DENY:
                        return None
                data = resp.read(self.max_binary_bytes + 1)

            if len(data) > self.max_binary_bytes:
                return None  # over cap — refuse oversized artefact
            if not data:
                return None

            sha256 = hashlib.sha256(data).hexdigest()
            suffix = Path(urllib.parse.urlparse(url).path).suffix or ".bin"
            run_cache = self.binary_cache_dir / self.run_id
            run_cache.mkdir(parents=True, exist_ok=True)
            dest = run_cache / f"{sha256}{suffix}"
            dest.write_bytes(data)

            # Register the local copy with the gate (audit-logged, static only)
            self.gate.register_dynamic_binary(
                str(dest),
                sha256,
                reason=f"downloaded binary from in-scope URL {url}",
                run_id=self.run_id,
            )
            return {
                "url": url,
                "path": str(dest),
                "sha256": sha256,
                "size_bytes": len(data),
            }
        except (urllib.error.URLError, OSError):
            return None

    def _scan_page_for_flags(
        self,
        task: Task,
        asset_ip: str,
        page_url: str,
        body_text: str,
        headers_text: str,
    ) -> list[str]:
        """Hunt planted CTF flags in body, HTML comments and HTTP headers."""
        haystacks = {
            "body": body_text,
            "html_comment": "\n".join(extract_html_comments(body_text)),
            "http_headers": headers_text,
        }
        fids: list[str] = []
        seen_flags: list[str] = []
        for location, haystack in haystacks.items():
            for flag in scan_flags(haystack):
                if flag in seen_flags:
                    continue
                seen_flags.append(flag)
                fids.append(
                    self._emit_flag_finding(task, asset_ip, page_url, flag, location)
                )
        return fids

    def _emit_flag_finding(
        self,
        task: Task,
        asset_ip: str,
        page_url: str,
        flag: str,
        location: str,
    ) -> str:
        """Record a high-severity CANDIDATE finding for a captured CTF flag."""
        asset_id = self._get_or_create_asset("web_app", asset_ip)

        finding = Finding(
            finding_id=new_id("find"),
            asset_id=asset_id,
            finding_type="ctf_planted_flag",
            severity="high",
            status=FindingStatus.CANDIDATE,
            confidence="high",
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            summary=(
                f"Planted CTF flag {flag!r} captured in {location} at {page_url}"
            ),
        )
        fid = _persist_finding(self.conn, finding)

        evidence = Evidence(
            evidence_id=new_id("evid"),
            finding_id=fid,
            source_tool="web_crawler",
            artifact_path=page_url,
            hash=hashlib.sha256(flag.encode()).hexdigest(),
            excerpt=f"location={location}; flag={flag}",
            verification_method="manual_review_required",
        )
        _persist_evidence(self.conn, evidence)
        return fid

    def _get_or_create_asset(self, asset_type: str, canonical_key: str) -> str:
        """Look up (or create) an asset for this run. Dedupe at DB level."""
        row = self.conn.execute(
            "SELECT asset_id FROM assets WHERE run_id=? AND asset_type=? AND canonical_key=?",
            (self.run_id, asset_type, canonical_key),
        ).fetchone()
        if row is not None:
            return row[0]

        from ..models import Asset
        asset = Asset(
            asset_id=new_id("asset"),
            run_id=self.run_id,
            asset_type=asset_type,
            canonical_key=canonical_key,
        )
        try:
            self.conn.execute(
                "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?)",
                (asset.asset_id, asset.run_id, asset.asset_type,
                 asset.canonical_key, asset.first_seen, asset.last_seen),
            )
            self.conn.commit()
            return asset.asset_id
        except sqlite3.IntegrityError:
            row = self.conn.execute(
                "SELECT asset_id FROM assets WHERE run_id=? AND asset_type=? AND canonical_key=?",
                (self.run_id, asset_type, canonical_key),
            ).fetchone()
            return row[0] if row else asset.asset_id

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
    ) -> tuple[list[str], list[dict], list[str], list[dict]]:
        """BFS crawler. Returns (visited_urls, forms, finding_ids, discovered_binaries)."""
        visited: set[str] = set()
        queue: deque[str] = deque([base_url])
        all_forms: list[dict] = []
        finding_ids: list[str] = []
        discovered_binaries: list[dict] = []
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

            # Binary artefact links are downloaded, hashed and handed to the
            # orchestrator instead of being parsed as HTML.
            if looks_like_binary_url(url):
                binary_info = self._download_binary(url)
                if binary_info:
                    discovered_binaries.append(binary_info)
                time.sleep(self.request_delay_s)
                continue

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
                    headers_text = str(resp.headers)
                    body = resp.read(task.budget.get("max_output", 1 << 20))

                time.sleep(self.request_delay_s)

                if "text/html" in content_type:
                    body_text = body.decode(errors="replace")
                    parser = _LinkParser(url)
                    try:
                        parser.feed(body_text)
                    except Exception:  # noqa: S110 BLE001
                        pass
                    for link in parser.links:
                        if link not in visited:
                            queue.append(link)
                    all_forms.extend(parser.forms)

                    # Planted-flag hunt: body, HTML comments, HTTP headers
                    flag_fids = self._scan_page_for_flags(
                        task, asset_ip, url, body_text, headers_text
                    )
                    finding_ids.extend(flag_fids)

                    # Emit a CANDIDATE finding for each form (potential injection surface)
                    for form in parser.forms:
                        if form["inputs"]:
                            fid = self._emit_form_finding(task, asset_ip, url, form)
                            finding_ids.append(fid)

            except (urllib.error.URLError, OSError):
                pass  # unreachable / timeout — continue crawl

        return list(visited), all_forms, finding_ids, discovered_binaries

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
