"""Binary specialist (spec section 5.7, PRD FR-3).

Static analysis of organiser-supplied, hash-registered binaries only.
Uses stdlib only: struct for ELF/PE headers, subprocess for strings(1)/
findstr fallback. Never opens a file whose sha256 is not in the manifest.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import struct
import subprocess
from collections.abc import Iterable
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
# CTF planted-flag + unsafe libc function detection (judge requirements)
# ---------------------------------------------------------------------------

FLAG_PATTERN = re.compile(
    r"(flag\{[^\}]+\}|CTF\{[^\}]+\}|CyberForge\{[^\}]+\})", re.IGNORECASE
)

UNSAFE_FUNCTIONS = {
    "strcpy": "Unbounded string copy prone to stack buffer overflow (CWE-120)",
    "gets": "Inherently dangerous input function with no length limit (CWE-242)",
    "system": "Command injection vulnerability if user input reaches argument (CWE-78)",
    "sprintf": "Format string / buffer overflow vulnerability (CWE-134)",
    "popen": "Process execution prone to command injection (CWE-78)",
    "strcat": "Unbounded string concatenation prone to buffer overflow (CWE-120)",
}

UnsafeMatch = dict[str, list[str]]  # function name -> matched strings


def scan_flags(text: str | Iterable[str]) -> list[str]:
    """Return every CTF flag literal found in `text` (or iterable of strings)."""
    if not isinstance(text, str):
        text = "\n".join(text)
    seen: list[str] = []
    for match in FLAG_PATTERN.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


def scan_unsafe_functions(strings: Iterable[str]) -> UnsafeMatch:
    """Match dangerous libc function names as whole-word symbols/strings.

    Whole-word matching keeps false positives down (e.g. 'fgets' must NOT
    trigger the 'gets' rule); still, matching against extracted strings or
    symbol names is a static heuristic, so emitted findings stay CANDIDATE.
    """
    triggered: UnsafeMatch = {}
    for s in strings:
        for name in UNSAFE_FUNCTIONS:
            if re.search(rf"\b{re.escape(name)}\b", s):
                triggered.setdefault(name, []).append(s)
    return triggered


# ---------------------------------------------------------------------------
# Header parsers (stdlib struct only)
# ---------------------------------------------------------------------------

def _detect_format(data: bytes) -> str:
    """Detect binary format from magic bytes."""
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:2] in (b"MZ", b"ZM"):
        return "PE"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    return "unknown"


def _parse_elf_header(data: bytes) -> dict:
    """Extract ELF e_machine, e_type, endianness."""
    if len(data) < 16:
        return {}
    ei_class = data[4]   # 1=32-bit, 2=64-bit
    ei_data = data[5]    # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"
    bits = 32 if ei_class == 1 else 64
    if len(data) < 18:
        return {"bits": bits, "endian": "LE" if ei_data == 1 else "BE"}
    e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
    machine_map = {
        0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64",
        0x08: "MIPS", 0xF3: "RISC-V",
    }
    return {
        "format": "ELF",
        "bits": bits,
        "endian": "LE" if ei_data == 1 else "BE",
        "e_type": e_type,
        "arch": machine_map.get(e_machine, f"0x{e_machine:04x}"),
    }


def _parse_pe_header(data: bytes) -> dict:
    """Extract PE machine type and characteristics."""
    if len(data) < 64:
        return {}
    # e_lfanew at offset 0x3C
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if len(data) < pe_offset + 24:
        return {}
    sig = data[pe_offset: pe_offset + 4]
    if sig != b"PE\x00\x00":
        return {"format": "PE", "note": "invalid PE signature"}
    machine, num_sections, _, _, _, _, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    machine_map = {
        0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM",
        0xAA64: "AArch64", 0x0200: "IA64",
    }
    return {
        "format": "PE",
        "arch": machine_map.get(machine, f"0x{machine:04x}"),
        "num_sections": num_sections,
        "characteristics": f"0x{characteristics:04x}",
    }


def _extract_strings(path: Path, min_length: int = 6, max_strings: int = 200) -> list[str]:
    """Extract printable strings using system strings(1) or fallback stdlib impl."""
    # Try system 'strings' binary first
    strings_bin = shutil.which("strings") or shutil.which("findstr")
    if strings_bin and "findstr" not in strings_bin:
        try:
            out = subprocess.run(
                [strings_bin, "-n", str(min_length), str(path)],
                check=False, capture_output=True, text=True, timeout=30,
            ).stdout
            result = [l.strip() for l in out.splitlines() if l.strip()]
            return result[:max_strings]
        except Exception:  # noqa: S110 BLE001
            pass

    # Pure stdlib fallback: scan for printable ASCII runs
    data = path.read_bytes()
    strings: list[str] = []
    current: list[int] = []
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(bytes(current).decode("ascii"))
                if len(strings) >= max_strings:
                    break
            current = []
    return strings


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


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

class BinaryWorker:
    """Static analysis of organiser-supplied, hash-registered binaries only."""

    def __init__(self, conn: sqlite3.Connection, gate: PolicyGate, run_id: str):
        self.conn = conn
        self.gate = gate
        self.run_id = run_id

    @staticmethod
    def sha256(path: str | Path) -> str:
        return _sha256(Path(path))

    def verify_registered(self, path: str | Path) -> bool:
        """True only when the on-disk hash matches the manifest entry."""
        expected = self.gate.manifest.binary_hashes.get(str(path))
        return bool(expected) and expected == self.sha256(path)

    def _get_or_create_asset(self, asset_type: str, canonical_key: str) -> str:
        """Look up (or create) a binary asset for this run. Dedupe at DB level."""
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

    def run(self, task: Task) -> dict:
        """Static analysis of the binary at task.target_id (file path).

        Gate check → hash verification → header parse → strings → findings.
        """
        path = Path(task.target_id)

        # SCOPE GATE (binary path check)
        gate_result = self.gate.gate(str(path), self.run_id, is_binary=True)
        event = ToolEvent(
            event_id=new_id("evt"),
            task_id=task.task_id,
            tool="binary_static_analysis",
            target=str(path),
            scope_decision=gate_result.decision,
            started_at=utc_now(),
        )

        if gate_result.decision is ScopeDecision.DENY:
            event.finished_at = utc_now()
            event.exit_status = "scope_denied"
            _persist_tool_event(self.conn, event)
            raise PermissionError(f"Scope DENY for binary {path}: {gate_result.reason}")

        # Hash verification — double-check on-disk hash matches manifest
        if not self.verify_registered(path):
            event.finished_at = utc_now()
            event.exit_status = "hash_mismatch"
            _persist_tool_event(self.conn, event)
            raise PermissionError(
                f"Binary {path} on-disk hash does not match registered manifest entry. Rejected."
            )

        if not path.exists():
            event.finished_at = utc_now()
            event.exit_status = "file_not_found"
            _persist_tool_event(self.conn, event)
            raise FileNotFoundError(f"Registered binary not found on disk: {path}")

        # Read header (first 4 KB)
        with open(path, "rb") as fh:
            header_bytes = fh.read(4096)

        fmt = _detect_format(header_bytes)
        if fmt == "ELF":
            header_info = _parse_elf_header(header_bytes)
        elif fmt == "PE":
            header_info = _parse_pe_header(header_bytes)
        else:
            header_info = {"format": fmt}

        # String extraction (bounded; min_length=4 so short names like "gets" survive)
        strings = _extract_strings(path, min_length=4, max_strings=200)

        # Interesting string heuristics → CANDIDATE findings
        finding_ids = self._emit_string_findings(task, path, strings, header_info)

        file_hash = self.sha256(path)
        event.finished_at = utc_now()
        event.exit_status = "0"
        event.output_hash = file_hash
        _persist_tool_event(self.conn, event)

        return {
            "path": str(path),
            "format": fmt,
            "header": header_info,
            "strings_count": len(strings),
            "findings": finding_ids,
        }

    def _emit_string_findings(
        self, task: Task, path: Path, strings: list[str], header_info: dict
    ) -> list[str]:
        """Look for interesting patterns in extracted strings → CANDIDATE findings."""
        asset_id = self._get_or_create_asset("binary", str(path))

        finding_ids: list[str] = []
        interesting_patterns = {
            "hardcoded_credential": ["password", "passwd", "secret", "apikey", "api_key", "token"],
            "network_indicator": ["http://", "https://", "ftp://", "192.168", "10.0.", "172.16"],
            "debug_artifact": ["DEBUG", "TODO", "FIXME", "backdoor", "test_mode"],
        }

        triggered: dict[str, list[str]] = {}
        for s in strings:
            sl = s.lower()
            for category, patterns in interesting_patterns.items():
                for pat in patterns:
                    if pat in sl:
                        triggered.setdefault(category, []).append(s)
                        break

        for category, matches in triggered.items():
            severity = "medium" if category == "hardcoded_credential" else "info"
            summary = (
                f"Binary {path.name} [{header_info.get('arch', header_info.get('format', '?'))}]: "
                f"{len(matches)} string(s) matching '{category}' pattern. "
                f"Examples: {matches[:3]}"
            )
            finding_ids.append(
                self._emit_finding_with_evidence(
                    asset_id=asset_id,
                    finding_type=f"binary_{category}",
                    severity=severity,
                    ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                    summary=summary,
                    confidence="low",
                    source_tool="binary_static_analysis",
                    artifact_path=str(path),
                    file_hash=self.sha256(path),
                    excerpt=json.dumps(matches[:10])[:500],
                    verification_method="manual_review_required",
                )
            )

        # ---------------- CTF planted-flag hunt (judge requirement 1) -------
        flags = scan_flags(strings)
        if flags:
            finding_ids.append(
                self._emit_finding_with_evidence(
                    asset_id=asset_id,
                    finding_type="ctf_planted_flag",
                    severity="high",
                    ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                    summary=(
                        f"Planted CTF flag captured in binary {path.name} strings: "
                        f"{flags}"
                    ),
                    confidence="high",
                    source_tool="binary_static_analysis",
                    artifact_path=str(path),
                    file_hash=self.sha256(path),
                    excerpt=json.dumps(flags)[:500],
                    verification_method="manual_review_required",
                )
            )

        # ---------------- Unsafe libc functions (judge requirement 1) -------
        triggered_unsafe = scan_unsafe_functions(strings)
        for func_name, matches in triggered_unsafe.items():
            explanation = UNSAFE_FUNCTIONS[func_name]
            finding_ids.append(
                self._emit_finding_with_evidence(
                    asset_id=asset_id,
                    finding_type="binary_unsafe_function",
                    severity="high",
                    ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                    summary=(
                        f"Binary {path.name} [{header_info.get('arch', header_info.get('format', '?'))}]: "
                        f"unsafe C function '{func_name}' found. {explanation}. "
                        f"Matched strings: {matches[:3]}"
                    ),
                    confidence="medium",
                    source_tool="binary_static_analysis",
                    artifact_path=str(path),
                    file_hash=self.sha256(path),
                    excerpt=json.dumps({"function": func_name, "matches": matches[:5]})[:500],
                    verification_method="manual_review_required",
                )
            )

        return finding_ids

    def _emit_finding_with_evidence(
        self,
        asset_id: str,
        finding_type: str,
        severity: str,
        ptes_phase: str,
        summary: str,
        confidence: str,
        source_tool: str,
        artifact_path: str,
        file_hash: str,
        excerpt: str,
        verification_method: str,
    ) -> str:
        """Create a CANDIDATE finding + evidence under it. Never auto-confirms."""
        finding = Finding(
            finding_id=new_id("find"),
            asset_id=asset_id,
            finding_type=finding_type,
            severity=severity,
            status=FindingStatus.CANDIDATE,
            confidence=confidence,
            ptes_phase=ptes_phase,
            summary=summary,
        )
        fid = _persist_finding(self.conn, finding)

        evidence = Evidence(
            evidence_id=new_id("evid"),
            finding_id=fid,
            source_tool=source_tool,
            artifact_path=artifact_path,
            hash=file_hash,
            excerpt=excerpt,
            verification_method=verification_method,
        )
        _persist_evidence(self.conn, evidence)
        return fid
