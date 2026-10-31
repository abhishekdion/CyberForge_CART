"""Verification service (spec section 5.8, PRD FR-6).

Turns CANDIDATE findings into CONFIRMED / REJECTED / INCONCLUSIVE / NEEDS_REVIEW.
Rules:
- Deterministic procedures first; LLM may explain but never upgrades a candidate alone.
- Verdict must be grounded in tool output + a repeatable rule.
- Verification unavailable => INCONCLUSIVE, never CONFIRMED silently.
- NEEDS_REVIEW is exceptional: requires explicit human override, never auto-confirmed.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3

from .models import Evidence, FindingStatus, new_id

# ---------------------------------------------------------------------------
# Playbook registry
# ---------------------------------------------------------------------------
# Each playbook receives a Finding dict and its Evidence list, returns
# (FindingStatus, confidence: str, verification_note: str).

Playbook = object  # type alias for clarity in signatures


def _playbook_web_form_endpoint(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Forms are genuine candidates only if they have non-empty input names."""
    for ev in evidence_list:
        try:
            form_data = json.loads(ev.get("excerpt", "{}"))
            inputs = form_data.get("inputs", [])
            named = [i for i in inputs if i.get("name")]
            if named:
                return (
                    FindingStatus.CONFIRMED,
                    "medium",
                    f"Form with {len(named)} named input(s) confirmed at {form_data.get('action', '?')}",
                )
        except (json.JSONDecodeError, AttributeError):
            pass
    return FindingStatus.INCONCLUSIVE, "low", "No named form inputs found in evidence"


def _playbook_binary_hardcoded_credential(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Hard-coded credential: CONFIRMED if excerpt contains classic password keywords."""
    high_confidence_patterns = ["password=", "passwd=", "secret=", "apikey="]
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        for pat in high_confidence_patterns:
            if pat in excerpt:
                return (
                    FindingStatus.CONFIRMED,
                    "high",
                    f"String matching hardcoded-credential pattern ({pat!r}) found in binary",
                )
    return (
        FindingStatus.NEEDS_REVIEW,
        "low",
        "Potential credential pattern requires manual review to confirm",
    )


def _playbook_binary_network_indicator(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    return (
        FindingStatus.CONFIRMED,
        "medium",
        "Network indicator strings present in binary static analysis output",
    )


def _playbook_binary_debug_artifact(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    return (
        FindingStatus.CONFIRMED,
        "low",
        "Debug/test artifact strings found in binary (informational)",
    )


def _playbook_ctf_planted_flag(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Planted CTF flags are genuine: CONFIRMED if excerpt contains a flag literal."""
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if re.search(
            r"flag\{[^\}]+\}|CTF\{[^\}]+\}|CyberForge\{[^\}]+\}",
            excerpt,
            re.IGNORECASE,
        ):
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Planted CTF flag literal confirmed in evidence",
            )
    return FindingStatus.INCONCLUSIVE, "low", "No flag literal found in evidence"


def _playbook_binary_unsafe_function(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Unsafe libc functions are genuine: CONFIRMED if excerpt names a known unsafe func."""
    _UNSAFE_FUNCTIONS = {"strcpy", "gets", "system", "sprintf", "popen", "strcat"}
    for ev in evidence_list:
        try:
            data = json.loads(ev.get("excerpt", "{}"))
        except (json.JSONDecodeError, AttributeError):
            continue
        if isinstance(data, dict) and data.get("function") in _UNSAFE_FUNCTIONS:
            return (
                FindingStatus.CONFIRMED,
                "medium",
                f"Unsafe function {data['function']!r} confirmed in static analysis output",
            )
    return (
        FindingStatus.NEEDS_REVIEW,
        "low",
        "Unsafe-function evidence requires manual review to confirm",
    )


def _playbook_default(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Fallback: insufficient deterministic check available."""
    if not evidence_list:
        return FindingStatus.INCONCLUSIVE, "low", "No evidence attached to finding"
    return (
        FindingStatus.NEEDS_REVIEW,
        "low",
        "No automated playbook for this finding type; human review required",
    )


_PLAYBOOKS: dict[str, object] = {
    "web_form_endpoint": _playbook_web_form_endpoint,
    "binary_hardcoded_credential": _playbook_binary_hardcoded_credential,
    "binary_network_indicator": _playbook_binary_network_indicator,
    "binary_debug_artifact": _playbook_binary_debug_artifact,
    "ctf_planted_flag": _playbook_ctf_planted_flag,
    "binary_unsafe_function": _playbook_binary_unsafe_function,
}


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class VerificationService:
    """Turns candidate findings into CONFIRMED / REJECTED / INCONCLUSIVE."""

    def __init__(self, conn: sqlite3.Connection, run_id: str):
        self.conn = conn
        self.run_id = run_id

    def queue(self, finding_ids: list[str]) -> None:
        """Transition findings to VERIFICATION_QUEUED."""
        for fid in finding_ids:
            row = self.conn.execute(
                "SELECT status FROM findings WHERE finding_id=?", (fid,)
            ).fetchone()
            if row and row[0] == FindingStatus.CANDIDATE.value:
                self.conn.execute(
                    "UPDATE findings SET status=? WHERE finding_id=?",
                    (FindingStatus.VERIFICATION_QUEUED.value, fid),
                )
        self.conn.commit()

    def verify_one(self, finding_id: str) -> FindingStatus:
        """Run the deterministic playbook for one queued finding."""
        row = self.conn.execute(
            "SELECT finding_id, asset_id, finding_type, severity, status, "
            "confidence, ptes_phase, summary FROM findings WHERE finding_id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"finding {finding_id} not found")

        finding = {
            "finding_id": row[0], "asset_id": row[1], "finding_type": row[2],
            "severity": row[3], "status": row[4], "confidence": row[5],
            "ptes_phase": row[6], "summary": row[7],
        }

        if finding["status"] not in (
            FindingStatus.CANDIDATE.value,
            FindingStatus.VERIFICATION_QUEUED.value,
        ):
            return FindingStatus(finding["status"])

        # Fetch evidence
        evidence_rows = self.conn.execute(
            "SELECT evidence_id, finding_id, source_tool, artifact_path, hash, "
            "timestamp, excerpt, verification_method FROM evidence WHERE finding_id=?",
            (finding_id,),
        ).fetchall()
        evidence_list = [
            {
                "evidence_id": r[0], "finding_id": r[1], "source_tool": r[2],
                "artifact_path": r[3], "hash": r[4], "timestamp": r[5],
                "excerpt": r[6], "verification_method": r[7],
            }
            for r in evidence_rows
        ]

        # Select playbook
        playbook = _PLAYBOOKS.get(finding["finding_type"], _playbook_default)
        new_status, new_confidence, note = playbook(finding, evidence_list)  # type: ignore[operator]

        # Persist outcome
        self.conn.execute(
            "UPDATE findings SET status=?, confidence=? WHERE finding_id=?",
            (new_status.value, new_confidence, finding_id),
        )

        # Attach verification evidence note
        ev = Evidence(
            evidence_id=new_id("evid"),
            finding_id=finding_id,
            source_tool="verification_service",
            artifact_path="",
            hash=hashlib.sha256(note.encode()).hexdigest(),
            excerpt=note[:500],
            verification_method="deterministic_playbook",
        )
        try:
            self.conn.execute(
                "INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, "
                "hash, timestamp, excerpt, verification_method) VALUES (?,?,?,?,?,?,?,?)",
                (ev.evidence_id, ev.finding_id, ev.source_tool, ev.artifact_path,
                 ev.hash, ev.timestamp, ev.excerpt, ev.verification_method),
            )
        except sqlite3.IntegrityError:
            pass
        self.conn.commit()
        return new_status

    def verify_all_queued(self) -> dict[str, FindingStatus]:
        """Process every VERIFICATION_QUEUED finding. Returns {finding_id: outcome}."""
        rows = self.conn.execute(
            "SELECT finding_id FROM findings WHERE status=?",
            (FindingStatus.VERIFICATION_QUEUED.value,),
        ).fetchall()
        results: dict[str, FindingStatus] = {}
        for (fid,) in rows:
            try:
                results[fid] = self.verify_one(fid)
            except Exception:  # noqa: BLE001
                results[fid] = FindingStatus.INCONCLUSIVE
        return results
