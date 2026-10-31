"""Frozen data contracts (spec section 6).

Build-order step 1: these dataclasses are the single source of truth for the
shared data model. Every record carries `run_id`. Findings and evidence must
be traceable to their originating task and tool event.

If you change anything here, you MUST update docs/data-contracts.md and the
SQLite DDL in cart.store in the same change. See the cart-data-contracts skill.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class RunStatus(enum.StrEnum):
    PENDING = "pending"
    PREFLIGHT = "preflight"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    ABORTED = "aborted"


class TaskStatus(enum.StrEnum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class FindingStatus(enum.StrEnum):
    CANDIDATE = "candidate"
    VERIFICATION_QUEUED = "verification_queued"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    NEEDS_REVIEW = "needs_review"


class ScopeDecision(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class AssessmentRun:
    run_id: str
    status: RunStatus
    tier: str
    started_at: str | None = None
    completed_at: str | None = None
    scope_version: str | None = None


@dataclass
class CandidateNetwork:
    """Preflight candidate. NOT authorised for testing until selected."""

    candidate_id: str
    interface: str
    address: str
    prefix: str
    family: str  # "ipv4" | "ipv6"
    route_metadata: str = ""
    confidence: str = "medium"  # high | medium | low
    selection_status: str = "unselected"  # unselected | selected | rejected


@dataclass
class ScopeManifest:
    """Immutable once locked. Any change requires a new version + re-approval."""

    scope_version: str
    included_prefixes: list[str] = field(default_factory=list)
    included_hosts: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    binary_hashes: dict[str, str] = field(default_factory=dict)  # path -> sha256
    created_by: str = "organiser-selection"
    locked_at: str | None = None


@dataclass
class Asset:
    asset_id: str
    run_id: str
    asset_type: str  # host | web_app | binary | other
    canonical_key: str
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)


@dataclass
class Service:
    service_id: str
    asset_id: str
    protocol: str
    port: int
    service_name: str
    version: str = ""
    state: str = "open"


@dataclass
class Task:
    task_id: str
    task_type: str
    owner: str  # controller | network | web | binary | verifier
    target_id: str
    status: TaskStatus = TaskStatus.PENDING
    ptes_phase: str = ""
    parent_task_id: str | None = None
    dedupe_key: str = ""
    budget: dict = field(default_factory=dict)  # timeout_s, retries, max_output


@dataclass
class ToolEvent:
    event_id: str
    task_id: str
    tool: str
    target: str
    scope_decision: ScopeDecision
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    exit_status: str | None = None
    output_hash: str | None = None


@dataclass
class Finding:
    finding_id: str
    asset_id: str
    finding_type: str
    severity: str  # info | low | medium | high | critical
    status: FindingStatus = FindingStatus.CANDIDATE
    confidence: str = "low"
    ptes_phase: str = ""
    summary: str = ""


@dataclass
class Evidence:
    evidence_id: str
    finding_id: str
    source_tool: str
    artifact_path: str
    hash: str
    timestamp: str = field(default_factory=utc_now)
    excerpt: str = ""
    verification_method: str = ""


@dataclass
class Relationship:
    """Attack-path graph edge. Must point at the evidence that justifies it."""

    source_id: str
    target_id: str
    relationship_type: str
    evidence_id: str
    confidence: str = "low"


@dataclass
class ReportArtifact:
    report_id: str
    run_id: str
    format: str  # md | html | json
    path: str
    hash: str
    created_at: str = field(default_factory=utc_now)
