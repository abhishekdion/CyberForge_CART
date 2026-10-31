# Data contracts

Frozen shared data model (spec section 6). Source of truth:
`src/cart/models.py` (dataclasses) + `src/cart/store.py` (SQLite DDL).
Change all three (models, DDL, this doc) in the same change — enforced by the
`cart-data-contracts` skill.

## Records

| Record | Key fields | Purpose |
|---|---|---|
| `AssessmentRun` | run_id, status, tier, started_at, completed_at, scope_version | One complete assessment |
| `CandidateNetwork` | candidate_id, interface, address, prefix, family, route_metadata, confidence, selection_status | Preflight candidates shown to organisers |
| `ScopeManifest` | scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at | Authorised, immutable target set |
| `Asset` | asset_id, run_id, asset_type, canonical_key, first_seen, last_seen | Host / web app / binary |
| `Service` | service_id, asset_id, protocol, port, service_name, version, state | Discovered network service |
| `Task` | task_id, task_type, owner, target_id, status, ptes_phase, parent_task_id, dedupe_key, budget | Work item for a specialist |
| `ToolEvent` | event_id, task_id, tool, target, scope_decision, started_at, finished_at, exit_status, output_hash | Auditable tool invocation |
| `Finding` | finding_id, asset_id, finding_type, severity, status, confidence, ptes_phase, summary | Candidate or verified weakness |
| `Evidence` | evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt, verification_method | Proof and provenance |
| `Relationship` | source_id, target_id, relationship_type, evidence_id, confidence | Attack-path graph edge |
| `ReportArtifact` | report_id, run_id, format, path, hash, created_at | Final deliverable |

Plus an implementation-level `scope_decisions_log` table for the audit trail
of gate allow/deny outcomes.

## Lifecycles

**Run:** `PENDING → PREFLIGHT → RUNNING → COMPLETED | PARTIAL | ABORTED`

**Task:** `PENDING → READY → RUNNING → SUCCEEDED | FAILED | TIMED_OUT |
CANCELLED` — FAILED may return to READY only within its retry budget, and
retries must be idempotent (no duplicate assets/findings, no scope growth).

**Finding:** `CANDIDATE → VERIFICATION_QUEUED → CONFIRMED | REJECTED |
INCONCLUSIVE | NEEDS_REVIEW`

## Invariants

- Every record carries `run_id`.
- Findings/evidence trace to their originating task AND tool event.
- Every `Relationship` edge references an `evidence_id`.
- Large raw outputs are stored as files; the database keeps hashes/metadata
  only (keeps agent context and RAM small).
- Dedupe keys are stable: `run + canonical host + port + protocol + task
  profile`, or `run + binary hash + analysis profile`.
