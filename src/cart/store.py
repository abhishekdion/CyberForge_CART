"""Run-scoped persistence (spec section 11 "Storage").

SQLite for metadata/tasks/events/findings/relationships; filesystem artifacts
for raw tool output and reports. Graph edges live in the Relationships table -
no graph database is needed for the first release.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    tier TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    scope_version TEXT
);

CREATE TABLE IF NOT EXISTS candidate_networks (
    candidate_id TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    address TEXT NOT NULL,
    prefix TEXT NOT NULL,
    family TEXT NOT NULL,
    route_metadata TEXT DEFAULT '',
    confidence TEXT DEFAULT 'medium',
    selection_status TEXT DEFAULT 'unselected'
);

CREATE TABLE IF NOT EXISTS scope_manifests (
    scope_version TEXT PRIMARY KEY,
    included_prefixes TEXT NOT NULL,   -- JSON list
    included_hosts TEXT NOT NULL,      -- JSON list
    exclusions TEXT NOT NULL,          -- JSON list
    binary_hashes TEXT NOT NULL,       -- JSON object path -> sha256
    created_by TEXT NOT NULL,
    locked_at TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    asset_type TEXT NOT NULL,
    canonical_key TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(run_id, asset_type, canonical_key)
);

CREATE TABLE IF NOT EXISTS services (
    service_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    version TEXT DEFAULT '',
    state TEXT DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    task_type TEXT NOT NULL,
    owner TEXT NOT NULL,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL,
    ptes_phase TEXT NOT NULL DEFAULT '',
    parent_task_id TEXT,
    dedupe_key TEXT NOT NULL DEFAULT '',
    budget TEXT NOT NULL DEFAULT '{}'  -- JSON object
);

CREATE TABLE IF NOT EXISTS tool_events (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    scope_decision TEXT NOT NULL,      -- allow | deny
    started_at TEXT NOT NULL,
    finished_at TEXT,
    exit_status TEXT,
    output_hash TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence TEXT DEFAULT 'low',
    ptes_phase TEXT DEFAULT '',
    summary TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    source_tool TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    hash TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    excerpt TEXT DEFAULT '',
    verification_method TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS relationships (
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    confidence TEXT DEFAULT 'low',
    PRIMARY KEY (source_id, target_id, relationship_type)
);

CREATE TABLE IF NOT EXISTS report_artifacts (
    report_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    format TEXT NOT NULL,
    path TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_decisions_log (
    event_id TEXT PRIMARY KEY,
    run_id TEXT,
    requested_target TEXT NOT NULL,
    decision TEXT NOT NULL,            -- allow | deny
    reason TEXT NOT NULL,
    at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
-- Enforce one task per dedupe_key, but only for non-empty keys.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_dedupe ON tasks(dedupe_key) WHERE dedupe_key != '';
"""


def connect(db_path: str | Path, check_same_thread: bool = False) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    conn.executescript(SCHEMA)
    return conn
