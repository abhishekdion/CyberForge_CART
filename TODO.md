# TODO — CyberForge CART build order

Status mirrors `docs/build-plan.md`. Mark boxes as work lands, and update the
docs per the `cart-docs` skill in the same change.

## Phase 0 — Setup (done)

- [x] Repo scaffold, package layout, pyproject, git ignore
- [x] Data contracts frozen (`src/cart/models.py`, `store.py`)
- [x] Fail-closed PolicyGate core checks (`src/cart/scope.py`)
- [x] OpenCode config, specialist subagents, 4 project skills
- [x] Docs set + graphify graph

## Step 2 — Preflight + organiser selection (done)

- [x] Read local interfaces/addresses/prefixes/routes (Windows first, then Linux)
- [x] Classify: private / link-local / global / virtual/VPN/container adapters
- [x] Confidence + ambiguity warnings per candidate
- [x] `cart preflight` populated end-to-end (no scanning!)
- [x] `cart select` flow: organiser picks lab, enters exclusions + binaries
- [x] Scope manifest creation + lock (versioned)

## Step 3 — Policy gate + denial tests (done)

- [x] Unit tests: not-locked → deny; exclusion wins; unparseable → deny
- [x] `PolicyGate.check_url` incl. redirect resolution
- [x] Wire allow/deny outcomes into `scope_decisions_log` via store
- [x] Binary hash mismatch rejection path + test

## Step 4 — Store + orchestrator wiring (done)

- [x] SQLite-backed Task/ToolEvent persistence (replace in-memory dict)
- [x] Scheduling loop: pick READY tasks, bounded concurrency (≤4 default)
- [x] Per-task timeout + retry budget + total-run budget (20 min default)
- [x] Dedupe key application at creation
- [x] Run state machine incl. ABORTED + partial-report path

## Step 5 — Network Worker (done)

- [x] Nmap availability check + version pinning
- [x] XML → canonical Asset/Service normaliser
- [x] Host-discovery task → port/service tasks fan-out (bounded)
- [x] Web follow-up task emission for in-scope web services only

## Step 6 — Web Worker + Binary Worker (done)

- [x] `PolicyGate.check_url` used on every request incl. redirects
- [x] Endpoint/form capture with evidence + provenance (pure stdlib crawler)
- [x] Hash-registered-only file access (verify_registered, done in scaffold)
- [x] Standalone format/arch/strings parser on sample binaries (pure stdlib)

## Step 7 — Verification + evidence (done)

- [x] Verification queue + per-type deterministic check playbooks
- [x] CONFIRMED/REJECTED/INCONCLUSIVE/NEEDS_REVIEW transitions + tests
- [x] Evidence bundles (artifact file + hash + excerpt) per finding

## Step 8 — Attack path + report (done)

- [x] Relationship table-backed graph builder (evidence-edge only)
- [x] Markdown & JSON report generator
- [x] Metrics: coverage/verification/false-alarm/scope/runtime/autonomy
- [x] One-command CLI experience (`preflight`, `select`, `run`, `status`, `report`)

## Judge-requirements build (hackathon feedback) — done

- [x] Planted-flag hunter: Web Worker scans page bodies, HTML comments and HTTP
      headers; Binary Worker scans extracted strings → high-severity
      `ctf_planted_flag` CANDIDATE findings (`flag{}` / `CTF{}` / `CyberForge{}`)
- [x] Unsafe libc function detection: `strcpy gets system sprintf popen strcat`
      → `binary_unsafe_function` findings with CWE-based explanations
- [x] Web→Binary agent hand-off: Web Worker downloads `.exe/.bin/.elf/.so/.dll`
      links (size-capped, sha256, gate-registered for static analysis only);
      orchestrator `on_binary_discovered` auto-enqueues `binary_static_analysis`
- [x] Remediation Advisor (`src/cart/advisor.py`): rule-based plain-English
      advisories + code/config patches per finding type
- [x] Agent tracing (`src/cart/tracing.py`): spans to `traces/agent_traces.jsonl`
      with optional LangSmith export when `LANGSMITH_API_KEY` is set
- [x] Tests: flag/unsafe-function detection (incl. `fgets`≠`gets` false-positive
      guard), advisor patches, tracer JSONL output, dynamic binary registration
      scope-safety, hand-off dedupe

## Steps 9–10 — Validation + demo (in progress)

- [x] Unit test suite covering scope, budgets, orchestrator, verify, paths, reports
- [ ] Confirm OWASP Juice Shop is organiser-approved and provision an isolated validation instance
- [ ] Validate that the selected scope is explicit and that out-of-scope destinations are denied and audited; do not run against an unapproved or internet-accessible target
- [ ] Ground-truth planted-host/binary evaluator
- [ ] Benchmark run at Recon tier → tune budgets
- [ ] README quick start tested verbatim + judge rehearsal
- [ ] Record test setup, ground truth, run evidence, and measured results before marking validation complete

## Deferred / open decisions

- [x] Framework spike: custom runner vs LangGraph (documented in docs/build-plan.md — keep custom orchestrator.py, stdlib-first)
- [ ] Final tier choice (Recon/Breach/Deep) after benchmarks (`recon` remains the default)
- [x] Optional LLM integration decision (documented: no cloud/LLM dependency in critical path; advisory-only boundary per docs/agents-and-llms.md)
- [ ] Organiser answers to spec section 15 items — require organiser input, tracked in docs/build-plan.md "Open decisions" section:
    - PRD scope-input discrepancy (prefix vs candidate confirmation vs both)
    - IPv4/IPv6 presence in the lab
    - Exact port/protocol/verification/rate rules
    - Supplied binary formats/sizes/symbols
    - Internet/API availability at the event
    - Laptop 2/3 specs confirmation
