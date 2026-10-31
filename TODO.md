# TODO — CyberForge CART build order

Status mirrors `docs/build-plan.md`. Mark boxes as work lands, and update the
docs per the `cart-docs` skill in the same change.

## Phase 0 — Setup (done)

- [x] Repo scaffold, package layout, pyproject, git ignore
- [x] Data contracts frozen (`src/cart/models.py`, `store.py`)
- [x] Fail-closed PolicyGate core checks (`src/cart/scope.py`)
- [x] OpenCode config, specialist subagents, 4 project skills
- [x] Docs set + graphify graph

## Step 2 — Preflight + organiser selection (in progress)

- [ ] Read local interfaces/addresses/prefixes/routes (Windows first, then Linux)
- [ ] Classify: private / link-local / global / virtual/VPN/container adapters
- [ ] Confidence + ambiguity warnings per candidate
- [ ] `cart preflight` populated end-to-end (no scanning!)
- [ ] `cart select` flow: organiser picks lab, enters exclusions + binaries
- [ ] Scope manifest creation + lock (versioned)

## Step 3 — Policy gate + denial tests (in progress)

- [ ] Unit tests: not-locked → deny; exclusion wins; unparseable → deny
- [ ] `PolicyGate.check_url` incl. redirect resolution
- [ ] Wire allow/deny outcomes into `scope_decisions_log` via store
- [ ] Binary hash mismatch rejection path + test

## Step 4 — Store + orchestrator wiring

- [ ] SQLite-backed Task/ToolEvent persistence (replace in-memory dict)
- [ ] Scheduling loop: pick READY tasks, bounded concurrency (≤4 default)
- [ ] Per-task timeout + retry budget + total-run budget (20 min default)
- [ ] Dedupe key application at creation
- [ ] Run state machine incl. ABORTED + partial-report path

## Step 5 — Network Worker

- [ ] Nmap availability check + version pinning
- [ ] XML → canonical Asset/Service normaliser
- [ ] Host-discovery task → port/service tasks fan-out (bounded)
- [ ] Web follow-up task emission for in-scope web services only

## Step 6 — Web Worker + Binary Worker

- [ ] `PolicyGate.check_url` used on every request incl. redirects
- [ ] Katana/ZAP spike + pick from designed comparison (not demo)
- [ ] Endpoint/form capture with evidence + provenance
- [ ] Hash-registered-only file access (verify_registered, done in scaffold)
- [ ] Ghidra headless spike: format/arch/strings on sample binaries

## Step 7 — Verification + evidence

- [ ] Verification queue + per-type deterministic check playbooks
- [ ] CONFIRMED/REJECTED/INCONCLUSIVE/NEEDS_REVIEW transitions + tests
- [ ] Evidence bundles (artifact file + hash + excerpt) per finding

## Step 8 — Attack path + report

- [ ] Relationship table-backed graph builder (evidence-edge only)
- [ ] Markdown/HTML/JSON report generator + findings endpoint
- [ ] Metrics: coverage/verification/false-alarm/scope/runtime/autonomy

## Steps 9–10 — Validation + demo

- [ ] Controlled validation lab plumbing (Laptop 3 host)
- [ ] Ground-truth planted-host/binary evaluator
- [ ] Benchmark run at Recon tier → tune budgets
- [ ] README quick start tested verbatim + judge rehearsal

## Deferred / open decisions

- [ ] Framework spike: custom runner vs LangGraph (before step 9 freeze)
- [ ] Tier choice (Recon/Breach/Deep) after benchmarks
- [ ] Optional LLM integration decision (only after internet/rules confirmed)
- [ ] Organiser answers to spec section 15 items (put them in docs/build-plan.md)
