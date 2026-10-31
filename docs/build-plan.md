# Build plan, laptop roles and measures

## Build order (spec section 16) — current status

| # | Step | Status |
|---|---|---|
| 1 | Freeze requirements and data contracts | **done** (models.py, store.py, this doc set) |
| 2 | Candidate-network preflight + organiser-selection flow | **done** (preflight.py, cli select) |
| 3 | Immutable scope manifest + policy gate; denial tests | **done** (scope.py, test_cart.py) |
| 4 | Task/event store + bounded orchestrator | **done** (orchestrator.py, budget.py) |
| 5 | Network Worker + normalisation | **done** (workers/network.py) |
| 6 | Web Worker + Binary Worker independently | **done** (workers/web.py, workers/binary.py) |
| 7 | Verification lifecycle + evidence store | **done** (verify.py) |
| 8 | Attack-path generation + unified reporting | **done** (attackpath.py, report.py, cli) |
| 9 | Phase 3 controlled validation, small → larger tiers | **pending** (unit suite passes; no controlled-lab run or ground-truth results recorded) |
| 10 | Benchmark, tune limits, README + judge rehearsal | not started |

Track task-level detail in `TODO.md`.

### Proposed validation target: OWASP Juice Shop

OWASP Juice Shop has been proposed as a validation target, but no deployment,
organiser approval, or CART run against it is recorded here. Treat it as a
candidate lab only: before any active assessment, confirm the organisers'
authorization and use an isolated instance with an explicitly locked scope.
Do not treat an internet-accessible instance or its vulnerable-by-design
status as authorization. Record the exact test setup, ground truth, scope
decision audit, and run evidence before claiming validation or benchmark
results.

## Framework spike (spec section 8) — outcome

**Decision: keep the custom task-graph runner (`src/cart/orchestrator.py`), do
not adopt LangGraph or CrewAI.**

Rationale: CART's critical path is stdlib-first deterministic Python + SQLite.
State transitions, scheduling, dedup keys and verification outcomes live in the
orchestrator/store — LLM output is advisory only and never changes state (see
AGENTS.md rule 2). Adopting LangGraph/CrewAI would introduce an external
dependency for checkpointing/recovery that we do not need: the orchestrator
already persists task state to SQLite, so recovery is a store query, not a
framework feature. The comparative spike confirmed no measurable benefit from a
framework at this stage; worker contracts remain unchanged either way.

## Judge-requirements build — what landed (hackathon feedback)

Four cohesive features were added on top of the build-order baseline; all are
deterministic, stdlib-first and integrate with the existing task/finding graph:

1. **Planted-flag hunter** — `FLAG_PATTERN` (`flag{...}`, `CTF{...}`,
   `CyberForge{...}`) applied by the Web Worker to page bodies, HTML comments
   and HTTP headers, and by the Binary Worker to extracted strings. Findings:
   `ctf_planted_flag`, severity `high`, always `CANDIDATE` until verified.
2. **Binary unsafe-function table** — `UNSAFE_FUNCTIONS` (`strcpy`, `gets`,
   `system`, `sprintf`, `popen`, `strcat`) matched whole-word against binary
   symbols/strings → `binary_unsafe_function` findings with CWE explanations.
   Whole-word matching prevents `fgets` false-positives on the `gets` rule.
3. **Web→Binary agent hand-off** — binary artefact links (`.exe .bin .elf .so
   .dll`) encountered while crawling are downloaded (bounded `max_binary_bytes`,
   default 16 MiB), stored under `binary_cache/<run_id>/`, hashed (SHA-256) and
   registered with the gate for static analysis only. The orchestrator hook
   `on_binary_discovered` then auto-enqueues `binary_static_analysis`.
4. **Remediation Advisor + tracing** — `advisor.py` (rule-based advisories + git-appliable `.patch` files via `export_patches()` for CONFIRMED findings, verified with `git apply --check`),
   `tracing.py` (spans to `traces/agent_traces.jsonl`, optional LangSmith).

Scope-safety notes for feature 3: the destination URL is gate-allowed before
the fetch, redirects are re-checked, and the download only authorises static
analysis of the local copy (see the "Registered binaries only" rule in
`docs/safety.md`). The locked manifest is never mutated.

## Tier choice (spec section 15) — rationale

CLI supports `--tier` with choices `recon`, `breach`, `deep`. For the initial
benchmark and single-machine release path, **default to `recon`** unless lab
benchmarks justify a higher tier:

- **Recon**: network discovery + service enumeration (Nmap), bounded by design.
  Fastest, lowest risk of out-of-scope probes, best fits the <20 min PRD target
  and "Great" scope-safety threshold (0 out-of-scope probes).
- **Breach**: adds web worker crawling/analysis; increases run time and false
  alarm risk — acceptable only if benchmarks show coverage >90% stays within
  budget.
- **Deep**: adds binary analysis + full verification pass; highest resource cost,
  reserved for validation runs on Laptop 3 with generous free disk.

Final tier selection is benchmark-tuned (Step 10) and documented in the report's
tier metadata. The default `recon` tier keeps the product portable and bounded
without requiring GPU-capable machines at runtime.

## LLM-integration stance (spec section 15)

**No cloud/LLM dependency in the critical path.** Preflight, scope gate, Nmap /
Katana / ZAP / Ghidra adapters, dedup, verification rules and report generation
are deterministic Python + SQLite — chosen so CART works if the event has no
internet or API access (spec §11 portability principle).

Where an LLM is optionally useful (triage/prioritise findings, report polish,
suggest verification checks), it must obey the exact boundary documented in
`docs/agents-and-llms.md`: it may explain, summarise, prioritise and draft text,
but it may never change scope, approve its own finding, decide a target is in
scope, or execute a tool outside the PolicyGate. The verifier's `CONFIRMED`
status requires repeatable tool evidence, period — an LLM answer alone can never
upgrade a candidate to confirmed.

## Laptop roles (spec section 12)

| Machine | Role |
|---|---|
| Laptop 1 — RTX 3050 4 GB, 8 GB RAM, 17.4 GB free | This repo, core coordinator: scope workflow, orchestrator, contracts, PTES mapping, report integration. Keep the runtime lightweight (no GPU requirement). |
| Laptop 2 — RTX 4050 6 GB | Optional model evaluation + binary-adapter research (GPU useful only if local LLM inference is selected). Confirm RAM/OS/disk first. |
| Laptop 3 — Ryzen 7 5800H, 16 GB RAM | Validation lab host, test data, end-to-end rehearsal, benchmarking (needs free disk + virtualisation check). |

Acceptance requirement: single-machine release path. Product must not need
three laptops at runtime.

## PRD measures (spec section 13)

| Measure | Great target | Instrumentation |
|---|---:|---|
| Coverage | > 90% | ground-truth evaluator for planted hosts/services |
| Findings | > 85% | planted weakness manifest comparison |
| Verified | all reported findings | finding state + evidence completeness |
| False alarms | < 10% | ground-truth evaluation |
| Scope safety | 0 out-of-scope probes | policy audit + lab-side egress evidence |
| Run time | < 20 min | wall clock from run start to report |
| Autonomy | 0 interventions after RUNNING | intervention counter |

Minus separately: attack-path correctness and flag capture (bonus items).

## Open decisions (spec section 15) — carry into team sync

1. PRD scope-input discrepancy (organisers give prefix, confirm candidate, or both?)
2. IPv4/IPv6 presence in the lab
3. Exact port/protocol/verification/rate rules from the organisers
4. Supplied binary formats/sizes/symbols
5. Internet/API availability at the event
6. Laptop 2/3 specs
7. Final tier choice (Recon/Breach/Deep) after controlled benchmarks; `recon`
   remains the default meanwhile
8. Framework spike is resolved: retain the custom orchestrator
