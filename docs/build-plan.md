# Build plan, laptop roles and measures

## Build order (spec section 16) — current status

| # | Step | Status |
|---|---|---|
| 1 | Freeze requirements and data contracts | **done** (models.py, store.py, this doc set) |
| 2 | Candidate-network preflight + organiser-selection flow | started (stub) |
| 3 | Immutable scope manifest + policy gate; denial tests | gate checks implemented, denial tests next |
| 4 | Task/event store + bounded orchestrator | task graph/state machine implemented; wiring next |
| 5 | Network Worker + normalisation | stub |
| 6 | Web Worker + Binary Worker independently | stubs |
| 7 | Verification lifecycle + evidence store | stub |
| 8 | Attack-path generation + unified reporting | stub |
| 9 | Phase 3 controlled validation, small → larger tiers | not started |
| 10 | Benchmark, tune limits, README + judge rehearsal | not started |

Track task-level detail in `TODO.md`.

## Framework spike (spec section 8, open decision)

Baseline is the small custom task-graph runner (`src/cart/orchestrator.py`).
Run a comparative spike against LangGraph before freezing: does checkpointing,
stateful branching and recovery justify the dependency? Do not pick a
framework from a demo.

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
7. Tier choice (Recon/Breach/Deep) after benchmarks
8. Framework spike outcome (LangGraph vs custom runner)
