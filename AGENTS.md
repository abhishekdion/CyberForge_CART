# AGENTS.md — CyberForge CART

Rules for any coding agent working in this repository.

## Project identity

CART is a controlled, multi-agent assessment engine for organiser-designated
labs. The authoritative design is
`CyberForge_CART_Architecture_Design_Spec_v0.1.md` (one level above this
directory). When code and spec disagree, raise it; do not silently diverge.

## Non-negotiable rules

1. **Scope safety first.** Never write code that sends packets, requests or
   probes anywhere before the PolicyGate (`src/cart/scope.py`) has allowed the
   destination. The gate fails closed — never weaken it to make a test pass.
   See the `cart-scope-safety` skill and `docs/safety.md`.
2. **Determinism owns state.** Scheduling, dedup, budget limits, state
   transitions and verification outcomes live in deterministic Python +
   SQLite. LLM output is advisory only and never changes state on its own.
3. **Evidence before claims.** Findings are `CANDIDATE` until the
   Verification Service confirms them. Never hard-code a confirmed status.
4. **Data contracts are frozen** in `src/cart/models.py` + `store.py`.
   Changes require updating `docs/data-contracts.md` in the same commit —
   see the `cart-data-contracts` skill.
5. **Docs must stay true.** Changes to API routes, payload shapes, config
   keys, schema, policy rules or run behaviour require the matching doc
   update. See the `cart-docs` skill.
6. **Bounded by design.** Concurrency, timeouts, retries, output sizes and
   run budgets are explicit configuration, not hardcoded accidents.

## Layout

```
src/cart/          package (preflight, scope, orchestrator, workers, verify, ...)
docs/              how the project works — keep updated
.opencode/         agent config, skills, specialist subagents
TODO.md            build order status
graphify-out/      per-developer code graph (never commit)
```

## Working style

- Python 3.11+, stdlib-first: SQLite core, argparse CLI, dataclasses.
- No cloud/LLM dependency in the critical path (portability principle).
- Every PRD feature traces to a record type + component (see
  `docs/build-plan.md`, Appendix A of the spec).
- Before any structural refactor, query the code graph:
  `graphify query "..."` (see the `cart-graphify` skill).
