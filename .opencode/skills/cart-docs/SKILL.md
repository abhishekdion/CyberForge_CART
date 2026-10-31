---
name: cart-docs
description: Method for keeping docs/ true of the code in CyberForge CART. Use before finishing any change that alters API routes/payload shapes, scope policy rules, the data contracts, task/finding lifecycle, duplicate-K keys, run behaviour, report content, or operations (install/run instructions).
---

# CART documentation standard

Docs are run behaviour documentation, not aspiration. Before you finish a
change, ask: did behaviour change? Then the matching docs change in the same
commit/PR.

## Mapping of change -> doc updates

| Changed | Update |
|---|---|
| CLI commands / launch flow | `README.md` quick start, `docs/how-it-works.md` |
| Record shapes, states, dedupe keys | `docs/data-contracts.md`, `src/cart/models.py` docstrings || Scope/policy gate rules | `docs/safety.md` (and the cart-scope-safety skill text if the rule itself changed) |
| Orchestration, budgets, autonomy boundary | `docs/how-it-works.md`, `docs/build-plan.md` |
| Worker adapters / tool selection | `docs/architecture.md` |
| Report content/metrics | `docs/how-it-works.md` Phase H, `docs/build-plan.md` measures |
| PTES labels | `docs/ptes.md` + `src/cart/ptes.py` |
| Build order progress | `TODO.md` checkbox + `docs/build-plan.md` current step |

## Rules

1. Never write a doc claim the code cannot demonstrate yet; label real gaps
   as "not implemented — planned in build-order step N".
2. Docs cite the spec (`CyberForge_CART_Architecture_Design_Spec_v0.1`)
   section numbers so teammates can trace decisions.
3. README quick-start commands must be tested verbatim before claiming them.
4. Update `TODO.md` whenever a build-order step's status changes.
