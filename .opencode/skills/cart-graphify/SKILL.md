---
name: cart-graphify
description: Use for structural code questions in CyberForge CART ("how does X connect to Y", call paths, hub modules, impact before refactors). Build/update/query the graphify-out/ code graph instead of grepping many files.
---

# Graphify for CyberForge CART

The graph lives in `graphify-out/` (per-developer, git-ignored, never
committed). Rebuild locally instead.

## Commands (run from CyberForge_CART/ root)

```powershell
# first build (offline, code-only, no API key)
graphify extract . --code-only

# after structural edits to src/cart/
graphify update . --no-cluster

# full rebuild
graphify extract . --code-only --force

# queries
graphify query "how does a discovered web service become a web worker task?"
graphify path "Orchestrator" "PolicyGate"
graphify explain "PolicyGate"
graphify god-nodes --top 10
```

(If the shim is not on PATH use `python -m graphify ...`.)

## When to use

- Tracing agent hand-offs: Network Worker -> orchestrator -> Web/Binary task
- Finding where the scope gate is (or should be) enforced in call paths
- Impact analysis before refactoring the orchestrator (bus factor check)
- Onboarding new teammates to the call graph

## Rules

1. Query first if `graphify-out/graph.json` exists — do not rebuild.
2. Update (`--no-cluster`) before querying after notable code changes.
3. Graphify is navigation only: it never authorizes writes.
4. Verify graph findings against real files before editing (nodes can lag).
