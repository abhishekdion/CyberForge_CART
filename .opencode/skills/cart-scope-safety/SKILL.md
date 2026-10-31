---
name: cart-scope-safety
description: Use before writing, reviewing or testing any CART code that could send a packet, HTTP request or binary analysis action - adapters, preflight, policy gate, workers, orchestrator hand-offs, and any nmap/katana/zap/ghidra invocation. Enforces fail-closed scope checking and non-destructive behaviour.
---

# CART scope safety

CART's core promise: **zero out-of-scope probes** (PRD "Great" target) and no
damage to targets. This skill is mandatory whenever code may touch a network
or execute an assessment tool.

## Rules

1. **Gate before every action, fail closed.** Every external action
   (network destination, URL, redirect, binary file) must pass
   `src/cart/scope.py::PolicyGate` immediately before execution. Missing,
   ambiguous or unresolvable scope = DENY. Never bypass, cache around, or
   weaken the gate to make a test pass.
2. **Redirects are re-checked.** Web crawling must resolve and re-check every
   redirect/linked destination; out-of-scope redirects are blocked and logged
  as a denied ToolEvent, never followed.
3. **Exclusions win.** Anything in `ScopeManifest.exclusions` is denied even
   if it is inside an included prefix.
4. **No silent scope expansion.** Candidate networks, gateway routes, DNS
   results or crawl links never widen the authorised target set. New targets
   require a new scope version + restart/re-approval.
5. **Non-destructive only.** No DoS, no brute-force, no destructive checks.
   The baseline is discovery + evidence-backed verification. Masscan stays
   banned until organiser limits and benchmark evidence justify it.
6. **Dynamic execution is off by default.** Binary worker: static analysis
   only unless docs/safety.md explicitly changes this.
7. **Every decision is auditable.** Allow AND deny outcomes land in the
   `scope_decisions_log` with a reason.

## Denial behaviour (write tests for this BEFORE the happy path)

| Trigger | Expected |
|---|---|
| Scope not locked | ScopeNotLockedError, no tool starts |
| Unparseable/ambiguous target | DENY with reason |
| URL redirect leaves scope | Block + denied event |
| Binary not in manifest / hash mismatch | Reject file + record |
| Any out-of-scope destination | DENY + denied ToolEvent |

The gate is enforced in deterministic Python code (spec principle: "policy in
code — an LLM prompt is not a security boundary").
