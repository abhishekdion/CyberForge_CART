# CyberForge CART

Controlled, multi-agent penetration-testing engine for the organiser-designated
CyberForge lab. Assesses three surfaces (network, web, supplied binaries),
coordinates specialist agents through a shared typed store, verifies findings
before trusting them, maps every action to PTES, and produces one
evidence-backed report with an attack path.

> **Status:** working prototype. Preflight, scope selection, gated workers,
> verification, reporting, and the local dashboard are implemented. The unit
> suite passes, but controlled-lab validation, ground-truth evaluation, and
> benchmarks are still pending; this is not yet a validated release. See
> `docs/build-plan.md`.

## Quick start (developers)

```powershell
cd CyberForge_CART
python -m venv .venv
.\.venv\Scripts\pip install -e .[dev]

# Phase A only — read-only, shows candidate networks (no scanning):
.\.venv\Scripts\python -m cart.cli preflight

# run tests / lint
.\.venv\Scripts\pytest
.\.venv\Scripts\ruff check src
```

Intended judge path: install prerequisites → organiser selects the authorised
lab and locks scope → start → report and any applicable remediation patches.
The end-to-end judge path has not yet been rehearsed in a controlled lab.

## How it works (the short version)

1. `cart preflight` — CART lists the networks the laptop can see. **It does
   not scan anything.**
2. The organiser names which candidate is the lab + exclusions + binaries →
   CART locks an immutable scope manifest.
3. The operator starts the run. From `RUNNING`, **no human input is needed**:
   network discovery → parallel web/binary specialists → verification of every
   candidate finding → evidence-backed attack path → one report.
4. Every tool action passes a deterministic policy gate that **fails closed**
   — anything outside the locked scope is denied and audited.

Full story: `docs/how-it-works.md`. Architecture: `docs/architecture.md`.

## Do agents use AI? Which LLM — free?

- The **core engine runs without any LLM**: deterministic Python + SQLite by
  design (works even with no internet at the venue).
- LLMs are optional helpers (findings triage, report polish). Free options and
  setup instructions for teammates: **`docs/agents-and-llms.md`**.
- The coding agents in this repo (OpenCode) already run on **free models**
  (`opencode/*-free`) — configured in `.opencode/opencode.json`.

## Repo layout

```
src/cart/          engine package (models, scope gate, orchestrator, workers…)
docs/              how the project works — kept true of the code
.opencode/         agents' rules, specialist subagents, skills, permissions
TODO.md            build-order checklist
graphify-out/      code knowledge graph (per-developer, git-ignored)
```

## Working with coding agents in this repo

Open any OpenCode session inside `CyberForge_CART/`:

- `AGENTS.md` + the skills (`cart-scope-safety`, `cart-data-contracts`,
  `cart-docs`, `cart-graphify`) load automatically.
- Specialist subagents exist for parallel dev work (see
  `.opencode/agents/`): `network-specialist`, `web-specialist`,
  `binary-specialist`, `verification-specialist`.
- Permissions: `git push`/`pip install`/active scanners ask first; `masscan`
  denied.
- Rebuild the code graph after structural edits: `graphify extract . --code-only`
  (usage in the `cart-graphify` skill).

## Safety

Testing only within organiser-selected scope; non-destructive by design.
Gate details and house rules: `docs/safety.md`.

Local OWASP Juice Shop lab setup (loopback-bound, isolated Docker network):
`labs/juice-shop/README.md`. The lab recipe does not count as validation
evidence; controlled-run results and benchmarks are still pending.

## Spec of record

`CyberForge_CART_Architecture_Design_Spec_v0.1.md` (parent directory) — this
repo implements its sections 1–16; docs cite spec sections for traceability.
