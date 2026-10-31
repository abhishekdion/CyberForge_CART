# How CART works — one run, end to end

This page explains the full operating story in practical terms: what the
operator does once, and what the engine then does alone. It is the plain
language answer to "how will the project run?" and "how is it autonomous?"

## The 30-second version

1. The operator launches CART **once** (`cart preflight` → select → run).
2. CART shows the networks the laptop can see. **The organiser picks the lab** —
   never the software.
3. The accepted targets are locked in an immutable scope manifest.
4. The run starts. From that moment **no human input is required**: the
   coordinator spawns discovery, webs, binary analysis, verification, attack
   path, and the final report on its own within hard budgets.
5. The team receives one report with evidence, metrics, and an attack path.

## Phase-by-phase

```mermaid
flowchart LR
    A[cart preflight] --> B[organiser selects lab]
    B --> C[scope lock - immutable]
    C --> D[autonomous run begins RUNNING]
    D --> E[network discovery]
    E --> F[web worker + binary worker in parallel]
    F --> G[verification queue]
    G --> H[attack path builder]
    H --> I[report + audit bundle]
```

### Phase A — Launch and candidate discovery
`cart preflight` reads the laptop's own network configuration: interfaces,
addresses, prefixes, gateways, VPN/virtual adapters. It **does not scan** — it
lists candidates and flags ambiguous or virtual ones. (Spec section 5.2.)

### Phase B — Organiser selects the lab
The organiser names which candidate is the lab and gives exclusions plus the
supplied binaries. This is the only required human decision, and it is the
data that becomes the run's **immutable scope manifest**. This distinction -
candidate network ≠ authorised scope - is the heart of the project (spec
Appendix B).

### Phase C — Scope lock and run initialisation
Before any worker starts, the controller validates: selected prefix parses,
exclusions are explicit, binary hashes are registered, tier and budgets are
set, and the PolicyGate can resolve every target. The operator hits start;
`RUNNING` is the autonomy boundary.

### Phase D — Network discovery
The Network Worker finds live hosts, ports, and services **inside the locked
scope only**, using Nmap XML adapter when available or falling back to a pure
stdlib non-blocking TCP socket scan (zero external dependencies) if nmap is
missing or fails at runtime. Output normalises to canonical asset/service
records written to the shared store. It raises follow-up tasks; it does not
decide to attack anything. The Web Worker uses the discovered service port
(including 3000 for a local Juice Shop container) instead of assuming every web
service listens on port 80 or 443. Every HTTP request remains subject to the
locked-scope gate, and redirects are rejected before following when the
destination is out of scope. An optional `cart run --ports` allowlist restricts
the network worker's TCP discovery; without it, both scanner backends use the
same common-port catalog. Worker threads use separate SQLite connections;
PolicyGate audit writes use the worker thread's connection.

### Phase E — Parallel specialist assessment
The orchestrator schedules independent work simultaneously: Web Worker tasks
for each in-scope web service, Binary Worker tasks for each organiser-supplied
binary (plus any downloaded from crawled pages, see below). Workers exchange
typed records — never shell commands — and cannot modify the scope or each
other's privileges.

Planted-flag hunting runs in both specialists: the Web Worker scans every
crawled page's body, HTML comments, and HTTP headers for `flag{...}`,
`CTF{...}`, `CyberForge{...}` literals; the Binary Worker scans extracted
strings. Both emit high-severity `ctf_planted_flag` CANDIDATE findings. The
Binary Worker additionally flags dangerous libc functions found in symbols or
strings (`strcpy`, `gets`, `system`, `sprintf`, `popen`, `strcat`) as
`binary_unsafe_function` (CANDIDATE until verified).

When the Web Worker encounters a link to a binary artefact, it downloads the
file into a bounded local cache, computes its SHA-256, registers the copy with
the PolicyGate for static analysis only, and the orchestrator automatically
enqueues a `binary_static_analysis` task for the Binary Worker — no human
intervention after scope lock.

### Phase F — Finding verification
Candidates land in a verification queue. Outcomes: `CONFIRMED` (repeatable
evidence), `REJECTED`, `INCONCLUSIVE`, `NEEDS_REVIEW` (human decision;
exceptional). A scanner message alone never becomes confirmed.

### Phase G — Attack-path construction
Paths are built **only** from relationships that carry evidence. Being on the
same network is not a path edge.

### Phase H — Report and completion
One consolidated report: exec summary, scope + exclusions, full inventory,
findings with severity/PTES/evidence/remediation, evidence-backed attack path,
metrics (coverage, verification, false alarms, scope safety, runtime,
autonomy), and tool execution summary. Run ends `COMPLETED`, `PARTIAL`, or
`ABORTED` with a reason. Findings additionally carry rule-based remediation
from `src/cart/advisor.py`: a plain-English explanation, impact, recommended
fix and a concrete code/config patch example (tailored per finding type —
e.g. bounded `fgets`/`snprintf` replacements for unsafe libc functions,
parameterised queries + CSRF for form endpoints, secret-manager guidance for
hard-coded credentials). Agent task execution is traced as spans to
`traces/agent_traces.jsonl` by `src/cart/tracing.py` (optional LangSmith
export when `LANGSMITH_API_KEY` is set). After report generation,
`RemediationAdvisor.export_patches()` writes ready-to-apply `.patch` files
(git unified diff format, verified with `git apply --check`) for every CONFIRMED
finding mapped to a hardening group into `reports/patches/`.

## What is autonomous, precisely

| Decision | Who makes it | Example |
|---|---|---|
| Which network is the lab | **Organiser** (once, pre-run) | picks candidate B |
| Which targets are tested | Locked manifest (immutable during run) | 10.10.20.0/24 minus exclusions |
| Every tool action destination | PolicyGate (deterministic code) | deny 10.9.9.9 probe |
| What to scan next | Orchestrator schedule + budgets | web tasks for :80/:443 hits |
| Binary artefacts linked from crawled pages | Deterministic hand-off rule | download + sha256 → auto `binary_static_analysis` task |
| Which finding is real | Verification Service | CONFIRMED with evidence |
| When to stop | Run budget / stop state | 20-min PRD target |
| Anything beyond scope | **Nobody** | denied + audited |

Autonomy is **bounded**: finite task budgets, concurrency caps, timeouts,
retry caps, output caps, and stop conditions. "Agentic" does not mean
uncontrolled - after scope lock the engine needs zero further input because
every possible choice is already policy- or budget-resolved.

## Run states

`PENDING → PREFLIGHT → RUNNING → COMPLETED | PARTIAL | ABORTED`

Interventions after `RUNNING` are counted as a PRD "autonomy" metric; organiser
interactions are recorded with timestamps to keep the measurement honest.
