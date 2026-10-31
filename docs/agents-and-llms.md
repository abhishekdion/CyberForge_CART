# Agents and LLMs — which AI does CART use, and the free options

This page answers three common questions directly:

1. **How do the agents work?**
2. **How is the project autonomous?**
3. **Which AI/LLM is used — and are there free options?**

## 1. How the agents work

CART is **multi-agent in the engineering sense, not the "chat with 10 AIs"
sense**. There is one controller (bounded task-graph orchestrator) and three
specialist workers (Network, Web, Binary) plus a Verification service.

Key points to explain to teammates/judges:

- **Agents are workers, not authorities.** Each specialist is a normal
  Python component with a strict input/output contract: it receives a task
  (target, budget, tools it may use, PTES phase) and returns structured
  records (assets, evidence, candidate findings, suggested follow-ups).
- **Coordination is through the shared database**, not conversation. The
  orchestrator dedupes work (stable keys like `run + host + port + protocol`),
  hands it to the right specialist, and enforces limits. That is how "no
  repeated work" (PRD FR-4) is actually enforced.
- **The LLM does not command anything.** A prompt is never a security
  boundary. Scope, schedules, and state transitions are deterministic code.

## 2. How it is autonomous

After the organiser picks the lab and scope lock happens, `RUNNING` begins and
**no further human input is needed**. Everything after that is scheduled by
the controller within explicit budgets (20-minute PRD target, concurrency
caps, retry caps). See `how-it-works.md` "What is autonomous, precisely".

The agent **autonomy lives in the product's own orchestrator** — not in the
IDE agent. OpenCode subagents are development helpers; CART itself does not
call OpenCode at runtime.

## 3. Which AI/LLM is used — free options

**Design principle (spec §11): the core needs NO LLM.** Preflight, scope
gate, Nmap/Katana/ZAP/Ghidra adapters, dedup, verification rules and report
generation are deterministic Python + SQLite. This was chosen deliberately so
the product works if the event has no internet or no API access.

### Where an LLM is optionally useful (all optional)

| Use | Why an LLM helps |
|---|---|
| Triage/prioritise candidate findings | messy evidence → readable summaries |
| Report writing/polish | plain-English remediation (bonus B-3) |
| Suggesting verification checks | verifier still decides from tool output |

### Free LLM options, in order of preference for the team

| Option | Cost | Needs internet? | Notes |
|---|---|---|---|
| **OpenCode built-in free models** (`opencode/*-free`: glm-5.3-flash-free, deepseek-v4.1-flash-free, nemotron-3.5-super-vl-free, flint-40b-free, beam-free, mimo-v2.6-flash-free) | Free | Yes | Already set as this repo's default model in `.opencode/opencode.json` |
| **OpenRouter `:free` models** (google/gemma-4-31b-it:free, nvidia/nemotron-3.5-super-vl:free, etc.) | Free tier | Yes | Good fallback; another teammate can register free and share |
| **Ollama local** (Qwen/DeepSeek/Llama small instruct models) | Free, offline | **No** | The RTX 4050 6 GB laptop can run small models; the RTX 3050 4 GB runs only very small ones. Best option if the venue has no internet |
| **Google AI Studio free tier** (Gemini) | Free tier | Yes | Reasonable quota; requires account |
| **Groq free tier** | Free tier | Yes | Fast, generous dev quota |

### What each teammate needs to do

1. Install [OpenCode](https://opencode.ai). The repo's `.opencode/`
   configuration (agents, skills, permissions, context7 docs MCP) applies
   automatically when you open OpenCode inside `CyberForge_CART/`.
2. The default model is a **free** OpenCode model — nothing to pay, no key to
   manage for coding assistance.
3. Everything an agent does in this repo is governed by the permissions in
   `.opencode/opencode.json`: e.g. git pushes and `pip install` ask first,
   `masscan` is denied, active scanners ask.

### The exact boundary (important for the PRD)

Even if we add an LLM: it may **explain, summarise, prioritise, and draft
report text**. It may never: change the scope, approve its own finding,
decide a target is in scope, or execute a tool outside the PolicyGate. The
verifier's CONFIRMED status requires repeatable tool evidence, period.
