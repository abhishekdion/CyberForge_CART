# CyberForge CART — Documentation

CART is a controlled, multi-agent penetration-test engine for the
organiser-designated CyberForge lab. It assesses three attack surfaces
(network, web, supplied binaries), lets specialised workers coordinate through
shared typed records (not chat), verifies findings before trusting them, maps
everything to PTES, and produces one evidence-backed report with an attack
path.

| Doc | What it covers |
|---|---|
| [how-it-works.md](how-it-works.md) | The full run lifecycle, Phase A→H, and exactly which parts are autonomous vs human |
| [architecture.md](architecture.md) | Components, agent coordination model, worker contracts |
| [agents-and-llms.md](agents-and-llms.md) | **Which AI/LLM the project uses, and the free options** (the answer for teammates) |
| [safety.md](safety.md) | Scope-locked execution policy, what gates every tool action |
| [data-contracts.md](data-contracts.md) | Shared record types, task/finding lifecycle |
| [ptes.md](ptes.md) | PTES phase labelling rules |
| [build-plan.md](build-plan.md) | Build order, laptop roles, PRD measures, open decisions |

Spec of record: `CyberForge_CART_Architecture_Design_Spec_v0.1.md` (one folder
up). Code structure mirrors its sections 4–10; the `docs/` layer explains it
in working terms.
