# PTES mapping

Every Task, ToolEvent and Finding carries a canonical PTES phase (spec
section 9; PRD FR-5). Constants live in `src/cart/ptes.py`

1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post-Exploitation
7. Reporting

## Engine default mapping (`ptes.py::DEFAULT_ACTIVITY_PHASE`)

| Engine activity | Canonical phase |
|---|---|
| Candidate network discovery | 1 Pre-engagement Interactions |
| Host discovery | 2 Intelligence Gathering |
| Port/service discovery | 2 Intelligence Gathering |
| Web crawl/endpoint discovery | 2 Intelligence Gathering |
| Binary static analysis | 2 Intelligence Gathering |
| Finding verification checks | 4 Vulnerability Analysis |
| Attack-path construction | 3 Threat Modeling |
| Report generation | 7 Reporting |

Rules:

- PRD example labels map to the closest canonical phase (e.g. port/service
  discovery → Intelligence Gathering).
- Labels must stay byte-identical across event logs, findings, and the final
  report — the report generator never re-invents a phase name.
- Exploitation (5) and Post-Exploitation (6) phases stay empty in the first
  release: the platform is discovery + verification by design; any
  organiser-permitted flag capture is an explicitly registered adapter with
  its own PTES label.
