"""CyberForge CART - controlled multi-agent assessment engine.

Package layout (see docs/architecture.md):

- preflight   Phase A candidate network identification
- scope       Phase B/C scope registry + execution policy gate (fail closed)
- orchestrator bounded task-graph controller
- workers     network / web / binary specialists
- verify      candidate -> confirmed verification service
- attackpath  evidence-backed attack path builder
- report      unified report generator + local API
- models      frozen data contracts (spec section 6)
- store       SQLite persistence
- ptes        canonical PTES phase constants

Version parity: this package implements the design in
CyberForge_CART_Architecture_Design_Spec_v0.1.md.
"""

__version__ = "0.1.0"
