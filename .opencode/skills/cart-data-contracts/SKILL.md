---
name: cart-data-contracts
description: Use when changing src/cart/models.py record shapes, src/cart/store.py schema, dedupe keys, task/finding state enums, or anything that alters payload shapes between controller and workers. Freezes the shared data model.
---

# CART data contracts

The data model in spec section 6 is the team contract. Any change must keep
the dataclasses, the SQLite DDL and the docs saying the same thing.

## Change procedure

1. Modify `src/cart/models.py` (dataclasses + state enums together).
2. Modify the matching CREATE TABLE / flavour in `src/cart/store.py`.
3. Update `docs/data-contracts.md` in the SAME change.
4. If a worker input/output contract changed, update the worker stub
   docstrings and `docs/architecture.md` section 7 references.
5. Run `graphify update . --no-cluster` if structural code changed.

## Invariants (never break these inside a change)

- Every record carries `run_id`.
- Findings/evidence trace to originating task AND tool event.
- Graph edges (`Relationship`) always reference an `evidence_id`.
- Task states: PENDING -> READY -> RUNNING -> SUCCEEDED | FAILED |
  TIMED_OUT | CANCELLED (FAILED may return to READY inside retry budget only).
- Finding states: CANDIDATE -> VERIFICATION_QUEUED -> CONFIRMED | REJECTED |
  INCONCLUSIVE | NEEDS_REVIEW.
- Large raw outputs stay as files; SQLite keeps hashes/metadata only.
