"""Binary specialist (spec section 5.7, PRD FR-3)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..models import Task
from ..scope import PolicyGate


class BinaryWorker:
    """Static analysis of organiser-supplied, hash-registered binaries only.

    Suggested adapter: Ghidra headless. radare2/angr remain optional targeted
    tools until formats and the resource budget are known.

    Hard rules:
    - refuses any file whose sha256 is not in the scope manifest (hash
      mismatch -> reject + record)
    - never opens local files outside the registered binary set
    - enforces CPU/memory/time limits; malformed inputs fail gracefully
    """

    def __init__(self, gate: PolicyGate):
        self.gate = gate

    @staticmethod
    def sha256(path: str | Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def verify_registered(self, path: str | Path) -> bool:
        """True only when the on-disk hash matches the manifest entry."""
        expected = self.gate.manifest.binary_hashes.get(str(path))
        return bool(expected) and expected == self.sha256(path)

    def run(self, task: Task) -> dict:  # noqa: ARG002
        raise NotImplementedError("integrated in build-order step 6")
