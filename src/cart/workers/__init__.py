"""Specialist worker packages.

Workers are executed, they do not coordinate through free-form chat or shell
hand-offs. Each worker implements the input/output contract from spec
section 7 and only acts inside what the PolicyGate allows.

IMPORTANT: worker classes never run tools themselves in-band; adapters execute
as bounded subprocesses with timeouts, allowlists and output caps.
"""
