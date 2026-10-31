"""CART command-line entrypoint (spec section 5.1: one-command product
experience).

    cart preflight   -> Phase A: show candidate networks
    cart select      -> Phase B: organiser selects lab + scope lock
    cart run         -> Phase C-H: autonomous assessment to final report
    cart status      -> show running/completed state
    cart report      -> open the consolidated report

After `cart run` starts, no further human input is required (the autonomy
boundary is scope lock -> RUNNING).
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cart")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight", help="Phase A: list candidate networks (read-only)")
    sub.add_parser("select", help="Phase B: organiser selects lab, locks scope")
    sub.add_parser("run", help="Phase C-H: autonomous run to final report")
    sub.add_parser("status", help="show current run status")
    sub.add_parser("report", help="open the final consolidated report")
    args = parser.parse_args(argv)

    if args.command == "preflight":
        from .preflight import list_candidate_networks

        candidates = list_candidate_networks()
        print(candidates)
        return 0

    print(
        f"`cart {args.command}` is not implemented yet. See docs/build-plan.md "
        f"for the build order and TODO.md for the current phase."
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
