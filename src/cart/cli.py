"""CART command-line entrypoint (spec section 5.1: one-command product experience).

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
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

# Reconfigure stdout/stderr for Windows consoles with cp1252 default
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:  # noqa: S110 BLE001
        pass

from .models import (
    FindingStatus,
    RunStatus,
    ScopeManifest,
    Task,
    TaskStatus,
    new_id,
    utc_now,
)
from .orchestrator import Orchestrator
from .preflight import format_candidates_table, list_candidate_networks
from .ptes import PtesPhase
from .report import ReportGenerator
from .scope import PolicyGate
from .store import connect
from .verify import VerificationService
from .workers.binary import BinaryWorker
from .workers.network import NetworkWorker
from .workers.web import WebWorker

DEFAULT_DB = "cart.db"


def _get_db(db_path: str = DEFAULT_DB) -> sqlite3.Connection:
    return connect(db_path, check_same_thread=False)


# ---------------------------------------------------------------------------
# Command: preflight
# ---------------------------------------------------------------------------

def cmd_preflight(args: argparse.Namespace) -> int:
    """List candidate networks for organiser review (read-only, no scanning)."""
    candidates = list_candidate_networks()
    print(format_candidates_table(candidates))

    # Save candidates to DB if available
    conn = _get_db(args.db)
    for c in candidates:
        conn.execute(
            """
            INSERT OR REPLACE INTO candidate_networks
            (candidate_id, interface, address, prefix, family, route_metadata, confidence, selection_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                c["candidate_id"],
                c["interface"],
                c["address"],
                c["prefix"],
                c["family"],
                c["route_metadata"],
                c["confidence"],
                c["selection_status"],
            ),
        )
    conn.commit()
    return 0


# ---------------------------------------------------------------------------
# Command: select
# ---------------------------------------------------------------------------

def cmd_select(args: argparse.Namespace) -> int:
    """Phase B: Organiser picks lab target, exclusions, and locks the scope."""
    conn = _get_db(args.db)

    print("=== Phase B: Organiser Scope Selection ===")
    prefix = args.prefix
    if not prefix:
        candidates = list_candidate_networks()
        if not candidates:
            print("No candidate networks detected. Please specify --prefix manually.")
            return 1

        print(format_candidates_table(candidates))
        choice = input("\nSelect candidate number (or press Enter for [1]): ").strip()
        idx = int(choice) - 1 if choice.isdigit() else 0
        if 0 <= idx < len(candidates):
            prefix = candidates[idx]["prefix"]
        else:
            print("Invalid selection.")
            return 1

    print(f"Selected Lab Prefix: {prefix}")

    # Exclusions
    exclusions: list[str] = []
    if args.exclude:
        exclusions = [e.strip() for e in args.exclude.split(",") if e.strip()]

    # Binary hashes
    binaries: dict[str, str] = {}
    if args.binaries:
        for b_path in args.binaries.split(","):
            bp = Path(b_path.strip())
            if bp.exists():
                digest = hashlib.sha256(bp.read_bytes()).hexdigest()
                binaries[str(bp)] = digest
                print(f"Registered binary: {bp} (sha256: {digest[:16]}...)")
            else:
                print(f"Warning: binary {bp} does not exist, skipping.")

    scope_version = new_id("scope")
    locked_at = utc_now()

    manifest = ScopeManifest(
        scope_version=scope_version,
        included_prefixes=[prefix],
        included_hosts=[],
        exclusions=exclusions,
        binary_hashes=binaries,
        created_by="organiser-cli",
        locked_at=locked_at,
    )

    conn.execute(
        """
        INSERT INTO scope_manifests
        (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            manifest.scope_version,
            json.dumps(manifest.included_prefixes),
            json.dumps(manifest.included_hosts),
            json.dumps(manifest.exclusions),
            json.dumps(manifest.binary_hashes),
            manifest.created_by,
            manifest.locked_at,
        ),
    )
    conn.commit()

    print(f"\n✅ Scope manifest `{scope_version}` locked at {locked_at}.")
    print("Ready to run: execute `cart run` to start the autonomous assessment.")
    return 0


# ---------------------------------------------------------------------------
# Command: run
# ---------------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    """Phase C-H: Fully autonomous assessment run within locked scope."""
    conn = _get_db(args.db)

    # Fetch latest locked scope manifest
    row = conn.execute(
        "SELECT scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at "
        "FROM scope_manifests WHERE locked_at IS NOT NULL ORDER BY locked_at DESC LIMIT 1"
    ).fetchone()

    if not row:
        print("❌ No locked scope manifest found! Please run `cart select` first.")
        return 1

    manifest = ScopeManifest(
        scope_version=row[0],
        included_prefixes=json.loads(row[1] or "[]"),
        included_hosts=json.loads(row[2] or "[]"),
        exclusions=json.loads(row[3] or "[]"),
        binary_hashes=json.loads(row[4] or "{}"),
        created_by=row[5],
        locked_at=row[6],
    )

    run_id = new_id("run")
    start_time = utc_now()
    print(f"=== Starting Autonomous Assessment Run: {run_id} ===")
    print(f"Scope Version: {manifest.scope_version} (Locked: {manifest.locked_at})")
    print(f"Included Targets: {manifest.included_prefixes + manifest.included_hosts}")
    print(f"Exclusions: {manifest.exclusions or 'None'}")
    print("Beginning autonomous phases... (0 human intervention required)\n")

    # Initialize Run record
    conn.execute(
        "INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES (?, ?, ?, ?, ?)",
        (run_id, RunStatus.RUNNING.value, args.tier, start_time, manifest.scope_version),
    )
    conn.commit()

    # Optional live background UI dashboard
    if getattr(args, "ui", False):
        import threading

        from .ui import run_dashboard_server
        def _run_ui():
            srv = run_dashboard_server(db_path=args.db, host="127.0.0.1", port=8080)
            srv.serve_forever()
        t = threading.Thread(target=_run_ui, daemon=True)
        t.start()

    # PolicyGate
    gate = PolicyGate(manifest)
    gate.bind_store(conn)

    # Initialize Orchestrator
    orchestrator = Orchestrator(
        conn=conn,
        run_id=run_id,
        max_concurrency=args.concurrency,
        total_time_budget_s=args.timeout,
    )

    # Initialize Workers
    try:
        net_worker = NetworkWorker(conn=conn, gate=gate, run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        print(f"Warning: NetworkWorker init (nmap): {exc}")
        net_worker = None

    web_worker = WebWorker(conn=conn, gate=gate, run_id=run_id)
    bin_worker = BinaryWorker(conn=conn, gate=gate, run_id=run_id)

    # Seed initial tasks from scope manifest
    for prefix in manifest.included_prefixes:
        t = Task(
            task_id=new_id("task"),
            task_type="host_discovery",
            owner="network",
            target_id=prefix,
            status=TaskStatus.READY,
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            dedupe_key=f"{run_id}:host:{prefix}",
            budget={"timeout_s": 180, "retries": 1},
        )
        orchestrator.create_task(t)

    for b_path in manifest.binary_hashes:
        t = Task(
            task_id=new_id("task"),
            task_type="binary_static_analysis",
            owner="binary",
            target_id=b_path,
            status=TaskStatus.READY,
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            dedupe_key=f"{run_id}:bin:{b_path}",
            budget={"timeout_s": 60, "retries": 1},
        )
        orchestrator.create_task(t)

    # Unified task dispatcher
    def dispatch_worker(task: Task) -> dict:
        print(f"[*] Executing task {task.task_id} [{task.task_type}] on target {task.target_id}")
        if task.owner == "network":
            if net_worker is None:
                raise RuntimeError("Network worker not available (nmap missing)")
            return net_worker.run(task)
        elif task.owner == "web":
            return web_worker.run(task)
        elif task.owner == "binary":
            return bin_worker.run(task)
        else:
            raise ValueError(f"Unknown task owner: {task.owner}")

    # Callback for result fan-out
    def handle_result(task: Task, result: dict) -> None:
        if task.task_type == "host_discovery":
            web_assets = result.get("web_asset_ids", [])
            for asset_id in result.get("assets", []):
                is_web = asset_id in web_assets
                orchestrator.on_host_discovered(asset_id, is_web=is_web)
        elif task.task_type == "web_crawl_endpoint_discovery":
            # Web→Binary agent hand-off: auto-enqueue static analysis for
            # every binary artefact downloaded during the crawl (no human
            # intervention after scope lock).
            for disc in result.get("discovered_binaries", []):
                bin_path = disc.get("path", "")
                if not bin_path:
                    continue
                print(
                    f"[+] Web→Binary hand-off: binary downloaded from "
                    f"{disc.get('url', '?')} (sha256 {disc.get('sha256', '?')[:16]}...) "
                    f"→ auto-enqueueing binary agent."
                )
                orchestrator.on_binary_discovered(bin_path, source_task=task)

    # Run scheduling loop
    print("[*] Dispatching tasks across orchestrator loop...")
    orchestrator.run_loop(worker_fn=dispatch_worker, on_result=handle_result)

    # Verification Phase
    print("\n[*] Running Verification Service on candidate findings...")
    verifier = VerificationService(conn=conn, run_id=run_id)
    candidate_rows = conn.execute(
        "SELECT finding_id FROM findings WHERE status = ?",
        (FindingStatus.CANDIDATE.value,),
    ).fetchall()
    fids = [r[0] for r in candidate_rows]
    verifier.queue(fids)
    ver_results = verifier.verify_all_queued()
    print(f"[*] Verified {len(ver_results)} findings.")

    # Final Report Generation
    print("\n[*] Generating Consolidated Assessment Report...")
    reporter = ReportGenerator(conn=conn, output_dir=args.report_dir)
    report_info = reporter.generate(run_id=run_id)

    print("\n" + "=" * 60)
    print("✅ Assessment Completed!")
    print(f"Summary: {report_info['summary']}")
    print(f"Markdown Report: {report_info['md_report']}")
    print(f"JSON Report:     {report_info['json_report']}")
    print("=" * 60)
    return 0


# ---------------------------------------------------------------------------
# Command: status
# ---------------------------------------------------------------------------

def cmd_status(args: argparse.Namespace) -> int:
    """Display latest run status, task counts, and finding counts."""
    conn = _get_db(args.db)
    run_row = conn.execute(
        "SELECT run_id, status, tier, started_at, completed_at, scope_version FROM runs ORDER BY started_at DESC LIMIT 1"
    ).fetchone()

    if not run_row:
        print("No runs recorded in database.")
        return 0

    run_id, status, tier, start, end, scope_ver = run_row
    print(f"Latest Run:      {run_id}")
    print(f"Status:          {status.upper()}")
    print(f"Tier:            {tier}")
    print(f"Scope Version:   {scope_ver}")
    print(f"Started At:      {start}")
    print(f"Completed At:    {end or 'In Progress'}")

    # Task status breakdown
    task_counts = conn.execute(
        "SELECT status, count(*) FROM tasks GROUP BY status"
    ).fetchall()
    print("\nTasks Breakdown:")
    for st, cnt in task_counts:
        print(f"  {st:<15}: {cnt}")

    # Findings status breakdown
    finding_counts = conn.execute(
        "SELECT status, count(*) FROM findings GROUP BY status"
    ).fetchall()
    print("\nFindings Breakdown:")
    for st, cnt in finding_counts:
        print(f"  {st:<15}: {cnt}")

    return 0


# ---------------------------------------------------------------------------
# Command: ui
# ---------------------------------------------------------------------------

def cmd_ui(args: argparse.Namespace) -> int:
    """Launch the zero-dependency local web dashboard."""
    from .ui import run_dashboard_server

    server = run_dashboard_server(
        db_path=args.db,
        host=args.host,
        port=args.port,
        open_browser=args.open_browser,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped.")
        server.server_close()
    return 0


# ---------------------------------------------------------------------------
# Command: report
# ---------------------------------------------------------------------------

def cmd_report(args: argparse.Namespace) -> int:
    """Print or display the most recently generated markdown report."""
    conn = _get_db(args.db)
    rep_row = conn.execute(
        "SELECT path FROM report_artifacts WHERE format = 'md' ORDER BY created_at DESC LIMIT 1"
    ).fetchone()

    if not rep_row or not Path(rep_row[0]).exists():
        print("No markdown report found. Run `cart run` first.")
        return 1

    path = Path(rep_row[0])
    print(path.read_text(encoding="utf-8"))
    return 0


# ---------------------------------------------------------------------------
# Main CLI Router
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cart",
        description="CyberForge CART - Controlled, Multi-Agent Assessment Engine",
    )
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite database path")

    sub = parser.add_subparsers(dest="command", required=True)

    # cart preflight
    sub.add_parser("preflight", help="Phase A: list candidate networks (read-only)")

    # cart select
    p_select = sub.add_parser("select", help="Phase B: organiser selects lab, locks scope")
    p_select.add_argument("--prefix", help="Lab network CIDR prefix to select")
    p_select.add_argument("--exclude", help="Comma-separated CIDRs/IPs to exclude")
    p_select.add_argument("--binaries", help="Comma-separated binary file paths to register")

    # cart run
    p_run = sub.add_parser("run", help="Phase C-H: autonomous run to final report")
    p_run.add_argument("--tier", default="recon", choices=["recon", "breach", "deep"], help="Assessment tier")
    p_run.add_argument("--concurrency", type=int, default=4, help="Max concurrent workers (default 4)")
    p_run.add_argument("--timeout", type=int, default=1200, help="Run budget timeout in seconds (default 1200 / 20 min)")
    p_run.add_argument("--report-dir", default="reports", help="Directory for generated reports")
    p_run.add_argument("--ui", action="store_true", help="Launch live UI dashboard in background during assessment")

    # cart status
    sub.add_parser("status", help="show current run status")

    # cart report
    sub.add_parser("report", help="open the final consolidated report")

    # cart ui
    p_ui = sub.add_parser("ui", help="launch local interactive web dashboard")
    p_ui.add_argument("--host", default="127.0.0.1", help="Host IP to bind (default 127.0.0.1)")
    p_ui.add_argument("--port", type=int, default=8080, help="HTTP port to listen on (default 8080)")
    p_ui.add_argument("--open-browser", action="store_true", help="Automatically open browser on launch")

    args = parser.parse_args(argv)

    handlers = {
        "preflight": cmd_preflight,
        "select": cmd_select,
        "run": cmd_run,
        "status": cmd_status,
        "report": cmd_report,
        "ui": cmd_ui,
    }

    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
