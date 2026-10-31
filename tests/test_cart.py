"""Comprehensive test suite for CyberForge CART engine (stdlib unittest)."""

import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from cart.attackpath import AttackPathBuilder, PathEdge
from cart.budget import BudgetExceeded, RunBudget, TaskRetryBudget
from cart.models import (
    Asset, Finding, FindingStatus, Relationship, RunStatus, ScopeDecision,
    ScopeManifest, Service, Task, TaskStatus, new_id, utc_now,
)
from cart.orchestrator import Orchestrator
from cart.preflight import list_candidate_networks
from cart.report import ReportGenerator
from cart.scope import PolicyGate, ScopeNotLockedError
from cart.store import connect
from cart.verify import VerificationService
from cart.workers.binary import BinaryWorker, _detect_format, _parse_elf_header


class TestPolicyGate(unittest.TestCase):
    def setUp(self):
        self.manifest = ScopeManifest(
            scope_version="test_v1",
            included_prefixes=["192.168.1.0/24"],
            included_hosts=["10.0.0.5"],
            exclusions=["192.168.1.254"],
            binary_hashes={"/bin/sample": "abcdef123456"},
            locked_at=utc_now(),
        )
        self.gate = PolicyGate(self.manifest)

    def test_unlocked_manifest_raises(self):
        unlocked = ScopeManifest(scope_version="unlocked")
        with self.assertRaises(ScopeNotLockedError):
            PolicyGate(unlocked)

    def test_in_scope_destination(self):
        res = self.gate.check_destination("192.168.1.50")
        self.assertEqual(res.decision, ScopeDecision.ALLOW)

    def test_in_scope_host(self):
        res = self.gate.check_destination("10.0.0.5")
        self.assertEqual(res.decision, ScopeDecision.ALLOW)

    def test_exclusion_always_wins(self):
        res = self.gate.check_destination("192.168.1.254")
        self.assertEqual(res.decision, ScopeDecision.DENY)
        self.assertIn("excluded", res.reason)

    def test_out_of_scope_destination(self):
        res = self.gate.check_destination("8.8.8.8")
        self.assertEqual(res.decision, ScopeDecision.DENY)

    def test_unparseable_destination(self):
        res = self.gate.check_destination("not-a-valid-ip-or-cidr")
        self.assertEqual(res.decision, ScopeDecision.DENY)
        self.assertIn("unparseable", res.reason)

    def test_binary_file_check(self):
        res = self.gate.check_binary_file("/bin/sample")
        self.assertEqual(res.decision, ScopeDecision.ALLOW)
        res_bad = self.gate.check_binary_file("/bin/unknown")
        self.assertEqual(res_bad.decision, ScopeDecision.DENY)

    def test_audit_log_recording(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit_test.db"
            conn = connect(db_path)
            self.gate.bind_store(conn)
            self.gate.gate("192.168.1.10", run_id="run_test")
            row = conn.execute("SELECT requested_target, decision FROM scope_decisions_log").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "192.168.1.10")
            self.assertEqual(row[1], "allow")
            conn.close()


class TestBudgetAndOrchestrator(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_orch.db"
        self.conn = connect(self.db_path)

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_retry_budget_backoff_and_cap(self):
        rb = TaskRetryBudget(task_id="t1", max_retries=2, backoff_base=2.0)
        self.assertTrue(rb.can_retry())
        w1 = rb.consume()
        self.assertEqual(w1, 1.0)
        w2 = rb.consume()
        self.assertEqual(w2, 2.0)
        self.assertFalse(rb.can_retry())
        with self.assertRaises(BudgetExceeded):
            rb.consume()

    def test_run_budget_expiration(self):
        rb = RunBudget(run_id="r1", total_seconds=0, max_tasks=10)
        self.assertTrue(rb.is_expired())
        with self.assertRaises(BudgetExceeded):
            rb.check_time()

    def test_orchestrator_dedup(self):
        orch = Orchestrator(conn=self.conn, run_id="run_test")
        t1 = Task(
            task_id="t1",
            task_type="discovery",
            owner="network",
            target_id="10.0.0.1",
            dedupe_key="dup_key_1",
            status=TaskStatus.READY,
        )
        t2 = Task(
            task_id="t2",
            task_type="discovery",
            owner="network",
            target_id="10.0.0.1",
            dedupe_key="dup_key_1",
            status=TaskStatus.READY,
        )
        id1 = orch.create_task(t1)
        id2 = orch.create_task(t2)
        self.assertEqual(id1, id2)
        self.assertEqual(id1, "t1")

    def test_orchestrator_transitions(self):
        orch = Orchestrator(conn=self.conn, run_id="run_test")
        t1 = Task(
            task_id="t1",
            task_type="discovery",
            owner="network",
            target_id="10.0.0.1",
            status=TaskStatus.PENDING,
        )
        orch.create_task(t1)
        orch.transition("t1", TaskStatus.READY)
        self.assertEqual(orch.get_task("t1").status, TaskStatus.READY)
        orch.transition("t1", TaskStatus.RUNNING)
        self.assertEqual(orch.get_task("t1").status, TaskStatus.RUNNING)
        orch.transition("t1", TaskStatus.SUCCEEDED)
        self.assertEqual(orch.get_task("t1").status, TaskStatus.SUCCEEDED)

        # Illegal transition
        with self.assertRaises(ValueError):
            orch.transition("t1", TaskStatus.RUNNING)


class TestAttackPathBuilder(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_attackpath.db"
        self.conn = connect(self.db_path)

        # Insert run first for FK integrity
        self.conn.execute("INSERT INTO runs (run_id, status, tier) VALUES ('r1', 'running', 'recon')")

        # Insert assets
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a1', 'r1', 'host', '10.0.0.1', '', '')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a2', 'r1', 'host', '10.0.0.2', '', '')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a3', 'r1', 'host', '10.0.0.3', '', '')")

        # Insert findings & evidence
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f1', 'a2', 'ssh', 'high', 'confirmed')")
        self.conn.execute("INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp) VALUES ('ev1', 'f1', 'tool', '', 'h1', '')")
        self.conn.execute("INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp) VALUES ('ev2', 'f1', 'tool', '', 'h2', '')")

        # Insert relationships
        self.conn.execute("INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES ('a1', 'a2', 'SSH_BRUTE', 'ev1', 'high')")
        self.conn.execute("INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES ('a2', 'a3', 'PASS_HASH', 'ev2', 'medium')")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_attack_path_traversal_and_scoring(self):
        builder = AttackPathBuilder(self.conn, "r1")
        paths = builder.build(entry_points=["a1"], high_value_targets=["a3"])
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p.hop_count, 2)
        # 0.9 * 0.7 = 0.63
        self.assertAlmostEqual(p.score, 0.63, places=2)
        report = builder.format_paths_report(paths)
        self.assertIn("10.0.0.1", report)
        self.assertIn("10.0.0.3", report)


class TestVerificationService(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_verify.db"
        self.conn = connect(self.db_path)
        # Insert run first for FK integrity
        self.conn.execute("INSERT INTO runs (run_id, status, tier) VALUES ('r1', 'running', 'recon')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a1', 'r1', 'host', '10.0.0.1', '', '')")

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_verify_web_form(self):
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f_web', 'a1', 'web_form_endpoint', 'info', 'candidate')")
        ev_excerpt = json.dumps({"action": "/login", "inputs": [{"name": "username"}, {"name": "password"}]})
        self.conn.execute("INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt) VALUES ('e1', 'f_web', 'crawler', '', 'h1', '', ?)", (ev_excerpt,))
        self.conn.commit()

        svc = VerificationService(self.conn, "r1")
        svc.queue(["f_web"])
        res = svc.verify_one("f_web")
        self.assertEqual(res, FindingStatus.CONFIRMED)


class TestReportGenerator(unittest.TestCase):
    def test_generate_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            conn = connect(db_path)
            conn.execute("INSERT INTO runs (run_id, status, tier, started_at, completed_at, scope_version) VALUES ('r_test', 'completed', 'recon', '2026-01-01T00:00:00', '2026-01-01T00:05:00', 's1')")
            conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s1', '[\"192.168.1.0/24\"]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00')")
            conn.commit()

            rep = ReportGenerator(conn, output_dir=tmpdir)
            out = rep.generate("r_test")
            self.assertTrue(Path(out["json_report"]).exists())
            self.assertTrue(Path(out["md_report"]).exists())
            md_text = Path(out["md_report"]).read_text(encoding="utf-8")
            self.assertIn("CyberForge CART Assessment Report", md_text)
            self.assertIn("PRD Assessment Metrics", md_text)
            conn.close()


class TestUIDashboard(unittest.TestCase):
    def test_ui_handler_methods(self):
        import io
        from cart.ui import DashboardHandler

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_ui.db"
            conn = connect(db_path)
            conn.execute("INSERT INTO runs (run_id, status, tier, started_at, completed_at, scope_version) VALUES ('r_ui', 'completed', 'recon', '2026-01-01T00:00:00', '2026-01-01T00:05:00', 's_ui')")
            conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s_ui', '[\"192.168.1.0/24\"]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00')")
            conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_ui', 'r_ui', 'host', '10.0.0.1', '', '')")
            conn.commit()
            conn.close()

            # Mock a minimal request
            class MockHandler(DashboardHandler):
                def __init__(self):
                    self.db_path = str(db_path)
                    self.wfile = io.BytesIO()
                    self._headers_buffer = []

                def send_response(self, code, message=None):
                    self.response_code = code

                def send_header(self, keyword, value):
                    pass

                def end_headers(self):
                    pass

            handler = MockHandler()

            # Test _handle_status
            handler._handle_status()
            res = json.loads(handler.wfile.getvalue())
            self.assertEqual(res["run_id"], "r_ui")
            self.assertIn("metrics", res)

            # Test _handle_inventory
            handler.wfile = io.BytesIO()
            handler._handle_inventory()
            inv = json.loads(handler.wfile.getvalue())
            self.assertEqual(len(inv), 1)
            self.assertEqual(inv[0]["canonical_key"], "10.0.0.1")

            # Test _handle_candidates
            handler.wfile = io.BytesIO()
            handler._handle_candidates()
            cand = json.loads(handler.wfile.getvalue())
            self.assertIsInstance(cand, list)

            # Test _handle_graph
            handler.wfile = io.BytesIO()
            handler._handle_graph()
            gdata = json.loads(handler.wfile.getvalue())
            self.assertIn("nodes", gdata)
            self.assertIn("edges", gdata)


if __name__ == "__main__":
    unittest.main()
