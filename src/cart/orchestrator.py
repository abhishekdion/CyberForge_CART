"""Bounded task-graph orchestrator (spec sections 5.4, 7, 8).

Design rules:
- Deterministic code owns scheduling, limits, dedup and state transitions.
- Bounded fan-out/fan-in. No free-form agent mesh, no unbounded recursion.
- Tasks go PENDING -> READY -> RUNNING -> SUCCEEDED | FAILED | TIMED_OUT | CANCELLED.
- Retries only within the task's retry budget and only if idempotent.
- SQLite-backed: in-memory dict replaced in build-order step 4.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor

from .budget import BudgetExceeded, RunBudget, TaskRetryBudget
from .models import RunStatus, Task, TaskStatus, new_id, utc_now
from .ptes import PtesPhase


class Orchestrator:
    def __init__(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        max_concurrency: int = 4,
        total_time_budget_s: int = 1200,
        max_tasks: int = 500,
    ):
        self.conn = conn
        self.run_id = run_id
        self.max_concurrency = max_concurrency
        self.budget = RunBudget(run_id, total_time_budget_s, max_tasks)
        self._retry_budgets: dict[str, TaskRetryBudget] = {}

    # ------------------------------------------------------------------
    # Task creation (SQLite-backed, dedupe enforced at DB level)
    # ------------------------------------------------------------------

    def create_task(self, task: Task) -> str:
        """Persist a task unless an equivalent dedupe_key already exists."""
        # Budget check before creation
        count = self._task_count()
        self.budget.check_all(count)

        try:
            self.conn.execute(
                """
                INSERT INTO tasks
                    (task_id, task_type, owner, target_id, status,
                     ptes_phase, parent_task_id, dedupe_key, budget)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    task.task_type,
                    task.owner,
                    task.target_id,
                    task.status.value,
                    task.ptes_phase,
                    task.parent_task_id,
                    task.dedupe_key,
                    json.dumps(task.budget),
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            # Dedupe key conflict — return the existing task_id
            if task.dedupe_key:
                row = self.conn.execute(
                    "SELECT task_id FROM tasks WHERE dedupe_key = ?",
                    (task.dedupe_key,),
                ).fetchone()
                if row:
                    return row[0]
        return task.task_id

    def _task_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Task reads
    # ------------------------------------------------------------------

    def get_task(self, task_id: str) -> Task | None:
        row = self.conn.execute(
            "SELECT task_id, task_type, owner, target_id, status, "
            "ptes_phase, parent_task_id, dedupe_key, budget "
            "FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_task(row)

    def ready_tasks(self, max_n: int | None = None) -> list[Task]:
        q = "SELECT task_id, task_type, owner, target_id, status, " \
            "ptes_phase, parent_task_id, dedupe_key, budget " \
            "FROM tasks WHERE status = ?"
        rows = self.conn.execute(q, (TaskStatus.READY.value,)).fetchall()
        tasks = [self._row_to_task(r) for r in rows]
        return tasks[:max_n]

    @staticmethod
    def _row_to_task(row: tuple) -> Task:
        return Task(
            task_id=row[0],
            task_type=row[1],
            owner=row[2],
            target_id=row[3],
            status=TaskStatus(row[4]),
            ptes_phase=row[5] or "",
            parent_task_id=row[6],
            dedupe_key=row[7] or "",
            budget=json.loads(row[8] or "{}"),
        )

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def transition(self, task_id: str, new_status: TaskStatus) -> None:
        task = self.get_task(task_id)
        if task is None:
            raise KeyError(f"unknown task {task_id}")
        legal: dict[TaskStatus, set[TaskStatus]] = {
            TaskStatus.PENDING: {TaskStatus.READY, TaskStatus.CANCELLED},
            TaskStatus.READY: {TaskStatus.RUNNING, TaskStatus.CANCELLED},
            TaskStatus.RUNNING: {
                TaskStatus.SUCCEEDED,
                TaskStatus.FAILED,
                TaskStatus.TIMED_OUT,
                TaskStatus.CANCELLED,
            },
            TaskStatus.FAILED: {TaskStatus.READY, TaskStatus.CANCELLED},
            TaskStatus.TIMED_OUT: {TaskStatus.CANCELLED},
        }
        if new_status not in legal.get(task.status, set()):
            raise ValueError(
                f"illegal transition {task.status.value} -> {new_status.value}"
            )
        self.conn.execute(
            "UPDATE tasks SET status = ? WHERE task_id = ?",
            (new_status.value, task_id),
        )
        self.conn.commit()

    def mark_ready(self, task_id: str) -> None:
        self.transition(task_id, TaskStatus.READY)

    # ------------------------------------------------------------------
    # Run-level transitions
    # ------------------------------------------------------------------

    def set_run_status(self, status: RunStatus) -> None:
        ts = utc_now()
        if status in (RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.ABORTED):
            self.conn.execute(
                "UPDATE runs SET status = ?, completed_at = ? WHERE run_id = ?",
                (status.value, ts, self.run_id),
            )
        else:
            self.conn.execute(
                "UPDATE runs SET status = ? WHERE run_id = ?",
                (status.value, self.run_id),
            )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Budget-exhaustion handler
    # ------------------------------------------------------------------

    def on_run_budget_exhausted(self) -> None:
        """Cancel all PENDING/READY tasks; mark RUNNING as TIMED_OUT; set run PARTIAL."""
        # Cancel PENDING and READY
        for status in (TaskStatus.PENDING, TaskStatus.READY):
            self.conn.execute(
                "UPDATE tasks SET status = ? WHERE status = ?",
                (TaskStatus.CANCELLED.value, status.value),
            )
        # Mark still-RUNNING tasks as TIMED_OUT
        self.conn.execute(
            "UPDATE tasks SET status = ? WHERE status = ?",
            (TaskStatus.TIMED_OUT.value, TaskStatus.RUNNING.value),
        )
        self.conn.commit()
        self.set_run_status(RunStatus.PARTIAL)

    # ------------------------------------------------------------------
    # Fan-out helpers (called by workers after host discovery)
    # ------------------------------------------------------------------

    def on_host_discovered(self, asset_id: str, is_web: bool) -> None:
        """Emit follow-up tasks for a discovered host."""
        port_task = Task(
            task_id=new_id("task"),
            task_type="port_service_discovery",
            owner="network",
            target_id=asset_id,
            status=TaskStatus.READY,
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            dedupe_key=f"{self.run_id}:port:{asset_id}",
            budget={"timeout_s": 120, "retries": 2, "max_output": 1 << 20},
        )
        self.create_task(port_task)

        if is_web:
            web_task = Task(
                task_id=new_id("task"),
                task_type="web_crawl_endpoint_discovery",
                owner="web",
                target_id=asset_id,
                status=TaskStatus.READY,
                ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                dedupe_key=f"{self.run_id}:web:{asset_id}",
                budget={"timeout_s": 180, "retries": 1, "max_output": 2 << 20},
            )
            self.create_task(web_task)

    def on_binary_discovered(
        self, binary_path: str, source_task: Task | None = None
    ) -> str:
        """Web→Binary agent hand-off (judge requirement 2).

        Automatically enqueue a binary_static_analysis task for a binary
        downloaded by the WebWorker (already hash-registered with the gate).
        Dedupe key prevents re-enqueueing the same artefact twice per run.
        """
        task = Task(
            task_id=new_id("task"),
            task_type="binary_static_analysis",
            owner="binary",
            target_id=binary_path,
            status=TaskStatus.READY,
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            parent_task_id=source_task.task_id if source_task else None,
            dedupe_key=f"{self.run_id}:bin:{binary_path}",
            budget={"timeout_s": 60, "retries": 1, "max_output": 1 << 20},
        )
        return self.create_task(task)

    # ------------------------------------------------------------------
    # Scheduling loop
    # ------------------------------------------------------------------

    def run_loop(
        self,
        worker_fn: Callable[[Task], dict],
        on_result: Callable[[Task, dict], None] | None = None,
    ) -> None:
        """Drive the scheduling loop until budget exhausted or all tasks done.

        worker_fn(task) -> result dict  (called in thread pool)
        on_result(task, result) -> None (called in main thread after completion)
        """
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as pool:
            in_flight: dict[str, Future] = {}  # task_id -> Future

            while True:
                # Budget check
                if self.budget.is_expired():
                    self.on_run_budget_exhausted()
                    break

                # Harvest completed futures
                done_ids = [tid for tid, f in in_flight.items() if f.done()]
                for tid in done_ids:
                    fut = in_flight.pop(tid)
                    task = self.get_task(tid)
                    if task is None:
                        continue
                    try:
                        result = fut.result()
                        self.transition(tid, TaskStatus.SUCCEEDED)
                        if on_result and task:
                            on_result(task, result)
                    except BudgetExceeded:
                        self.transition(tid, TaskStatus.TIMED_OUT)
                    except Exception as exc:  # noqa: BLE001
                        print(f"[-] Task {tid} ({task.task_type}) error: {exc}")
                        # Retry logic
                        rb = self._retry_budgets.setdefault(
                            tid,
                            TaskRetryBudget(
                                tid,
                                max_retries=task.budget.get("retries", 1),
                            ),
                        )
                        if rb.can_retry():
                            wait = rb.consume()
                            time.sleep(min(wait, 5))  # cap sleep in loop
                            self.transition(tid, TaskStatus.FAILED)
                            self.transition(tid, TaskStatus.READY)
                        else:
                            self.transition(tid, TaskStatus.FAILED)

                # Schedule more tasks up to concurrency cap
                slots = self.max_concurrency - len(in_flight)
                if slots > 0:
                    for task in self.ready_tasks(max_n=slots):
                        self.transition(task.task_id, TaskStatus.RUNNING)
                        future = pool.submit(worker_fn, task)
                        in_flight[task.task_id] = future

                # All done?
                if not in_flight and not self.ready_tasks(max_n=1):
                    break

                time.sleep(0.1)  # brief poll interval

        # Final run status
        failed = self.conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE status IN ('failed','timed_out')"
        ).fetchone()[0]
        if failed:
            self.set_run_status(RunStatus.PARTIAL)
        else:
            self.set_run_status(RunStatus.COMPLETED)
