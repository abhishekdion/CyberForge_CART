"""Bounded task-graph orchestrator (spec sections 5.4, 7, 8).

Design rules:
- Deterministic code owns scheduling, limits, dedup and state transitions.
- Bounded fan-out/fan-in. No free-form agent mesh, no unbounded recursion.
- Tasks go PENDING -> READY -> RUNNING -> SUCCEEDED | FAILED | TIMED_OUT | CANCELLED.
- Retries only within the task's retry budget and only if idempotent.
"""

from __future__ import annotations

from .models import Task, TaskStatus


class Orchestrator:
    def __init__(self, max_concurrency: int = 4, total_time_budget_s: int = 1200):
        self.max_concurrency = max_concurrency
        self.total_time_budget_s = total_time_budget_s  # PRD: report ready < 20 min
        self.tasks: dict[str, Task] = {}

    def create_task(self, task: Task) -> str:
        """Create a task unless an equivalent one already exists (dedupe_key)."""
        for existing in self.tasks.values():
            if existing.dedupe_key and existing.dedupe_key == task.dedupe_key:
                return existing.task_id
        self.tasks[task.task_id] = task
        return task.task_id

    def ready_tasks(self, max_n: int | None = None) -> list[Task]:
        # Filter for READY (not PENDING) — tasks move PENDING -> READY before scheduling.
        ready = [t for t in self.tasks.values() if t.status is TaskStatus.READY]
        return ready[:max_n]  # slice with None means no limit

    def transition(self, task_id: str, new_status: TaskStatus) -> None:
        task = self.tasks.get(task_id)
        if task is None:
            raise KeyError(f"unknown task {task_id}")
        # Legal transitions (spec section 7). Anything else is a bug, not a gamma.
        legal: dict[TaskStatus, set[TaskStatus]] = {
            TaskStatus.PENDING: {TaskStatus.READY, TaskStatus.CANCELLED},
            TaskStatus.READY: {TaskStatus.RUNNING, TaskStatus.CANCELLED},
            TaskStatus.RUNNING: {
                TaskStatus.SUCCEEDED,
                TaskStatus.FAILED,
                TaskStatus.TIMED_OUT,
                TaskStatus.CANCELLED,
            },
            # FAILED may return to READY only within retry budget (idempotent retries).
            TaskStatus.FAILED: {TaskStatus.READY, TaskStatus.CANCELLED},
            TaskStatus.TIMED_OUT: {TaskStatus.CANCELLED},
        }
        if new_status not in legal.get(task.status, set()):
            raise ValueError(f"illegal transition {task.status.value} -> {new_status.value}")
        task.status = new_status

    # --- hand-offs to specialists (build-order step 4) -----------------------
    def on_host_discovered(self, run_id: str, asset_id: str, is_web: bool) -> None:  # noqa: ARG002
        raise NotImplementedError

    def on_run_budget_exhausted(self) -> None:  # noqa: ARG002
        raise NotImplementedError("stop scheduling, cancel eligible work, partial report")
