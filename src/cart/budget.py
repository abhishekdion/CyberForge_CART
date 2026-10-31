"""Run and task budget enforcement for CyberForge CART.

Standard-library only. No background threads: time is measured at gate calls
using :func:`time.monotonic`, and retry budgets are count-based (sliding)
rather than tied to an absolute clock deadline.
"""

import time


class BudgetExceeded(Exception):
    """Raised when any budget limit is hit."""

    def __init__(self, reason: str, budget_type: str):
        super().__init__(reason)
        self.reason = reason
        self.budget_type = budget_type

    def __str__(self) -> str:
        return f"BudgetExceeded[{self.budget_type}]: {self.reason}"


class RunBudget:
    """Wall-clock and task-count budget for a single assessment run."""

    def __init__(self, run_id: str, total_seconds: int = 1200, max_tasks: int = 200):
        self.run_id = run_id
        self.total_seconds = float(total_seconds)
        self.max_tasks = int(max_tasks)
        self._start_time = time.monotonic()

    def time_remaining(self) -> float:
        """Seconds left; 0.0 if expired. Never negative."""
        elapsed = time.monotonic() - self._start_time
        return max(0.0, self.total_seconds - elapsed)

    def is_expired(self) -> bool:
        """True if wall-clock budget is exhausted."""
        return self.time_remaining() <= 0.0

    def check_time(self) -> None:
        """Raise BudgetExceeded if expired."""
        if self.is_expired():
            raise BudgetExceeded(
                f"Run time budget exhausted for run {self.run_id}",
                "time",
            )

    def check_task_count(self, current_count: int) -> None:
        """Raise BudgetExceeded if current_count >= max_tasks."""
        if current_count >= self.max_tasks:
            raise BudgetExceeded(
                f"Task count {current_count} reached ceiling {self.max_tasks} for run {self.run_id}",
                "tasks",
            )

    def check_all(self, current_count: int) -> None:
        """Convenience: check time AND task count."""
        self.check_time()
        self.check_task_count(current_count)


class TaskRetryBudget:
    """Per-task retry budget with exponential backoff."""

    def __init__(self, task_id: str, max_retries: int = 3, backoff_base: float = 2.0):
        self.task_id = task_id
        self.max_retries = int(max_retries)
        self.backoff_base = float(backoff_base)
        self._retries_used = 0

    def can_retry(self) -> bool:
        """True if retries remaining > 0."""
        return self._retries_used < self.max_retries

    def consume(self) -> float:
        """
        Consume one retry. Returns the number of seconds the caller should
        wait before retrying (exponential backoff: backoff_base ** attempt,
        capped at 60 s). Raises BudgetExceeded if no retries left.
        """
        if not self.can_retry():
            raise BudgetExceeded(
                f"No retries remaining for task {self.task_id}",
                "retry",
            )
        attempt = self._retries_used
        wait = self.backoff_base**attempt
        wait = min(wait, 60.0)
        self._retries_used += 1
        return float(wait)

    def retries_used(self) -> int:
        """How many retries have been consumed so far."""
        return self._retries_used


if __name__ == "__main__":
    # PART 5 — Integration test

    # RunBudget simulation: total_seconds=5, max_tasks=3, loop 5 tasks.
    budget = RunBudget(run_id="test-run", total_seconds=5, max_tasks=3)

    for task_number in range(1, 6):
        try:
            budget.check_all(task_number)
            print(f"Task {task_number} passed check (count={task_number})")
        except BudgetExceeded as exc:
            print(f"BudgetExceeded raised: {exc}")
            break

    # TaskRetryBudget simulation: max_retries=2, consume all, 3rd raises.
    retry_budget = TaskRetryBudget(task_id="test-task", max_retries=2)
    assert retry_budget.can_retry() is True, "should be able to retry initially"

    w1 = retry_budget.consume()
    assert retry_budget.retries_used() == 1, "one retry consumed"
    assert w1 == 1.0, f"first backoff should be 1.0s, got {w1}"

    w2 = retry_budget.consume()
    assert retry_budget.retries_used() == 2, "two retries consumed"
    assert w2 == 2.0, f"second backoff should be 2.0s, got {w2}"

    assert retry_budget.can_retry() is False, "no retries left after 2 consumes"

    try:
        retry_budget.consume()
        raise AssertionError("third consume should have raised BudgetExceeded")
    except BudgetExceeded as exc:
        assert exc.budget_type == "retry", "budget type should be 'retry'"
        assert "No retries remaining for task test-task" in str(exc)

    print("All assertions passed.")


# BONUS — Race condition analysis
#
# Q: CART runs tasks concurrently (up to 4 workers). The current_count passed
#    to check_task_count comes from a SELECT COUNT(*) on SQLite. Describe a
#    race condition that could allow more than max_tasks tasks to be created,
#    and how you would fix it using only SQLite primitives (no Python
#    threading.Lock or multiprocessing).
#
# RACE CONDITION:
#   With 4 concurrent workers, each independently runs:
#       SELECT COUNT(*) FROM task WHERE run_id = ?;
#   Suppose the count returns 199 and max_tasks is 200. All four workers see
#   199 < 200, so all four pass check_task_count() and each issues an INSERT
#   for a new task. The final count becomes up to 203 — exceeding max_tasks.
#   This is a classic check-then-insert (TOCTOU: time-of-check to time-of-use)
#   race: the READ (COUNT) is not serialized with the subsequent WRITE (INSERT).
#
# FIX USING SQLITE PRIMITIVES:
#   Replace the COUNT-based gate with an atomic "claim a slot" operation using
#   a dedicated counter table, e.g. run_task_counts(run_id PRIMARY KEY, n INTEGER).
#   In a single transaction per candidate task, do:
#
#       BEGIN IMMEDIATE;
#       UPDATE run_task_counts
#           SET n = n + 1
#         WHERE run_id = ? AND n < 200;
#       -- cursor.rowcount / changes() == 1 means we successfully claimed a slot
#       IF changed:
#           INSERT INTO task (..., run_id, ...) VALUES (...);
#       COMMIT;
#
#   The UPDATE ... WHERE n < max_tasks is atomic under SQLite's write lock, so
#   exactly one worker increments the counter up to the ceiling. No Python locks
#   are needed: concurrency safety comes from SQLite's transactional serialization
#   of writes and the conditional UPDATE acting as a row-level mutex on the count.
