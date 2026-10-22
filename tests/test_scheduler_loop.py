"""Global: automatic cadence uses the same scan ownership as manual requests. Local: exercise real scheduler turns without elapsed-time sleeps.

Sources: https://docs.python.org/3/library/asyncio-sync.html#event and
https://docs.pytest.org/en/stable/how-to/monkeypatch.html .
"""

import asyncio  # Bound test completion and await real service-owned jobs.
from datetime import datetime, timedelta, timezone  # Represent an overdue workspace without changing the system clock.

import pytest  # Test both the scheduled winner and a manual winner at the lock boundary.

from security_monitoring_agent.config import save_settings  # Exercise real settings reloads in each timer turn.
from security_monitoring_agent.models import Settings  # Keep the production configuration contract.
from security_monitoring_agent.service import Monitor  # Run the real timer, persistent records, and cross-process lock.


@pytest.mark.asyncio
@pytest.mark.parametrize("manual_wins", [False, True], ids=["coalesce-overdue", "manual-wins-collision"])
async def test_scheduler_coalesces_overdue_intervals_and_manual_collision(tmp_path, monkeypatch, manual_wins):
    """Global: missed hours cause one investigation, never a backlog. Local: step two actual timer turns with bounded event checkpoints."""
    settings = Settings(auto_scan=True, interval_minutes=60)  # Several missed intervals should produce one current attempt.
    save_settings(tmp_path, settings)  # The scheduler must read the same persisted configuration as the UI.
    timer, manual = Monitor(tmp_path), Monitor(tmp_path)  # Independent service instances share SQLite and the native lock.
    old = timer.create_run(settings, "scan")  # Seed one historical attempt with the normal persisted shape.
    timer.store.update("run", old["id"], status="completed", started_at=(datetime.now(timezone.utc) - timedelta(hours=8)).isoformat())  # Simulate waking after eight hourly intervals.
    investigations, attempts, checkpoints = [], [], []  # Observe outcomes rather than assuming the timer's branch executed.

    async def investigate(*args):
        """Global: no live model calls in cadence tests. Local: finish the real service lifecycle with a deterministic result."""
        investigations.append(args[3])  # The production pipeline receives its persisted run ID as the fourth argument.
        return {"status": "completed", "summary": "Synthetic cadence check"}  # Normal completion releases the native scan lock.

    original_start = timer.start_scan  # Preserve the production acquisition and record-creation path.

    def start_after_manual_race(current):
        """Global: a manual request can win after the timer's active check. Local: force that ordering at the real lock boundary."""
        attempts.append(True)  # A second timer launch would expose an unwanted backlog.
        if manual_wins:  # The race is intentional and reproducible, rather than dependent on thread timing.
            manual.start_scan(current)  # This service owns the shared lock before the timer tries to acquire it.
        return original_start(current)  # The losing timer raises BusyError, which the real scheduler must handle.

    async def next_turn():
        """Global: keep timer verification fast and deterministic. Local: replace only the periodic wait, then run another real iteration."""
        checkpoints.append(True)  # Each call follows a completed scheduler decision.
        await asyncio.gather(*tuple(timer.tasks.values()), *tuple(manual.tasks.values()))  # Let the accepted investigation finish before testing the next due time.
        if len(checkpoints) == 2:  # Two turns distinguish coalescing from replaying every missed interval.
            timer.stopping.set()  # Exit through the production stop condition.
            return  # The enclosing wait_for completes normally.
        raise TimeoutError  # Mimic a timer tick immediately, with no wall-clock sleep.

    monkeypatch.setattr("security_monitoring_agent.service.run_scan", investigate)  # Stub research only; ownership and persistence remain real.
    monkeypatch.setattr(timer, "start_scan", start_after_manual_race)  # Observe dispatch and optionally inject the competing manual request.
    monkeypatch.setattr(timer.stopping, "wait", next_turn)  # Advance the normal five-second wait without delaying the suite.
    try:  # Always release service-owned jobs if an assertion or timeout fails.
        await asyncio.wait_for(timer.scheduler(), timeout=3)  # A broken scheduler cannot hang this regression.
        records = [run for run in timer.store.all("run") if run["id"] != old["id"]]  # Exclude the seeded historical attempt.
        assert len(records) == len(investigations) == len(attempts) == 1  # Eight missed intervals and competing triggers still create exactly one investigation.
        assert records[0]["status"] == "completed" and records[0]["id"] == investigations[0]  # The one accepted investigation completed normally.
        assert len(checkpoints) == 2 and timer.active() is None  # A second timer turn observes the new cadence without a queued duplicate.
        assert datetime.fromisoformat(timer.next_scan()) > datetime.now(timezone.utc)  # The next run is scheduled from the current attempt, not the stale backlog.
    finally:  # Failed tests must not leave a held workspace lock or background task.
        timer.stopping.set()  # Prevent further scheduler work.
        await asyncio.wait_for(asyncio.gather(timer.close(), manual.close()), timeout=3)  # Reuse production cancellation and cleanup for both owners.
