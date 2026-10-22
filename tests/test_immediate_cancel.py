"""Global: lifecycle regression. Local: cancellation before the first task tick still releases ownership."""

import pytest

from security_monitoring_agent.service import Monitor


@pytest.mark.asyncio
async def test_cancel_before_first_tick_releases_lock(tmp_path):
    """Global: rapid double-clicks cannot wedge scanning. Local: enter cleanup before cancelling."""
    monitor = Monitor(tmp_path)
    run = monitor.start_scan()
    task = monitor.tasks[run["id"]]
    monitor.cancel(run["id"])
    await task
    assert monitor.store.get("run", run["id"])["status"] == "cancelled"
    handle = monitor.lock("scan")
    handle.release()
