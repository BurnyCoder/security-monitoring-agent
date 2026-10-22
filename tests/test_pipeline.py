"""Global: scan workflow regressions. Local: fake collection and inference; real SQLite uses synthetic records.

Source: https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread .
"""

import asyncio  # Exercise the same event loop used by the dashboard service.
import threading  # A controlled blocking writer reveals event-loop stalls without a timing benchmark.
from types import SimpleNamespace  # Supply only the provider response fields consumed by the pipeline.

import pytest  # Async tests and monkeypatching keep fixtures independent of installed agents.

from security_monitoring_agent import pipeline  # Exercise the public scan wrapper with fake external phases.
from security_monitoring_agent.models import Advisory, Asset, Coverage, Finding, Inventory, Investigation, Settings, Source
from security_monitoring_agent.storage import Store  # Real persistence exposes transaction and thread behavior.


def prepare_pipeline(monkeypatch, tmp_path, result=None, coverage_status="ok", web_searches=1):
    """Global: test scan orchestration without web/model calls. Local: preserve actual store and evidence validation."""
    asset = Asset(id="fixture-app", kind="windows_app", name="Fixture", version="1", platform="Windows")  # Never inventory the test machine.
    inventory = Inventory(assets=[asset], coverage=[Coverage(component="fixture", status=coverage_status, detail="Synthetic collection")])  # Coverage is an explicit observable input.
    result = result or Investigation(summary="Synthetic investigation", advisories=[], findings=[], coverage_notes=[])  # A valid empty assessment is distinct from a failed scan.
    async def collect_inventory(*args):
        """Global: controlled collection input. Local: return a new snapshot per run."""
        return inventory.model_copy(deep=True)  # Pipeline enrichment must not mutate the fixture.
    async def collect_intelligence(*args):
        """Global: exclude external feeds. Local: an empty deterministic batch still exercises persistence."""
        return [], [], []  # No test sends synthetic package metadata to an API.
    async def run_agent(*args, **kwargs):
        """Global: isolate model transport. Local: supply a terminal structured result and observed search count."""
        return SimpleNamespace(structured=result.model_dump(mode="json"), text="", web_searches=web_searches, session_id="fixture-session", model="fixture-model")  # Match the real response contract.
    monkeypatch.setattr(pipeline, "collect_inventory", collect_inventory)  # Only external phases are replaced.
    monkeypatch.setattr(pipeline, "collect_intelligence", collect_intelligence)  # Keep database writes real.
    monkeypatch.setattr(pipeline, "run_agent", run_agent)  # No model quota or credentials are needed.
    return Store(tmp_path / "monitor.sqlite3")  # Each test has independent durable state.


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_method", ["save_inventory", "save_investigation"])
async def test_bulk_persistence_keeps_event_loop_responsive(monkeypatch, tmp_path, blocked_method):
    """Global: dashboard work proceeds during SQLite persistence. Local: the loop releases a deliberately blocked writer."""
    store = prepare_pipeline(monkeypatch, tmp_path)  # Exercise both inventory and intelligence persistence paths.
    started, release = threading.Event(), threading.Event()  # Thread-safe gates avoid polling shared coroutine state.
    loop_thread, observed_threads, released = threading.get_ident(), [], []  # Verify offloading for every bulk method call.
    original = getattr(store, blocked_method)  # Retain production persistence after the controlled delay.
    def blocked(*args):
        """Global: model slow disk I/O. Local: wait once for another event-loop task to release the writer."""
        observed_threads.append(threading.get_ident())  # A same-thread call would freeze request handling.
        if not started.is_set():  # One blocked write is sufficient to reveal starvation.
            started.set()  # Signal that the scan has reached persistence.
            released.append(release.wait(timeout=1))  # Bound failure time even if the event loop regresses to blocking.
        return original(*args)  # Complete the actual SQLite operation.
    monkeypatch.setattr(store, blocked_method, blocked)  # Delay the public method, not asyncio internals.
    task = asyncio.create_task(pipeline.run_scan(Settings(), tmp_path, store, "run", lambda *_: None, asyncio.Event()))  # Run the full scan workflow.
    try:  # Always unblock the worker if an assertion fails.
        while not started.is_set() and not task.done():  # A responsive loop can observe the in-progress write.
            await asyncio.sleep(0)  # Simulate another request receiving execution time.
        release.set()  # Only the event loop can satisfy the worker's gate.
        result = await task  # Require the entire scan to finish correctly.
    finally:  # Never leave a background thread waiting after a failed test.
        release.set()  # Idempotent thread signal.
    assert released == [True]  # A synchronous implementation times out before this task can run.
    assert len(observed_threads) == 2 and all(identifier != loop_thread for identifier in observed_threads)  # Both snapshots or both investigation writes run off-loop.
    assert result["status"] == "completed"  # Persistence threading does not alter successful workflow semantics.


@pytest.mark.asyncio
async def test_cancellation_waits_for_in_progress_persistence(monkeypatch, tmp_path):
    """Global: cancelled scans retain ownership until writes stop. Local: cancellation cannot orphan a worker thread."""
    store = prepare_pipeline(monkeypatch, tmp_path)  # Use the normal scan boundary and a controlled initial write.
    started, release, finished = threading.Event(), threading.Event(), threading.Event()  # Observe the writer's full lifetime.
    original = store.save_inventory  # The blocked operation remains a real transaction.
    def blocked(*args):
        """Global: reproduce cancellation during disk work. Local: mark completion only after the writer exits."""
        started.set()  # Let the event loop cancel at the precise persistence phase.
        release.wait(timeout=1)  # Bound a failing synchronous implementation.
        original(*args)  # The transaction must finish before scan ownership is released.
        finished.set()  # Confirm there is no writer left after cancellation completes.
    monkeypatch.setattr(store, "save_inventory", blocked)  # Isolate the cancellation boundary.
    task = asyncio.create_task(pipeline.run_scan(Settings(), tmp_path, store, "run", lambda *_: None, asyncio.Event()))  # Cancellation targets the owned scan task.
    try:  # Release the worker regardless of intermediate assertions.
        while not started.is_set() and not task.done():  # Wait without blocking the dashboard loop.
            await asyncio.sleep(0)  # The writer is running in its dedicated executor thread.
        task.cancel()  # Mirror the service's single cancellation request.
        await asyncio.sleep(0)  # Give cancellation a chance to reach the persistence await.
        assert not task.done() and not finished.is_set()  # Do not release scan ownership before the outstanding write completes.
    finally:  # Prevent a leaked worker even if the ownership assertion fails.
        release.set()  # Allow the pending transaction to complete.
    with pytest.raises(asyncio.CancelledError):  # Cancellation remains the terminal scan result.
        await task  # Await worker cleanup before reporting cancellation.
    assert finished.is_set()  # No writes occur after the run has ended.


@pytest.mark.asyncio
async def test_rejected_output_is_exposed_as_partial(monkeypatch, tmp_path):
    """Global: rejected model claims remain auditable. Local: drop uncited/orphan records and explain each omission."""
    advisory = Advisory(id="CVE-2026-1234", title="Uncited", summary="Fixture")  # This news item lacks publishable evidence.
    finding = Finding(advisory_id=advisory.id, asset_id="fixture-app", status="unknown", rationale="Fixture")  # Filtering its advisory creates an orphan unless rejected too.
    result = Investigation(summary="Synthetic investigation", advisories=[advisory], findings=[finding], coverage_notes=["Fixture caveat is preserved verbatim."])  # Model limitations must reach the user unchanged.
    store = prepare_pipeline(monkeypatch, tmp_path, result)  # External phases remain deterministic.
    events = []  # Capture user-visible structured log events.
    output = await pipeline.run_scan(Settings(), tmp_path, store, "run", lambda kind, text: events.append((kind, text)), asyncio.Event())  # Exercise filtering and publication together.
    assert output["status"] == "partial"  # Rejected claims are a concrete validation gap.
    assert "Rejected uncited advisory: CVE-2026-1234" in output["summary"]  # Do not silently discard model news.
    assert "Rejected finding with unknown advisory: CVE-2026-1234" in output["summary"]  # Applicability is not orphaned from its supporting intelligence.
    assert "Fixture caveat is preserved verbatim." in output["summary"]  # Preserve the original model caveat.
    assert any(kind == "coverage" and "Rejected uncited advisory" in text for kind, text in events)  # Live logs disclose the rejection before the final run view.
    assert not store.advisories() and not store.findings()  # Invalid evidence is neither published nor silently repaired.


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [("affected", "potentially_affected"), ("not_affected", "unknown")])
async def test_downgraded_certainty_is_partial(monkeypatch, tmp_path, status, expected):
    """Global: invalid definitive assessments are visible gaps. Local: preserve qualified findings and explain their downgrade."""
    source = Source(title="Fixture", url="https://example.org/advisory")  # The advisory exists, but finding applicability evidence is absent.
    advisory = Advisory(id="CVE-2026-1234", title="Fixture", summary="Fixture", sources=[source])  # Permit publication of the source intelligence.
    finding = Finding(advisory_id=advisory.id, asset_id="fixture-app", status=status, rationale="Unsupported certainty")  # Existing validation must weaken this assessment.
    store = prepare_pipeline(monkeypatch, tmp_path, Investigation(summary="Fixture", advisories=[advisory], findings=[finding], coverage_notes=[]))  # Exercise the actual evidence validator.
    output = await pipeline.run_scan(Settings(), tmp_path, store, "run", lambda *_: None, asyncio.Event())  # Persist only qualified evidence.
    assert output["status"] == "partial" and "Downgraded finding" in output["summary"]  # Run status exposes the concrete validation failure.
    assert store.findings()[0]["status"] == expected  # A rejected not_affected conclusion cannot become a false clean result.


@pytest.mark.asyncio
@pytest.mark.parametrize("coverage_status,web_searches,expected", [("ok", 1, "completed"), ("partial", 1, "partial"), ("ok", 0, "partial")])
async def test_workflow_status_uses_observed_gaps_not_every_note(monkeypatch, tmp_path, coverage_status, web_searches, expected):
    """Global: completed means workflow completion. Local: generic scope notes do not masquerade as collector failures."""
    note = "Recorded lockfile evidence does not establish runtime reachability."  # A normal scope boundary is not a failed collection step.
    result = Investigation(summary="Fixture", advisories=[], findings=[], coverage_notes=[note])  # Preserve the model's exact qualification.
    store = prepare_pipeline(monkeypatch, tmp_path, result, coverage_status, web_searches)  # Explicit observable inputs determine degraded status.
    output = await pipeline.run_scan(Settings(), tmp_path, store, "run", lambda *_: None, asyncio.Event())  # Run the shared pipeline rather than duplicating status logic.
    assert output["status"] == expected and note in output["summary"]  # No free-text guessing or blanket notes-imply-partial rule.
    assert bool(store.get("meta", "research_checkpoint")) == bool(web_searches)  # Only an observed web-search event advances the cursor.
