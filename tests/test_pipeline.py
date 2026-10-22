"""Global: scan workflow regressions. Local: fake collection and inference; real SQLite uses synthetic records.

Source: https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread .
"""

import asyncio  # Exercise the same event loop used by the dashboard service.
import threading  # A controlled blocking writer reveals event-loop stalls without a timing benchmark.
from types import SimpleNamespace  # Supply only the provider response fields consumed by the pipeline.

import httpx  # In-memory primary-source responses exercise WSL guard integration without external requests.
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
    assert bool(store.get("meta", "research_checkpoint")) == (expected == "completed")  # Partial research cannot move the successful-research cursor forward.


@pytest.mark.asyncio
@pytest.mark.parametrize("coverage_status,expected", [("partial", "partial"), ("ok", "completed")])
async def test_research_checkpoint_preserves_previous_until_completed(monkeypatch, tmp_path, coverage_status, expected):
    """Global: failed coverage must not skip incremental research. Local: preserve the last successful checkpoint until a complete researched scan."""
    store = prepare_pipeline(monkeypatch, tmp_path, coverage_status=coverage_status)  # Both runs emit an observed web-search event.
    previous = {"at": "2026-01-01T00:00:00+00:00"}  # A prior successful scan already established the cursor.
    store.put("meta", "research_checkpoint", previous)  # Exercise cursor preservation rather than only initial absence.
    output = await pipeline.run_scan(Settings(), tmp_path, store, "run", lambda *_: None, asyncio.Event())  # Execute the real publication and checkpoint branch.
    assert output["status"] == expected  # Collection quality remains an explicit workflow outcome.
    assert store.get("meta", "research_checkpoint") == (previous if expected == "partial" else {"at": store.inventory()["captured_at"]})  # Only the completed run records its new observation time.


@pytest.mark.parametrize("identifier,alias", [("GHSA-fixture", "CVE-2026-1234"), ("CVE-2026-1234", "GHSA-fixture")])
def test_finding_resolves_unambiguous_alias_from_current_response(tmp_path, identifier, alias):
    """Global: a fresh source alias must not discard a supported finding. Local: bind the alias to its publishable current advisory before storage."""
    store = Store(tmp_path / "monitor.sqlite3")  # No previous run has registered either identity.
    source = Source(title="Fixture", url="https://example.org/advisory")  # News and applicability carry explicit evidence.
    asset = Asset(id="fixture-app", kind="windows_app", name="Fixture", version="1", platform="Windows")  # Exact observed installation identity.
    result = Investigation(summary="Fixture", advisories=[Advisory(id=identifier, aliases=[alias], title="Fixture", summary="Fixture", sources=[source])], findings=[Finding(advisory_id=alias, asset_id=asset.id, status="affected", rationale="Fixture", evidence=["Observed version"], sources=[source])], coverage_notes=[])  # The finding uses the equivalent name introduced by this same response.
    checked, incomplete = pipeline._publishable_result(result, Inventory(assets=[asset]), store)  # Exercise the pre-persistence orphan gate.
    assert not incomplete and len(checked.findings) == 1  # Equivalent fresh identities must survive publication.
    assert checked.findings[0].advisory_id == "CVE-2026-1234"  # Preserve an available CVE identity for the downstream WSL primary checker.
    store.save_investigation("run", checked)  # Normal storage subsequently chooses the canonical CVE.
    assert store.findings()[0]["advisory"]["id"] == "CVE-2026-1234"  # The saved occurrence joins a real canonical advisory.


def test_multi_cve_current_notice_does_not_resolve_as_one_cve(tmp_path):
    """Global: shared notices are not vulnerability equivalences. Local: current-batch alias support retains the existing multi-CVE guard."""
    store = Store(tmp_path / "monitor.sqlite3")  # Neither CVE exists independently in stored intelligence.
    source = Source(title="Fixture", url="https://example.org/notice")  # A single notice covers multiple separate issues.
    asset = Asset(id="fixture-app", kind="windows_app", name="Fixture", version="1", platform="Windows")  # Valid asset prevents unrelated rejection.
    result = Investigation(summary="Fixture", advisories=[Advisory(id="USN-fixture", aliases=["CVE-2026-1234", "CVE-2026-5678"], title="Fixture", summary="Fixture", sources=[source])], findings=[Finding(advisory_id="CVE-2026-1234", asset_id=asset.id, status="unknown", rationale="Fixture")], coverage_notes=[])  # The shared notice cannot supply a distinct CVE record.
    checked, incomplete = pipeline._publishable_result(result, Inventory(assets=[asset]), store)  # Do not collapse the notice to whichever CVE appeared first.
    assert incomplete and not checked.findings  # Keep the unresolved reference visible rather than manufacturing a canonical record.


@pytest.mark.asyncio
@pytest.mark.parametrize("has_applicability_evidence", [False, True])
async def test_primary_wsl_guard_runs_after_structural_validation(monkeypatch, tmp_path, has_applicability_evidence):
    """Global: publish WSL conflicts as partial without laundering weak evidence. Local: only already-supported definitive claims trigger the primary check."""
    source = Source(title="Fixture", url="https://example.org/advisory")  # The advisory is independently publishable.
    advisory = Advisory(id="CVE-2026-57968", title="Fixture", summary="Fixture", sources=[source])  # Use a valid CVE for exact repository URL construction.
    finding = Finding(advisory_id=advisory.id, asset_id="fixture-app", status="affected", rationale="Fixture", evidence=["Observed applicability"] if has_applicability_evidence else [], sources=[source] if has_applicability_evidence else [])  # The weaker original must be downgraded before primary evidence is appended.
    store = prepare_pipeline(monkeypatch, tmp_path, Investigation(summary="Fixture", advisories=[advisory], findings=[finding], coverage_notes=[]))  # Keep the actual pipeline publication path.
    async def collect_wsl_inventory(*args):
        """Global: select the narrow platform scope. Local: replace the default Windows-app fixture only."""
        return Inventory(assets=[Asset(id="fixture-app", kind="wsl_platform", name="WSL", version="2.7.0.0", platform="Windows")])  # No real device inventory is used.
    monkeypatch.setattr(pipeline, "collect_inventory", collect_wsl_inventory)  # The primary guard must discover an observed WSL platform asset.
    requests = []  # Zero requests proves structural rejection happened before primary-source enrichment.
    def respond(request):
        """Global: supply an inverted primary range. Local: match the published CNA record shape with synthetic scope."""
        requests.append(str(request.url))  # Count actual primary-check transport calls.
        return httpx.Response(200, json={"cveMetadata": {"cveId": advisory.id, "state": "PUBLISHED"}, "containers": {"cna": {"providerMetadata": {"shortName": "microsoft"}, "affected": [{"vendor": "Microsoft", "product": "Windows Subsystem for Linux", "versions": [{"version": "5.0.0.0", "lessThan": "2.7.8", "versionType": "custom", "status": "affected"}]}]}}})  # No installed-version comparison is needed to expose the contradiction.
    real_check = pipeline.check_wsl_primary_ranges  # Preserve the production guard while replacing only its transport.
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:  # No external web request is made by this integration test.
        async def checked_primary(result, inventory, emit):
            """Global: exercise the real primary guard. Local: inject the in-memory HTTP client."""
            return await real_check(result, inventory, emit, client=client)  # Return the actual gap flag consumed by the pipeline.
        monkeypatch.setattr(pipeline, "check_wsl_primary_ranges", checked_primary)  # Only transport ownership is replaced.
        output = await pipeline.run_scan(Settings(), tmp_path, store, "run", lambda *_: None, asyncio.Event())  # Save the qualified result through real storage.
    assert output["status"] == "partial" and store.findings()[0]["status"] == "potentially_affected"  # Both structural and primary-source gaps prevent definitive publication.
    assert len(requests) == int(has_applicability_evidence)  # A primary record citation cannot rescue originally unsupported certainty.
    assert ("WSL primary check downgraded" in output["summary"]) == has_applicability_evidence  # The summary reports the actual reason for qualification.
