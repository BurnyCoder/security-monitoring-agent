"""Global: actual local HTTP workflow tests. Local: synthetic state and no live paid inference."""

import asyncio
from datetime import datetime, timedelta, timezone  # Use relative dates so news-window assertions remain reproducible.

import pytest
from fastapi.testclient import TestClient

from security_monitoring_agent.app import create_app
from security_monitoring_agent.config import load_settings, save_settings
from security_monitoring_agent.service import BusyError, Monitor
from security_monitoring_agent.models import Advisory  # Reuse the actual persisted intelligence contract.


@pytest.fixture
def client(tmp_path):
    """Global: isolated server lifecycle. Local: disable automatic paid scans in tests."""
    settings = load_settings(tmp_path)
    settings.auto_scan = False
    save_settings(tmp_path, settings)
    with TestClient(create_app(tmp_path)) as session:
        yield session


def test_real_empty_dashboard_and_settings(client):
    """Global: usable pre-scan UI. Local: no fake clean result is generated."""
    assert client.get("/").status_code == 200
    assert client.get("/api/inventory").json() is None
    status = client.get("/api/status").json()
    assert status["last_successful"] is None
    assert status["next_scan_at"] is None
    settings = client.get("/api/settings").json()
    settings["news_days"] = 1
    assert client.patch("/api/settings", json=settings).status_code == 200
    assert client.get("/api/settings").json()["news_days"] == 1


def test_cross_origin_mutation_rejected(client):
    """Global: foreign web pages cannot start local agents. Local: same-origin API remains usable."""
    response = client.post("/api/chats", json={"provider": "codex", "model": "gpt-6-luna"}, headers={"origin": "https://example.org"})
    assert response.status_code == 403
    assert client.post("/api/chats", json={"provider": "codex", "model": "gpt-6-luna"}).status_code == 201


def test_public_api_has_named_response_contracts(client):
    """Global: clients can discover typed boundaries. Local: OpenAPI exposes persisted domain models."""
    schema = client.get("/openapi.json").json()  # Inspect the same contract available to local clients.
    for name in ("RunRecord", "StoredFinding", "ConversationDetail", "DashboardStatus"):
        assert name in schema["components"]["schemas"]  # Reject anonymous or missing public response shapes.


def test_news_window_override_changes_view_without_mutating_settings(client):
    """Global: quick news windows apply immediately. Local: persisted scheduler preferences stay explicit."""
    published = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()  # Older than 24 hours but within seven days.
    client.app.state.monitor.store.save_advisory(Advisory(id="test-news", title="Test", summary="Fixture", published_at=published))  # Use a source-date fixture without live inference.
    assert client.get("/api/advisories?news_days=1").json() == []  # The quick window must affect the actual response.
    assert len(client.get("/api/advisories?news_days=7").json()) == 1  # The stored record remains available in the broader window.
    assert client.get("/api/advisories?news_days=5").status_code == 422  # Reject unsupported windows consistently.
    assert client.get("/api/settings").json()["news_days"] == 7  # Viewing recent news never writes configuration.


def test_sse_replays_large_events_from_cursor(client):
    """Global: reconnect must not lose output. Local: ended runs still replay complete unseen events."""
    store = client.app.state.monitor.store
    store.put("run", "synthetic", {"id": "synthetic", "status": "completed", "kind": "scan"})
    first = store.event("synthetic", "progress", "old")
    store.event("synthetic", "stdout", "x" * 100000)
    response = client.get("/api/runs/synthetic/events", headers={"last-event-id": str(first)})
    assert response.status_code == 200
    assert "x" * 100000 in response.text
    assert '"text":"old"' not in response.text


@pytest.mark.asyncio
async def test_manual_scheduler_collision_and_cancel(tmp_path, monkeypatch):
    """Global: one scan across processes. Local: a second service competes for the same OS lock."""
    async def slow_scan(*args):
        await asyncio.sleep(60)
    monkeypatch.setattr("security_monitoring_agent.service.run_scan", slow_scan)
    first, second = Monitor(tmp_path), Monitor(tmp_path)
    run = first.start_scan()
    await asyncio.sleep(0)
    with pytest.raises(BusyError):
        second.start_scan()
    task = first.tasks[run["id"]]
    first.cancel(run["id"])
    await task
    assert first.store.get("run", run["id"])["status"] == "cancelled"
    handle = second.lock("scan")
    handle.release()


def test_restart_recovers_only_unowned_jobs(tmp_path):
    """Global: restart does not kill a scheduled scanner. Local: respect a still-held lock."""
    first, second = Monitor(tmp_path), Monitor(tmp_path)
    first.store.put("run", "test", {"id": "test", "status": "running", "kind": "scan"})
    handle = first.lock("scan")
    second.recover()
    assert second.store.get("run", "test")["status"] == "running"
    handle.release()
    second.recover()
    assert second.store.get("run", "test")["status"] == "interrupted"
