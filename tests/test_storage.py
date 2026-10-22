"""Global: persistent correctness tests. Local: temporary databases contain synthetic data."""

from security_monitoring_agent.models import Advisory, Asset, Finding, Inventory, Investigation
from security_monitoring_agent.storage import Store


def test_alias_dedup_keeps_occurrences(tmp_path):
    """Global: one advisory can affect multiple installations. Local: deduplicate by alias."""
    store = Store(tmp_path / "test.sqlite3")
    assets = [Asset(id=x, kind="project_dependency", name="example", version="1", platform=x) for x in ["one", "two"]]
    store.save_inventory("run", Inventory(assets=assets))
    first = Advisory(id="GHSA-example", aliases=["CVE-2026-1234"], title="Example", summary="synthetic")
    second = Advisory(id="CVE-2026-1234", title="Corrected", summary="updated")
    store.save_investigation("run", Investigation(summary="done", advisories=[first], findings=[Finding(advisory_id=first.id, asset_id=x.id, status="potentially_affected", rationale="test") for x in assets], coverage_notes=[]))
    store.save_investigation("run", Investigation(summary="done", advisories=[second], findings=[], coverage_notes=[]))
    assert len(store.advisories()) == 1
    assert len(store.findings()) == 2
    assert store.advisories()[0]["title"] == "Corrected"


def test_event_cursor_and_full_text(tmp_path):
    """Global: reconnectable complete logs. Local: large data round-trips without truncation."""
    store = Store(tmp_path / "test.sqlite3")
    first = store.event("run", "stdout", "x" * 100000)
    store.event("run", "stderr", "second")
    assert len(store.events("run")[0]["text"]) == 100000
    assert [row["text"] for row in store.events("run", after=first)] == ["second"]
