"""Global: persistent correctness tests. Local: temporary databases contain synthetic data."""

import sqlite3  # Inject an atomic transaction failure without changing application code.

import pytest  # Parameterize source-evidence and identity-order regressions.

from security_monitoring_agent.models import Advisory, Asset, Finding, Inventory, Investigation, Source
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


def test_canonical_url_identity_merges_news_without_losing_installations(tmp_path):
    """Global: no-CVE news has a stable URL identity. Local: changed titles remain one advisory while installations stay separate."""
    store = Store(tmp_path / "test.sqlite3")  # Synthetic public-shaped evidence remains isolated.
    identifier = "https://vendor.example/security/advisories/fixture"  # This explicit canonical ID differs from an arbitrary supporting citation.
    assets = [Asset(id=name, kind="windows_app", name="Fixture", version="1", platform="Windows") for name in ("system-install", "user-install")]  # Separate observed installations share the same vulnerability.
    store.save_inventory("run", Inventory(assets=assets))  # Preserve both installation snapshots for persisted occurrences.
    for title, asset in zip(("Initial report", "Updated advisory title"), assets, strict=True):  # Repeated observations can change source text without changing identity.
        advisory = Advisory(id=identifier, title=title, summary="Fixture", sources=[Source(title="Vendor advisory", url=identifier)])  # No CVE or invented alias is needed for a URL-keyed record.
        finding = Finding(advisory_id=identifier, asset_id=asset.id, status="potentially_affected", rationale="Fixture")  # Each observation retains its own installation identity.
        store.save_investigation("run", Investigation(summary="Fixture", advisories=[advisory], findings=[finding], coverage_notes=[]))  # Use ordinary ingestion and canonical occurrence hashing.
    assert len(store.advisories()) == 1 and store.advisories()[0]["title"] == "Updated advisory title"  # Exact canonical URL identity deduplicates successive source observations.
    assert len(store.findings()) == 2 and all(row["advisory"]["id"] == identifier for row in store.findings())  # Neither installation is lost or orphaned by the merge.


def test_event_cursor_and_full_text(tmp_path):
    """Global: reconnectable complete logs. Local: large data round-trips without truncation."""
    store = Store(tmp_path / "test.sqlite3")
    first = store.event("run", "stdout", "x" * 100000)
    store.event("run", "stderr", "second")
    assert len(store.events("run")[0]["text"]) == 100000
    assert [row["text"] for row in store.events("run", after=first)] == ["second"]


@pytest.mark.parametrize("previous,incoming,expected", [
    ("known_exploited", "none_known", "known_exploited"),
    ("public_poc", "none_known", "public_poc"),
    ("unverified_report", "none_known", "unverified_report"),
    ("public_poc", "unverified_report", "public_poc"),
    ("unverified_report", "public_poc", "public_poc"),
    ("public_poc", "known_exploited", "known_exploited"),
])
def test_enrichment_preserves_strongest_exploitation(tmp_path, previous, incoming, expected):
    """Global: generic enrichment cannot retract evidence. Local: exercise every adjacent evidence strength."""
    store = Store(tmp_path / "test.sqlite3")  # Each transition starts from an independent synthetic history.
    record = Advisory(id="CVE-2026-1234", title="Synthetic", summary="Fixture", exploitation=previous)  # A cited source may later omit exploitation detail.
    store.save_advisory(record)  # Establish the earlier classification.
    store.save_advisory(record.model_copy(update={"exploitation": incoming}))  # Feed a later source's classification.
    assert store.advisories()[0]["exploitation"] == expected  # Evidence only strengthens through ordinary enrichment.


def test_late_alias_link_consolidates_records_and_occurrences(tmp_path):
    """Global: aliases mean the same vulnerability. Local: retain the newest observation per installation.

    Source: https://ossf.github.io/osv-schema/#aliases-field distinguishes identity from related notices.
    """
    store = Store(tmp_path / "test.sqlite3")  # Keep test evidence entirely local and synthetic.
    assets = [Asset(id=name, kind="windows_app", name="Fixture", version="1", platform="Windows") for name in ("shared", "first-only", "second-only")]  # Repeated installs are not duplicate findings.
    first = Advisory(id="GHSA-example", aliases=["OSV-example"], title="First", summary="Fixture", exploitation="public_poc", published_at="2026-01-01", sources=[Source(title="First", url="https://example.org/first")])  # The first source lacks the CVE link.
    second = Advisory(id="CVE-2026-1234", title="Second", summary="Fixture", severity="high", sources=[Source(title="Second", url="https://example.org/second")])  # A separate CVE record arrives before the equivalence is known.
    for run_id, advisory, selected, status in [("first", first, assets[:2], "affected"), ("second", second, [assets[0], assets[2]], "not_affected")]:  # Later explicit assessments must win collision resolution.
        store.save_inventory(run_id, Inventory(assets=assets))  # Preserve original observed assets for each assessment.
        store.save_investigation(run_id, Investigation(summary="Fixture", advisories=[advisory], findings=[Finding(advisory_id=advisory.id, asset_id=asset.id, status=status, rationale=run_id) for asset in selected], coverage_notes=[]))  # Exercise the public occurrence-writing path.
    canonical = store.save_advisory(Advisory(id=first.id, aliases=[second.id], title="Linked", summary="Fixture"))  # New evidence finally joins the two existing records.
    assert canonical == second.id  # Prefer the sole CVE once the equivalence is established.
    assert len(store.advisories()) == 1  # Delete superseded advisory objects, not only their lookup aliases.
    merged = store.advisories()[0]  # Inspect metadata combined from both old source records.
    assert merged["exploitation"] == "public_poc" and merged["severity"] == "high"  # Generic enrichment retains stronger established facts.
    assert merged["published_at"] == "2026-01-01"  # Empty enrichment cannot erase the original disclosure date.
    assert {item["url"] for item in merged["sources"]} == {"https://example.org/first", "https://example.org/second"}  # Both supporting sources survive.
    assert all(store.canonical(identifier) == canonical for identifier in (first.id, second.id, "OSV-example"))  # Historical aliases all point directly to the surviving identity.
    findings = {row["asset_id"]: row for row in store.findings()}  # Join against the consolidated advisory like the dashboard.
    assert len(findings) == 3 and all(row["advisory"]["id"] == canonical for row in findings.values())  # Preserve separate installations without orphan joins.
    assert findings["shared"]["status"] == "not_affected" and findings["shared"]["run_id"] == "second"  # Do not revive an obsolete affected assessment.
    assert findings["first-only"]["stale"] and not findings["shared"]["stale"]  # Rekeying is not a new scan.
    store.save_investigation("second", Investigation(summary="Fixture", advisories=[], findings=[Finding(advisory_id="OSV-example", asset_id="shared", status="unknown", rationale="Rechecked")], coverage_notes=[]))  # Saving through an old alias must update the same occurrence key.
    assert len(store.findings()) == 3  # A stale hash key would incorrectly create a fourth finding.


@pytest.mark.parametrize("notice_first", [False, True])
def test_multi_cve_notice_never_merges_distinct_vulnerabilities(tmp_path, notice_first):
    """Global: a multi-issue notice is not a CVE alias. Local: ingestion order cannot collapse distinct CVEs."""
    store = Store(tmp_path / "test.sqlite3")  # Use isolated state for both real ingestion orders.
    cves = [Advisory(id=identifier, title=identifier, summary="Fixture") for identifier in ("CVE-2026-1234", "CVE-2026-5678")]  # Two independent vulnerabilities.
    notice = Advisory(id="USN-example", aliases=[item.id for item in cves], title="Multi-issue notice", summary="Fixture")  # Source-linked notice covers both vulnerabilities.
    for advisory in ([notice, *cves] if notice_first else [*cves, notice]):  # Simulate a source notice before or after KEV records.
        store.save_advisory(advisory)  # Source aliases are preserved for display but ambiguous ones must not become equality mappings.
    store.save_advisory(cves[0].model_copy(update={"aliases": [notice.id]}))  # Reverse linking cannot silently undo the multi-CVE guard.
    assert {item["id"] for item in store.advisories()} == {notice.id, *(item.id for item in cves)}  # Keep all three independent records.
    assert all(store.canonical(item.id) == item.id for item in [notice, *cves])  # Neither CVE resolves through the shared notice.
    assert set(store.get("advisory", notice.id)["aliases"]) == {item.id for item in cves}  # Preserve source metadata without treating it as equivalence.


def test_transitive_alias_conflict_cannot_merge_two_cves(tmp_path):
    """Global: prevent indirect multi-CVE collapse. Local: a shared non-CVE alias cannot bridge distinct CVEs."""
    store = Store(tmp_path / "test.sqlite3")  # This fixture has conflicting source identity evidence.
    store.save_advisory(Advisory(id="CVE-2026-1234", aliases=["GHSA-example"], title="First", summary="Fixture"))  # Establish the original unambiguous mapping.
    store.save_advisory(Advisory(id="CVE-2026-5678", aliases=["GHSA-example"], title="Second", summary="Fixture"))  # A conflicting later source is not enough to equate the CVEs.
    assert len(store.advisories()) == 2  # Retain separate vulnerability objects.
    assert store.canonical("GHSA-example") == "CVE-2026-1234"  # Preserve the earlier mapping instead of stealing the shared alias.
    assert store.canonical("CVE-2026-5678") == "CVE-2026-5678"  # The conflicting CVE remains independently addressable.


def test_identity_consolidation_rolls_back_as_one_transaction(tmp_path):
    """Global: interrupted merges cannot leave orphan findings. Local: force the final alias write to fail."""
    store = Store(tmp_path / "test.sqlite3")  # SQLite rollback is the production mechanism under test.
    first = Advisory(id="GHSA-example", title="First", summary="Fixture")  # Initially unrelated source identities.
    second = Advisory(id="CVE-2026-1234", title="Second", summary="Fixture")  # The later link would consolidate them.
    for advisory in (first, second):  # Include findings so rollback covers their rekeying too.
        store.save_investigation("run", Investigation(summary="Fixture", advisories=[advisory], findings=[Finding(advisory_id=advisory.id, asset_id="asset", status="unknown", rationale="Fixture")], coverage_notes=[]))  # Assets are irrelevant to this atomicity test.
    before = (store.advisories(), store.all("finding"))  # Record exact documents, including timestamps and original identity keys.
    with store.connect() as connection:  # Inject a synthetic constraint failure after the merge's other writes.
        connection.execute("CREATE TRIGGER reject_alias BEFORE INSERT ON aliases WHEN NEW.alias='FAIL-ALIAS' BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")  # SQLite abort must roll back the surrounding transaction.
    with pytest.raises(sqlite3.IntegrityError, match="fixture failure"):  # Failed persistence remains visible to the caller.
        store.save_advisory(first.model_copy(update={"aliases": [second.id, "FAIL-ALIAS"]}))  # This would otherwise merge records and findings.
    assert (store.advisories(), store.all("finding")) == before  # No partial metadata or occurrence changes survive.
    assert store.canonical(first.id) == first.id and store.canonical(second.id) == second.id  # Alias mappings roll back with their target records.
