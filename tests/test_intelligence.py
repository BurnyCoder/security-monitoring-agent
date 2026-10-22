"""Global: intelligence provenance regressions. Local: test KEV baseline semantics offline."""

from security_monitoring_agent.intelligence.kev import parse_kev  # Pure feed normalization.


def test_kev_keeps_old_entries_and_addition_is_not_publication():
    """Global: existing exposures remain monitored. Local: don't apply the news window here."""
    records = parse_kev({"catalogVersion": "2026.10.22", "vulnerabilities": [{"cveID": "CVE-2014-0001", "vulnerabilityName": "Old issue", "vendorProject": "Vendor", "product": "Product", "dateAdded": "2026-10-22", "shortDescription": "Description", "requiredAction": "Apply vendor fix", "notes": "https://example.com/advisory"}]}, "https://example.com/feed")  # Old CVE newly added to KEV.
    assert len(records) == 1  # Full baseline, not recent CVE years only.
    assert records[0].published_at == ""  # Addition date must not become disclosure date.
    assert records[0].kev_added_at == "2026-10-22"  # Preserve the actual field meaning.
    assert records[0].exploitation == "known_exploited"  # KEV is explicit exploitation evidence.
    assert any(source.url == "https://example.com/feed" for source in records[0].sources)  # Mirror provenance remains auditable.


def test_kev_rejects_unexpected_shape():
    """Global: a failed feed is not an empty feed. Local: validate its required array."""
    import pytest  # The assertion applies only to this malformed fixture.
    with pytest.raises(ValueError):  # A schema failure must propagate to coverage.
        parse_kev({"error": "unavailable"}, "https://example.com/feed")  # No fabricated success.
