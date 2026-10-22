"""Global: intelligence provenance regressions. Local: test KEV baseline semantics offline."""

import httpx  # MockTransport exercises the HTTP boundary without external traffic.
import pytest  # Async source tests share the fixture framework used by the scanner adapter.

from security_monitoring_agent.intelligence.kev import KEV_URLS, fetch_kev, parse_kev  # Test official endpoint ordering as well as normalization.


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
    with pytest.raises(ValueError):  # A schema failure must propagate to coverage.
        parse_kev({"error": "unavailable"}, "https://example.com/feed")  # No fabricated success.


@pytest.mark.asyncio
@pytest.mark.parametrize("mirror_available", [True, False])
async def test_kev_http_fallback_preserves_provenance_and_failure(monkeypatch, mirror_available):
    """Global: source outages cannot become clean intelligence. Local: exercise primary failure and official-mirror success/failure.

    Source: https://www.python-httpx.org/advanced/transports/#mock-transports .
    """
    requests, events = [], []  # Capture actual HTTP endpoint order and complete source diagnostics.
    payload = {"catalogVersion": "fixture-catalog", "vulnerabilities": [{"cveID": "CVE-2026-1234", "vulnerabilityName": "Fixture", "dateAdded": "2026-10-22", "shortDescription": "Synthetic source evidence"}]}  # A valid mirror response contains a real-shaped catalog, not invented clean status.
    def respond(request):
        """Global: simulate independent official endpoints. Local: the primary always fails and the mirror behavior is parameterized."""
        requests.append(str(request.url))  # The implementation must try canonical CISA before its official mirror.
        if str(request.url) == KEV_URLS[1] and mirror_available:  # Only the configured mirror may recover the failed source.
            return httpx.Response(200, json=payload)  # Exercise response JSON parsing and advisory normalization.
        return httpx.Response(503, text="Fixture source unavailable")  # Both failure branches use a genuine HTTP error response.
    client_type = httpx.AsyncClient  # Preserve the real client while replacing only its transport construction.
    monkeypatch.setattr("security_monitoring_agent.intelligence.kev.httpx.AsyncClient", lambda **options: client_type(transport=httpx.MockTransport(respond), **options))  # Production timeout/headers/redirect arguments still reach HTTPX.
    advisories, coverage = await fetch_kev(lambda kind, text: events.append((kind, text)))  # Exercise the complete source phase without live network access.
    assert requests == list(KEV_URLS)  # No arbitrary fallback host or skipped canonical attempt.
    assert len(coverage) == 1 and "503" in coverage[0].detail and KEV_URLS[0] in coverage[0].detail  # Preserve the primary error in either final outcome.
    if mirror_available:  # A valid official fallback supplies evidence with explicit provenance.
        assert coverage[0].status == "ok" and coverage[0].asset_count == 1  # Count successful source records, not failed attempts.
        assert len(advisories) == 1 and advisories[0].sources[0].url == KEV_URLS[1]  # Never label mirror evidence as downloaded from the failed canonical endpoint.
        assert "Official mirror used" in coverage[0].detail and "fixture-catalog" in coverage[0].detail  # Retain fallback and catalog metadata for review.
        assert len([event for event in events if event[0] == "error"]) == 1  # The first failure remains visible even though fallback succeeds.
    else:  # Total source outage must remain explicitly incomplete.
        assert not advisories and coverage[0].status == "error" and coverage[0].asset_count == 0  # An empty payload is never presented as a clean successful source.
        assert KEV_URLS[1] in coverage[0].detail  # Preserve both attempted source failures.
        assert len([event for event in events if event[0] == "error"]) == 2  # Both unsuccessful HTTP responses are logged independently.
