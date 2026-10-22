"""Global: regression tests for WSL primary-source contradictions. Local: synthetic CVE records, no device or exploit activity.

Record shape: https://cveproject.github.io/cve-schema/schema/docs/ .
"""

import httpx  # MockTransport exercises real HTTP response and failure handling without external requests.
import pytest  # Parameterized fixtures distinguish inverted bounds from ordinary source ranges.

from security_monitoring_agent.intelligence.wsl_primary import check_wsl_primary_ranges, cve_record_url, numeric_range_conflicts
from security_monitoring_agent.models import Asset, Finding, Inventory, Investigation, Source


def primary_record(lower="5.0.0.0", upper="2.7.8", bound="lessThan"):
    """Global: match Microsoft CNA's published shape. Local: values are synthetic except the regression's problematic numeric bounds."""
    return {"cveMetadata": {"cveId": "CVE-2026-57968", "state": "PUBLISHED"}, "containers": {"cna": {"providerMetadata": {"shortName": "microsoft"}, "affected": [{"vendor": "Microsoft", "product": "Windows Subsystem for Linux (WSL2)", "versions": [{"version": lower, bound: upper, "versionType": "custom", "status": "affected"}]}]}}}  # Only CNA affected rows drive the checker.


def finding_input(status="affected", count=1):
    """Global: preserve model evidence through source checking. Local: repeated findings exercise the per-scan CVE cache."""
    assets = [Asset(id=f"wsl-{index}", kind="wsl_platform", name="Windows Subsystem for Linux", version="WSL version: 2.7.0.0", platform="Windows") for index in range(count)]  # The checker must not compare this installed version against vendor ranges.
    findings = [Finding(advisory_id="CVE-2026-57968", asset_id=asset.id, status=status, rationale="Model supplied applicability", evidence=["Original observed fact"], sources=[Source(title="Original", url="https://example.org/advisory")]) for asset in assets]  # Existing evidence remains visible after a downgrade.
    return Investigation(summary="Fixture", advisories=[], findings=findings, coverage_notes=[]), Inventory(assets=assets)  # No persistent database is involved.


def test_cve_path_uses_validated_official_repository_layout():
    """Global: source URL is fixed and reviewable. Local: untrusted IDs cannot introduce arbitrary hosts or paths."""
    assert cve_record_url("CVE-2026-57968") == "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/57xxx/CVE-2026-57968.json"  # Five-digit sequences use the documented thousand-record bucket.
    assert "/2026/1xxx/" in cve_record_url("CVE-2026-1234")  # Four-digit CVE numbers retain their own bucket.
    assert cve_record_url("CVE-2026-57968/../../payload") is None  # Reject path components before any request.


@pytest.mark.parametrize("lower,upper,bound", [("5.0.0.0", "2.7.8", "lessThan"), ("5.0.0.0", "3.0.1", "lessThan"), ("2.10", "2.9", "lessThanOrEqual"), ("2.7", "2.7.0", "lessThan")])
def test_inverted_or_empty_numeric_ranges_are_conflicts(lower, upper, bound):
    """Global: detect a structural contradiction only. Local: numeric tuple comparison pads omitted trailing zeros."""
    conflicts = numeric_range_conflicts(primary_record(lower, upper, bound), "CVE-2026-57968")  # No installed package version enters this calculation.
    assert len(conflicts) == 1 and lower in conflicts[0] and upper in conflicts[0]  # Report exact source bounds for review.


@pytest.mark.parametrize("lower,upper,bound", [("0", "3.0.1", "lessThan"), ("2.9", "2.10", "lessThan"), ("2.7", "2.7.0", "lessThanOrEqual"), ("5.0-preview", "2.7.8", "lessThan"), ("*", "2.7.8", "lessThan")])
def test_ordinary_and_non_numeric_ranges_are_not_reinterpreted(lower, upper, bound):
    """Global: avoid inventing generic version semantics. Local: only unmistakable all-numeric contradictions are flagged."""
    assert numeric_range_conflicts(primary_record(lower, upper, bound), "CVE-2026-57968") == []  # No conflict does not prove installed-version applicability.


def test_only_matching_microsoft_cna_wsl_rows_are_inspected():
    """Global: vendor/product context controls the check. Local: unrelated CNA products and ADP data cannot trigger a downgrade."""
    record = primary_record("0", "3.0.1")  # Valid WSL bounds establish the applicable primary-source scope.
    record["containers"]["cna"]["affected"].append({"vendor": "Microsoft", "product": "Unrelated Product", "versions": [{"version": "9.0", "lessThan": "1.0", "status": "affected"}]})  # Other product ranges are deliberately inverted.
    record["containers"]["adp"] = [{"affected": primary_record()["containers"]["cna"]["affected"]}]  # Secondary enrichment cannot override the CNA scope.
    assert numeric_range_conflicts(record, "CVE-2026-57968") == []  # Ignore both unrelated products and secondary containers.
    with pytest.raises(ValueError, match="CVE identity"):  # Wrong response content cannot become primary verification.
        numeric_range_conflicts(record, "CVE-2026-57973")  # Exact request/record identity must match.


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["affected", "not_affected"])
async def test_conflict_downgrades_and_preserves_primary_evidence(status):
    """Global: contradictory primary data prevents definitive WSL claims. Local: preserve originals and cache repeated CVEs."""
    result, inventory = finding_input(status, count=2)  # Same CVE may appear on multiple observed occurrences.
    requests, events = [], []  # Track external work and full source logging.
    def respond(request):
        """Global: isolate network behavior. Local: count exact repository requests and return the source fixture."""
        requests.append(str(request.url))  # Ensure duplicates do not cause repeated network calls.
        return httpx.Response(200, json=primary_record())  # Serve the Microsoft CNA range conflict.
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:  # Real async HTTP client with an in-memory transport.
        checked, incomplete = await check_wsl_primary_ranges(result, inventory, lambda kind, text: events.append((kind, text)), client=client)  # Exercise the public check independently of storage.
    assert incomplete and len(requests) == 1  # Cache is scoped to this one investigation.
    assert all(finding.status == "potentially_affected" for finding in checked.findings)  # No numeric contradiction can justify definite affected or clear status.
    assert all("5.0.0.0" in " ".join(finding.evidence) and "2.7.8" in " ".join(finding.evidence) for finding in checked.findings)  # Keep exact primary bounds in evidence.
    assert all(any(source.url == requests[0] for source in finding.sources) and "installed-version" in finding.uncertainty for finding in checked.findings)  # Link the primary source and explain the check's limit.
    assert checked.coverage_notes and result.findings[0].status == status  # Original model output stays intact for audit.
    assert any(kind == "source" and '"version"' in text for kind, text in events)  # Full fetched primary data is logged.


@pytest.mark.asyncio
async def test_normal_primary_range_keeps_status_with_scope_caveat():
    """Global: the checker is not a replacement applicability engine. Local: ordinary bounds do not change a model's status."""
    result, inventory = finding_input()  # Existing definitive evidence is still subject to the general structural validator.
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=primary_record("0", "3.0.1")))) as client:  # A numerically ordinary range says nothing about a local match by itself.
        checked, incomplete = await check_wsl_primary_ranges(result, inventory, lambda *_: None, client=client)  # No real device or network activity.
    assert not incomplete and checked.findings[0].status == "affected"  # Do not downgrade merely because the record uses custom version semantics.
    assert "installed-version" in checked.findings[0].uncertainty  # Preserve the narrow validation boundary explicitly.


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [("affected", "potentially_affected"), ("not_affected", "unknown")])
async def test_unavailable_primary_evidence_never_retains_definitive_status(status, expected):
    """Global: unavailable primary verification is an explicit gap. Local: failures are cached and cannot imply clearance."""
    result, inventory = finding_input(status, count=2)  # Both occurrences share one unavailable CVE source.
    requests = []  # Repeated source failure should not multiply timeouts.
    def unavailable(request):
        """Global: simulate upstream outage. Local: return a deterministic unsuccessful HTTP status."""
        requests.append(str(request.url))  # Cache failures as well as successful records.
        return httpx.Response(503, text="Fixture unavailable")  # HTTP errors must not be parsed as records.
    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:  # Run failure handling through the real HTTP library.
        checked, incomplete = await check_wsl_primary_ranges(result, inventory, lambda *_: None, client=client)  # Preserve useful uncertainty instead of failing the whole scan.
    assert incomplete and len(requests) == 1  # One bounded attempt per CVE per scan.
    assert all(finding.status == expected and "unavailable" in finding.uncertainty.lower() for finding in checked.findings)  # Retrieval failure is never definitive applicability evidence.
    assert "503" in " ".join(checked.coverage_notes)  # Retain the actual failure for diagnostics.


@pytest.mark.asyncio
async def test_non_definitive_and_non_wsl_findings_do_not_fetch():
    """Global: keep the check narrowly conditional. Local: unrelated platforms and already-uncertain claims add no requests."""
    result, inventory = finding_input(status="potentially_affected", count=2)  # One finding is already qualified.
    result.findings[1].status = "affected"  # The other is definitive but belongs to a different inventory scope.
    inventory.assets[1].kind = "wsl_package"  # Distro package versions must not enter this platform-only guard.
    def unexpected(_):
        """Global: enforce the intended request boundary. Local: any HTTP request fails this test."""
        raise AssertionError("Unexpected primary-record request")  # No broad CVE crawl is permitted by the test.
    async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:  # An unused transport proves the no-op path.
        checked, incomplete = await check_wsl_primary_ranges(result, inventory, lambda *_: None, client=client)  # The helper preserves unrelated findings.
    assert not incomplete and checked == result  # No opportunistic inspection or speculative downgrade.
