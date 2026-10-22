"""Global: regression tests for claim strength. Local: synthetic evidence only."""

from security_monitoring_agent.evidence import validate_investigation
from security_monitoring_agent.models import Asset, Finding, Inventory, Investigation, Source


def test_unknown_asset_rejected():
    """Global: forbid invented installations. Local: assert unresolved identities fail."""
    result = Investigation(summary="test", advisories=[], findings=[Finding(advisory_id="CVE-TEST", asset_id="invented", status="affected", rationale="a claim")], coverage_notes=[])
    validated = validate_investigation(result, Inventory())
    assert not validated.findings
    assert "invented" in " ".join(validated.coverage_notes)


def test_definitive_without_citations_downgraded():
    """Global: ungrounded certainty is invalid. Local: downgrade rather than hide evidence."""
    asset = Asset(id="app", kind="windows_app", name="Example", version="1", platform="Windows")
    result = Investigation(summary="test", advisories=[], findings=[Finding(advisory_id="CVE-TEST", asset_id="app", status="affected", rationale="missing KB")], coverage_notes=[])
    finding = validate_investigation(result, Inventory(assets=[asset])).findings[0]
    assert finding.status == "potentially_affected"
    assert finding.uncertainty


def test_explicit_evidence_preserved():
    """Global: retain qualified findings. Local: evidence plus a citation satisfies the structural gate."""
    asset = Asset(id="ubuntu:lib", kind="wsl_package", name="example", version="1-ubuntu2", platform="Ubuntu")
    result = Investigation(summary="test", advisories=[], findings=[Finding(advisory_id="CVE-TEST", asset_id=asset.id, status="not_affected", rationale="vendor backport", evidence=["Installed distro version includes the vendor backport."], sources=[Source(title="Vendor", url="https://example.org/advisory")])], coverage_notes=[])
    assert validate_investigation(result, Inventory(assets=[asset])).findings[0].status == "not_affected"
