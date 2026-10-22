"""Global: scanner adapter regressions. Local: deterministic OSV report and process fixtures."""

import json  # Fixtures use the documented JSON boundary.
from types import SimpleNamespace  # Fake completed process, no executable required.

import pytest  # Async subprocess adapter tests.

from security_monitoring_agent.intelligence.dependencies import parse_scanner_report, scan_projects  # Public phase helpers.
from security_monitoring_agent.models import ProjectRoot, Settings  # Shared validated configuration.


def scanner_fixture():
    """Global: reusable scanner fixture. Local: one vulnerable resolved dependency."""
    return {"results": [{"source": {"path": "C:/project/uv.lock", "type": "lockfile"}, "packages": [{"package": {"name": "example", "version": "1.0", "ecosystem": "PyPI"}, "vulnerabilities": [{"id": "GHSA-test-test-test", "aliases": ["CVE-2026-12345"], "summary": "Example flaw", "affected": [{"package": {"name": "example", "ecosystem": "PyPI"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}]}]}]}]}  # Exact OSV range is carried as evidence.


def test_dependency_finding_describes_lockfile_not_runtime():
    """Global: avoid overclaiming exploitability. Local: preserve package occurrence and source."""
    assets, advisories, findings = parse_scanner_report(scanner_fixture(), ProjectRoot(path="C:/project"))  # No network.
    assert len(assets) == len(advisories) == len(findings) == 1  # One occurrence with one advisory.
    assert findings[0].status == "affected"  # Scanner matched the recorded dependency version.
    assert "lockfile" in findings[0].rationale.lower()  # State the exact evidence scope.
    assert "reachability" in findings[0].uncertainty.lower()  # No inference that vulnerable code runs.
    assert "1.1" in findings[0].remediation.summary  # Vendor fixed-range evidence is retained.


def test_clean_packages_still_become_assets():
    """Global: expose coverage denominator. Local: all-packages output includes clean packages."""
    fixture = scanner_fixture()  # Reuse fixture construction.
    fixture["results"][0]["packages"][0]["vulnerabilities"] = []  # Clean scanner outcome.
    assets, advisories, findings = parse_scanner_report(fixture, ProjectRoot(path="C:/project"))  # Same package identity.
    assert len(assets) == 1 and not advisories and not findings  # Clean package coverage stays visible.


def test_withdrawn_advisory_is_not_active_finding():
    """Global: honor source corrections. Local: withdrawn records are not vulnerabilities."""
    fixture = scanner_fixture()  # Reuse the observed dependency fixture.
    fixture["results"][0]["packages"][0]["vulnerabilities"][0]["withdrawn"] = "2026-10-01T00:00:00Z"  # OSV withdrawal field.
    assets, advisories, findings = parse_scanner_report(fixture, ProjectRoot(path="C:/project"))  # No live service.
    assert len(assets) == 1 and not advisories and not findings  # Keep inventory but remove invalidated claim.


@pytest.mark.asyncio
@pytest.mark.parametrize("exit_code,status", [(0, "ok"), (1, "ok"), (127, "error"), (128, "unsupported")])
async def test_scanner_exit_semantics(monkeypatch, tmp_path, exit_code, status):
    """Global: findings are successful scans. Local: no-packages remains unsupported."""
    async def fake_process(*args, **kwargs):
        """Global: isolate scanner invocation. Local: reproduce documented process outcomes."""
        return SimpleNamespace(returncode=exit_code, stdout=json.dumps(scanner_fixture()), stderr="diagnostic")  # Full deterministic report.
    monkeypatch.setattr("security_monitoring_agent.intelligence.dependencies.run_process", fake_process)  # Substitute only external process boundary.
    settings = Settings(project_roots=[ProjectRoot(path=str(tmp_path))])  # Only explicit root is scanned.
    _, _, _, coverage = await scan_projects(settings, tmp_path, lambda *_: None)  # No live scanner.
    assert coverage[0].status == status  # Errors can never masquerade as no findings.
