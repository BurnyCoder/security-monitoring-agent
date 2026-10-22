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


@pytest.mark.asyncio
async def test_wsl_project_argv_is_literal_and_occurrences_stay_separate(monkeypatch, tmp_path):
    """Global: explicitly configured WSL projects retain their own scope. Local: argv contains literal distro/path values without shell interpolation."""
    distribution = "Ubuntu Fixture"  # A name containing a space must remain one argument.
    paths = ["/home/fixture/project with spaces;$(literal)", "/home/fixture/second project"]  # Metacharacters are path text, never a shell command.
    calls = []  # Record the wrapper boundary without launching WSL or installing a scanner.
    async def fake_process(args, **options):
        """Global: reproduce a successful Linux scanner response. Local: give each configured project its own source-file path."""
        calls.append((args, options))  # Preserve the complete argument vector and timeout contract.
        payload = scanner_fixture()  # Reuse the same recorded package/version to test occurrence isolation.
        payload["results"][0]["source"]["path"] = args[-1] + "/uv.lock"  # Native Linux scanner paths remain native through normalization.
        return SimpleNamespace(returncode=1, stdout=json.dumps(payload), stderr="Fixture scanner diagnostic")  # Findings are a successful scanner exit.
    monkeypatch.setattr("security_monitoring_agent.intelligence.dependencies.run_process", fake_process)  # Replace only the native process boundary.
    settings = Settings(project_roots=[ProjectRoot(kind="wsl", distribution=distribution, path=path) for path in paths], timeout_seconds=600)  # No automatic discovery or Windows path translation.
    assets, advisories, findings, coverage = await scan_projects(settings, tmp_path, lambda *_: None)  # Exercise selection, invocation, parsing, and coverage in one wrapper call.
    for (args, options), path in zip(calls, paths, strict=True):  # Each configured root gets exactly one scoped invocation.
        assert args == ["wsl.exe", "--distribution", distribution, "--exec", "osv-scanner", "scan", "source", "--format=json", "--all-packages", "--no-call-analysis=go", "--no-resolve", "--recursive", path]  # Documented non-mutating scanner flags and values are separate literal arguments.
        assert options["cwd"] == tmp_path and options["timeout"] == 300  # The Windows caller cwd and five-minute project bound are explicit.
    assert len(calls) == len(assets) == len(advisories) == len(findings) == len(coverage) == 2  # No configured project is silently skipped.
    assert len({asset.id for asset in assets}) == 2 and {finding.asset_id for finding in findings} == {asset.id for asset in assets}  # Identical packages in distinct projects stay separate occurrences.
    assert all(asset.platform == f"WSL:{distribution}" for asset in assets)  # A Linux project is never mislabeled as a Windows dependency.
    assert {asset.location for asset in assets} == {path + "/uv.lock" for path in paths}  # Keep exact source paths for applicability evidence.
    assert all(item.status == "ok" and item.asset_count == 1 for item in coverage)  # Both scopes report their actual successful package count.
