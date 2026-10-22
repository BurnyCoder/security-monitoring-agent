"""Global: inventory accuracy regressions. Local: exercise source-shaped fixtures offline."""

import asyncio  # Cancellation must propagate through scope isolation.
from types import SimpleNamespace  # Deterministic process results avoid another device scan.

import pytest  # Async fixture boundaries exercise Windows-only orchestration anywhere.

from security_monitoring_agent.collectors.windows import parse_windows_inventory  # Pure parser boundary.
from security_monitoring_agent.collectors.wsl import parse_wsl_inventory  # Preserve distro identity.


def test_windows_preserves_patch_evidence_and_registry_occurrences():
    """Global: avoid false patch conclusions. Local: keep separate registry installations."""
    assets, coverage = parse_windows_inventory({"os": {"name": "Windows 11", "build": "26100.1234", "edition": "Professional", "architecture": "AMD64"}, "apps": [{"name": "Example", "version": "1.0", "location": "HKLM/example"}, {"name": "Example", "version": "2.0", "location": "HKCU/example"}], "appx": [], "hotfixes": ["KB123"], "errors": []})  # Observed fields mirror PowerShell JSON.
    assert len(assets) == 3  # Duplicate names are not duplicate installations.
    assert assets[0].metadata["hotfixes"] == "KB123"  # Supplemental KB evidence survives.
    assert assets[1].id != assets[2].id  # Locations identify separate occurrences.
    assert all(item.status == "ok" for item in coverage)  # Successful fixture has no errors.


def test_windows_partial_collector_is_not_clean():
    """Global: preserve collection gaps. Local: AppX failure is explicit."""
    _, coverage = parse_windows_inventory({"os": {}, "apps": [], "appx": [], "hotfixes": [], "errors": [{"component": "windows_appx", "detail": "Access denied"}]})  # Failure remains source-specific.
    assert next(item for item in coverage if item.component == "windows_appx").status == "error"  # Missing coverage never implies safe.


def test_wsl_uses_source_versions_and_only_installed_packages():
    """Global: respect distro backports. Local: source versions differ from binary versions."""
    raw = 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n__SM_KERNEL__\n6.6.1-microsoft-standard-WSL2\n__SM_PACKAGES__\ninstalled\tlibexample:amd64\t1:2.0-1ubuntu2\tamd64\texample\t1:2.0-1ubuntu1\nconfig-files\tremoved\t1\tamd64\tremoved\t1\n'  # dpkg-query's virtual source fields are authoritative.
    assets, coverage = parse_wsl_inventory("Ubuntu", raw)  # No shell or machine access.
    package = next(item for item in assets if item.kind == "wsl_package")  # Inspect collected userland.
    assert package.metadata["source_package"] == "example"  # Avoid binary/source-name confusion.
    assert package.metadata["source_version"] == "1:2.0-1ubuntu1"  # Keep Debian epoch/revision intact.
    assert not any(item.name == "removed" for item in assets)  # Residual config is not installed code.
    assert coverage[-1].asset_count == 1  # Count actual packages, not all dpkg rows.


def test_unsupported_wsl_package_manager_keeps_os_inventory():
    """Global: partial evidence remains useful. Local: unsupported packages stay visible."""
    assets, coverage = parse_wsl_inventory("Other", "ID=other\n__SM_KERNEL__\n1.0\n__SM_PACKAGES_UNSUPPORTED__\n")  # No invented apt coverage.
    assert assets[0].kind == "wsl_os"  # OS identity still exists.
    assert coverage[-1].status == "unsupported"  # Explicit limitation, not no vulnerabilities.


def test_wsl_missing_metadata_and_malformed_rows_are_partial():
    """Global: prevent false coverage confidence. Local: malformed observed rows stay visible."""
    _, coverage = parse_wsl_inventory("Broken", "__SM_KERNEL__\n1.0\n__SM_PACKAGES__\ninstalled\tbroken\t1\n")  # Failed metadata and truncated row.
    assert coverage[0].status == "partial"  # A distro name does not establish its OS release.
    assert coverage[1].status == "partial"  # Silent row loss cannot count as successful coverage.


@pytest.mark.asyncio
async def test_wsl_platform_nul_padding_and_cancellation(monkeypatch, tmp_path):
    """Global: preserve portable WSL evidence/cancellation. Local: simulate legacy output and a cancelled distro."""
    from security_monitoring_agent.collectors.wsl import collect_wsl  # Exercise the complete scope wrapper.
    monkeypatch.setattr("security_monitoring_agent.collectors.wsl.platform.system", lambda: "Windows")  # No host dependency.
    async def discover(*args, **kwargs):
        """Global: isolate registry discovery. Local: return one configured test distro."""
        return ["TestDistro"]  # PowerShell normally yields the same name list.
    async def completed_process(args, **kwargs):
        """Global: simulate successful native pipes. Local: separate platform and package commands."""
        text = "W\x00S\x00L\x00 2.6.0\x00" if "--version" in args else "ID=ubuntu\nVERSION_ID=24.04\n__SM_KERNEL__\n6.6\n__SM_PACKAGES__\n"  # Legacy version NUL padding does not affect shell output.
        return SimpleNamespace(returncode=0, stdout=text, stderr="")  # Shared ProcessResult-compatible contract.
    monkeypatch.setattr("security_monitoring_agent.collectors.wsl.powershell_json", discover)  # No registry reads.
    monkeypatch.setattr("security_monitoring_agent.collectors.wsl.run_process", completed_process)  # No native process.
    assets, _ = await collect_wsl(tmp_path, lambda *_: None)  # Collect one synthetic distro.
    assert assets[0].version == "WSL 2.6.0"  # Strip legacy NUL padding from display/agent context.
    async def cancelled_process(args, **kwargs):
        """Global: cancellation ends collection. Local: raise at the per-distro subprocess boundary."""
        if "--version" in args:  # Platform succeeds before the user cancels the distro phase.
            return await completed_process(args, **kwargs)  # Reuse the platform fixture.
        raise asyncio.CancelledError  # Must not become a swallowed coverage error.
    monkeypatch.setattr("security_monitoring_agent.collectors.wsl.run_process", cancelled_process)  # Simulate the shared helper cancellation contract.
    with pytest.raises(asyncio.CancelledError):  # Calling pipeline can stop promptly.
        await collect_wsl(tmp_path, lambda *_: None)  # No further distro work should run.
