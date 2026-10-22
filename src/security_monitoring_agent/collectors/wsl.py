"""Global: inspect each WSL distribution separately. Local: parse package facts, never upstream semver.

Sources: https://learn.microsoft.com/en-us/windows/wsl/basic-commands and
https://manpages.debian.org/unstable/dpkg/dpkg-query.1.en.html .
"""

import platform  # WSL discovery is a Windows-host operation.
import shlex  # Decode shell-quoted os-release values without sourcing a file.
from pathlib import Path  # Load the reviewable fixed shell script.

from ..models import Asset, Coverage  # Shared observed-evidence contracts.
from ..process import run_process  # Shared complete streaming and bounded subprocess lifetime.
from .common import asset_id, powershell_json  # Stable identities and UTF-8 discovery.


def parse_wsl_inventory(distribution: str, raw: str) -> tuple[list[Asset], list[Coverage]]:
    """Global: retain distro/package provenance. Local: decode explicit section boundaries."""
    if "__SM_KERNEL__" not in raw:  # A failed shell invocation must not yield an invented clean distro.
        raise ValueError(f"Missing WSL metadata sections for {distribution}")  # Caller records an error.
    os_text, remainder = raw.split("__SM_KERNEL__", 1)  # Metadata is before the fixed delimiter.
    metadata = {}  # os-release values remain plain strings.
    for line in os_text.splitlines():  # Do not execute os-release as shell code.
        if "=" in line and not line.startswith("#"):  # Ignore comment/blank lines.
            key, value = line.split("=", 1)  # Values can contain additional equals signs.
            values = shlex.split(value)  # Standard quoted os-release syntax.
            metadata[key] = values[0] if values else ""  # Keep empty metadata fields.
    lines = remainder.strip().splitlines()  # Kernel is the first line after the delimiter.
    metadata["kernel"] = lines[0] if lines else ""  # WSL kernel is separate from distro packages.
    metadata["kernel_scope"] = "WSL kernel/platform requires Microsoft evidence; distro kernel advisories do not automatically apply."  # Avoid Ubuntu-kernel false positives.
    assets = [Asset(id=asset_id("wsl", distribution, "os"), kind="wsl_os", name=metadata.get("PRETTY_NAME", distribution), version=metadata.get("VERSION_ID", ""), platform=f"WSL:{distribution}", metadata=metadata)]  # One OS identity per distro.
    count, malformed = 0, 0  # Count installed packages and visibly incomplete records separately.
    for line in lines[1:]:  # Skip the running-kernel line.
        fields = line.split("\t")  # dpkg-query controls the six field boundaries.
        if line and not line.startswith("__SM_") and len(fields) != 6:  # Malformed output cannot silently inflate coverage confidence.
            malformed += 1  # Report all unparseable records in coverage.
        if len(fields) != 6 or fields[0] != "installed":  # Residual configuration is not an installed package.
            continue  # Section markers and removed packages are not assets.
        _, name, version, architecture, source_name, source_version = fields  # Preserve Debian epochs and revisions exactly.
        assets.append(Asset(id=asset_id("wsl", distribution, name, architecture), kind="wsl_package", name=name, version=version, platform=f"WSL:{distribution}", location="dpkg-query", metadata={"architecture": architecture, "source_package": source_name or name.split(":", 1)[0], "source_version": source_version or version, "distribution_id": metadata.get("ID", ""), "distribution_version": metadata.get("VERSION_ID", "")}))  # Source identity supports vendor-package research.
        count += 1  # Inventory denominator reflects successful package rows.
    status = "unsupported" if "__SM_PACKAGES_UNSUPPORTED__" in raw else "partial" if "__SM_PACKAGES_ERROR__" in raw or malformed or "__SM_PACKAGES__" not in raw else "ok"  # Package failures never hide OS evidence.
    os_status = "ok" if metadata.get("ID") and metadata.get("VERSION_ID") and metadata.get("kernel") else "partial"  # Missing release data prevents definitive advisory applicability.
    coverage = [Coverage(component=f"wsl:{distribution}:os", status=os_status, detail="Read /etc/os-release and running kernel." if os_status == "ok" else "OS release or running kernel metadata is incomplete.", asset_count=1), Coverage(component=f"wsl:{distribution}:packages", status=status, detail=f"Read installed dpkg packages and source versions; {malformed} malformed rows. No deterministic Linux CVE matching. Other package managers, snaps, portable installs and runtime reachability are not covered.", asset_count=count)]  # Explicitly state collection gaps and matching limitations.
    return assets, coverage  # Caller joins all independently inspected distros.


async def collect_wsl(root: Path, emit) -> tuple[list[Asset], list[Coverage]]:
    """Global: WSL inventory phase. Local: bounded per-distro commands retain partial success."""
    if platform.system() != "Windows":  # Do not pretend a Linux host inventory is WSL discovery.
        return [], [Coverage(component="wsl", status="unsupported", detail="WSL discovery requires a Windows host.")]  # Unsupported remains visible.
    assets, coverage = [], []  # Independent distro failures do not discard prior observations.
    try:  # Discover only installed distributions registered for this Windows user.
        script = "$ErrorActionPreference='Stop'; if (Test-Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss') { @((Get-ChildItem 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss' | Get-ItemProperty).DistributionName) | ConvertTo-Json -Compress } else { '[]' }"  # Registry avoids localized/UTF-16 wsl --list parsing.
        distributions = await powershell_json(script, root, emit, timeout=30)  # Discovery is bounded separately.
        if isinstance(distributions, str):  # PowerShell may unwrap a single array element.
            distributions = [distributions]  # Restore the shared collection shape.
        distributions = distributions or []  # An empty registry is a valid no-distro result.
        coverage.append(Coverage(component="wsl:discovery", status="ok", detail=f"Found {len(distributions)} registered WSL distributions for the current user.", asset_count=len(distributions)))  # Distinguish absence from failure.
    except Exception as exc:  # Error evidence is retained for the agent.
        return [], [Coverage(component="wsl:discovery", status="error", detail=str(exc))]  # Stop only this failed discovery phase.
    if distributions:  # Avoid launching the WSL installation prompt on systems without distros.
        try:  # WSL platform metadata is independent from distro package inventories.
            result = await run_process(["wsl.exe", "--version"], cwd=root, emit=emit, timeout=30)  # Documented non-mutating version command.
            version = result.stdout.replace("\x00", "").strip()  # Legacy wsl output can contain UTF-16 NULs.
            if result.returncode != 0:  # Older inbox WSL may not support --version.
                raise RuntimeError(result.stderr or version)  # Keep unsupported platform metadata visible.
            assets.append(Asset(id=asset_id("wsl", "platform"), kind="wsl_platform", name="Windows Subsystem for Linux", version=version, platform="Windows", metadata={"collection_command": "wsl.exe --version"}))  # Preserve the full component version output.
            coverage.append(Coverage(component="wsl:platform", status="ok", detail="Collected WSL component versions.", asset_count=1))  # Platform coverage is separate from userland.
        except Exception as exc:  # Still inspect individual distributions.
            coverage.append(Coverage(component="wsl:platform", status="error", detail=str(exc)))  # Missing version is not a fixed platform.
    script = Path(__file__).with_suffix(".sh").read_text(encoding="utf-8")  # Fixed script contains no user-provided shell interpolation.
    for distribution in distributions:  # Independent commands isolate distro failures and timeouts.
        try:  # Opening a stopped distro is necessary to inspect its package database.
            result = await run_process(["wsl.exe", "--distribution", distribution, "--exec", "sh", "-c", script], cwd=root, emit=emit, timeout=120)  # Distro name is one argument, never shell code.
            if result.returncode != 0:  # Reject incomplete shell startup failures.
                raise RuntimeError(result.stderr or f"WSL exited {result.returncode}")  # Preserve exact stderr in logs.
            distro_assets, distro_coverage = parse_wsl_inventory(distribution, result.stdout)  # Normalize only successful observations.
            assets.extend(distro_assets)  # Retain all package occurrences.
            coverage.extend(distro_coverage)  # Retain this distro's actual coverage.
        except Exception as exc:  # One broken distro must not abort the monitoring run.
            emit("error", f"WSL {distribution}: {exc}\n")  # Full immediate diagnostic.
            coverage.append(Coverage(component=f"wsl:{distribution}", status="error", detail=str(exc)))  # Explicit missing scope.
    return assets, coverage  # All successful and failed WSL scopes reach the dashboard.
