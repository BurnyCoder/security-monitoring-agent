"""Global: intelligence orchestration. Local: combine exploitation feed and project dependency evidence."""

from pathlib import Path  # Workspace remains explicit across phase interfaces.

from ..models import Advisory, Coverage, Finding, Inventory, Settings  # Shared public contracts.
from .dependencies import scan_projects  # Existing maintained scanner handles dependency ecosystems.
from .kev import fetch_kev  # Complete known-exploitation baseline.


async def collect_intelligence(settings: Settings, inventory: Inventory, root: Path, emit) -> tuple[list[Advisory], list[Finding], list[Coverage]]:
    """Global: gather deterministic intelligence before agent research. Local: execute clearly named independent phases."""
    advisories, coverage = await fetch_kev(emit)  # Keep every KEV entry irrespective of the news window.
    assets, dependency_advisories, findings, dependency_coverage = await scan_projects(settings, root, emit)  # Explicit project roots only.
    inventory.assets.extend(assets)  # The shared contract permits appending dependency observations.
    advisories.extend(dependency_advisories)  # Storage merges alias overlap with source provenance.
    coverage.extend(dependency_coverage)  # Partial sources remain visible to the UI and agent.
    return advisories, findings, coverage  # The next phase uses web search for device-specific applicability.
