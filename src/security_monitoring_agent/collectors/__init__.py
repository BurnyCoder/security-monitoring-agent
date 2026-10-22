"""Global: inventory orchestration. Local: readable phases share one immutable-evidence contract."""

from pathlib import Path  # Explicit workspace boundary.

from ..models import Inventory, Settings  # Shared public phase types.
from .windows import collect_windows  # Windows installation evidence.
from .wsl import collect_wsl  # Per-distribution Linux metadata.


async def collect_inventory(settings: Settings, root: Path, emit) -> Inventory:
    """Global: collect this device's evidence. Local: combine independent Windows and WSL phases."""
    inventory = Inventory()  # Timestamp the observation snapshot at collection start.
    for collector in (collect_windows, collect_wsl):  # Clear ordered phases avoid process overload.
        emit("phase", f"Starting {collector.__name__}\n")  # Real-time progress shares run logs.
        assets, coverage = await collector(root, emit)  # Each collector reports its own gaps.
        inventory.assets.extend(assets)  # Preserve observed installation occurrences.
        inventory.coverage.extend(coverage)  # Never drop partial-failure evidence.
    return inventory  # Dependency scanning may append project assets in the next phase.
