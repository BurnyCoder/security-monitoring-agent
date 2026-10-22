"""Global: observed Windows inventory. Local: normalize registry/AppX/OS facts without CVE inference.

Source: https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations .
"""

import platform  # Unsupported hosts remain explicit.
from pathlib import Path  # Load the fixed, reviewable collector script.

from ..models import Asset, Coverage  # Shared evidence contracts.
from .common import asset_id, powershell_json  # Reuse process and identity primitives.


def parse_windows_inventory(payload: dict) -> tuple[list[Asset], list[Coverage]]:
    """Global: retain installation evidence. Local: decode each independent Windows scope."""
    assets = []  # Keep all successfully inspected occurrences.
    errors = payload.get("errors", [])  # Scope failures arrive separately from evidence.
    os_info = payload.get("os", {})  # Build/edition are necessary for OS applicability.
    if os_info:  # Do not invent an OS asset after failed collection.
        metadata = {key: str(value or "") for key, value in os_info.items()}  # Asset metadata is intentionally textual.
        metadata["hotfixes"] = ", ".join(payload.get("hotfixes", []))  # Preserve partial KB evidence.
        metadata["patch_evidence_limit"] = "Get-HotFix is incomplete; absent KBs do not prove vulnerability; cumulative-update supersedence requires vendor evidence."  # State the API's known limitation.
        assets.append(Asset(id=asset_id("windows", "os"), kind="windows_os", name=os_info.get("name", "Windows"), version=os_info.get("build", ""), platform="Windows", metadata=metadata))  # The OS is one stable installation.
    for key in ("apps", "appx"):  # Registry and Store installations remain distinct sources.
        for app in payload.get(key, []):  # Keep versionless applications for agent investigation.
            location = str(app.get("location", ""))  # Registry key or package full name identifies occurrence.
            assets.append(Asset(id=asset_id("windows", key, location, app["name"]), kind="windows_app", name=app["name"], version=str(app.get("version") or ""), platform="Windows", location=location, metadata={"publisher": str(app.get("publisher") or ""), "inventory_source": key}))  # Preserve raw vendor version strings.
    counts = {"windows_os": int(bool(os_info)), "windows_registry": len(payload.get("apps", [])), "windows_appx": len(payload.get("appx", [])), "windows_hotfixes": len(payload.get("hotfixes", []))}  # Scope counts make gaps interpretable.
    coverage = []  # Emit one summary per collection scope.
    for component, count in counts.items():  # Failures affect only their own collector.
        failures = [error["detail"] for error in errors if error.get("component") == component]  # Preserve every error without truncation.
        detail = "; ".join(failures) if failures else "Collected installed metadata; portable applications and other users are outside this inventory."  # No claim of exhaustive device coverage.
        if component == "windows_hotfixes" and not failures:  # A successful API call still has known scope limits.
            detail = "Collected Get-HotFix evidence; missing KBs do not prove missing fixes or account for supersedence."  # Prevent downstream false certainty.
        coverage.append(Coverage(component=component, status=("partial" if count else "error") if failures else "ok", detail=detail, asset_count=count))  # Partial success preserves assets.
    return assets, coverage  # The orchestrator combines Windows and WSL evidence.


async def collect_windows(root: Path, emit) -> tuple[list[Asset], list[Coverage]]:
    """Global: Windows phase boundary. Local: isolate host/script failures into coverage."""
    if platform.system() != "Windows":  # The dashboard is designed to inspect Windows from Windows.
        return [], [Coverage(component="windows", status="unsupported", detail="Run the dashboard on Windows to inspect Windows and WSL.")]  # Unsupported is not clean.
    try:  # External collection failure must not abort WSL/dependency phases.
        script = Path(__file__).with_suffix(".ps1").read_text(encoding="utf-8")  # Versioned script is the implementation source.
        return parse_windows_inventory(await powershell_json(script, root, emit))  # Complete JSON and terminal logs share one process boundary.
    except Exception as exc:  # Cancellation derives from BaseException and still propagates.
        emit("error", f"Windows inventory failed: {exc}\n")  # Log exact failure in real time.
        return [], [Coverage(component="windows", status="error", detail=str(exc))]  # Preserve failed coverage explicitly.
