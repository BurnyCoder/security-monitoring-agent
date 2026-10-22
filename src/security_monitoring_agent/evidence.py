"""Global: evidence validation is distinct from collection. Local: prevent unsupported certainty.

This structural gate is not a factual verifier; source checking remains part of agent investigation.
Sources: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering
and https://documentation.ubuntu.com/security/security-updates/ .
"""

from .models import Inventory, Investigation  # Enforce the same structure used by both providers.


def validate_investigation(result: Investigation, inventory: Inventory) -> Investigation:
    """Global: bind conclusions to observations. Local: reject invented IDs and qualify weak evidence."""
    validated = result.model_copy(deep=True)  # Preserve the original model output in the transcript.
    asset_ids = {asset.id for asset in inventory.assets}  # Only observed installations can be assessed.
    validated.findings = []  # Rebuild from individually validated occurrences.
    for finding in result.findings:  # One bad occurrence must not erase useful sibling findings.
        if finding.asset_id not in asset_ids:  # Models occasionally invent an installation identifier.
            validated.coverage_notes.append(f"Rejected finding for unknown asset: {finding.asset_id}")  # Audit it.
            continue  # An invented asset is not a valid device finding.
        item = finding.model_copy(deep=True)  # Keep the parser's input immutable.
        if item.status in {"affected", "not_affected"} and (not item.sources or not item.evidence):  # Require both.
            item.status = "potentially_affected" if item.status == "affected" else "unknown"  # No false clearance.
            item.uncertainty = "Definitive assessment lacked cited applicability or observed evidence. " + item.uncertainty  # Explain downgrade.
        validated.findings.append(item)  # Qualified uncertainty remains useful to the user.
    return validated  # Persistence only receives this checked result.
