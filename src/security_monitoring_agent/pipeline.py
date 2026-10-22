"""Global: the single scan workflow. Local: readable phases delegate implementation to modules.

Source: https://docs.python.org/3/library/asyncio-task.html . Cancellation is checked between phases.
"""

import asyncio  # Shared cancellation survives a disconnected dashboard.
import json  # Full evidence snapshots are readable by either CLI.
from datetime import datetime, timedelta, timezone  # Compute overlap from successful checkpoints.
from pathlib import Path  # Keep each run's working files inside the current workspace.

from .agents import run_agent  # Provider-specific details stay behind one interface.
from .collectors import collect_inventory  # Deterministic observations precede model assessment.
from .evidence import validate_investigation  # Reject invalid certainty before committing findings.
from .intelligence import collect_intelligence  # Reuse CISA and OSV implementations.
from .models import Investigation, Settings  # One final result schema for both agents.
from .prompts import scan_prompt  # Versioned instructions stay separate from orchestration.
from .storage import Store  # Durable state survives UI or server restarts.


def strict_schema(schema: dict) -> dict:
    """Global: provider structured output compatibility. Local: require every declared object field."""
    result = json.loads(json.dumps(schema))  # Never mutate Pydantic's reusable schema definition.
    def visit(node):
        """Global: recurse schema objects only. Local: make defaults explicit in structured responses."""
        if isinstance(node, dict):  # References and array items contain nested schema definitions.
            if node.get("type") == "object":  # Strict providers require required=all properties.
                node["required"] = list(node.get("properties", {}))  # Nullable fields remain explicitly null.
                node["additionalProperties"] = False  # Avoid unvalidated output extensions.
            node.pop("default", None)  # Defaults are application concerns, not provider instructions.
            for child in node.values():  # Traverse definitions, properties and array constraints.
                visit(child)  # Lists are handled by the sibling branch below.
        elif isinstance(node, list):  # anyOf and required arrays are both harmless to traverse.
            for child in node:  # Primitive strings terminate recursion immediately.
                visit(child)  # Reuse the same object rule throughout the schema.
    visit(result)  # Normalize the schema exactly once per scan.
    return result  # The original runtime model retains its ergonomic defaults.


async def run_scan(settings: Settings, root: Path, store: Store, run_id: str, emit, cancel: asyncio.Event) -> dict:
    """Global: complete monitoring pipeline. Local: expose phases, preserve partial successes."""
    workdir = root / "data" / "runs" / run_id  # Agents may inspect only this run's prepared context by default.
    workdir.mkdir(parents=True, exist_ok=True)  # These ignored files never enter a public commit.
    emit("phase", "Collecting Windows, WSL and project inventory")  # Explain current work immediately.
    inventory = await collect_inventory(settings, root, emit)  # Read-only deterministic collection.
    store.save_inventory(run_id, inventory)  # Preserve facts even if a later source is unavailable.
    if cancel.is_set():  # Stop before starting another potentially expensive phase.
        raise asyncio.CancelledError  # The coordinator records cancellation, not success.
    emit("phase", "Collecting CISA intelligence and OSV dependency evidence")  # APIs complement web search.
    advisories, findings, coverage = await collect_intelligence(settings, inventory, root, emit)  # Full source records.
    inventory.coverage.extend(coverage)  # Source failures are visible alongside collector coverage.
    store.save_inventory(run_id, inventory)  # Dependency scanning may have added observed lockfile assets.
    deterministic = Investigation(summary="Source collection completed", advisories=advisories, findings=findings, coverage_notes=[])  # Preserve non-model findings independently.
    store.save_investigation(run_id, validate_investigation(deterministic, inventory))  # Useful results survive agent failure.
    for name, body in [("inventory.json", inventory.model_dump(mode="json")), ("intelligence.json", deterministic.model_dump(mode="json"))]:  # Complete agent evidence files.
        (workdir / name).write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")  # No token-based evidence truncation.
    checkpoint = store.get("meta", "research_checkpoint")  # Only validated web-enabled runs advance this cursor.
    start = datetime.now(timezone.utc) - timedelta(days=settings.news_days)  # Default initial news window.
    if checkpoint:  # Include overlap for delayed publication or corrected advisories.
        start = max(start, datetime.fromisoformat(checkpoint["at"]) - timedelta(hours=24))  # Do not search beyond chosen history unnecessarily.
    emit("phase", "Investigating applicability with live web search")  # Provider selection belongs to this run.
    prompt = scan_prompt(settings, inventory, start.isoformat())  # Explicitly scopes inspection and copyable fixes.
    response = await run_agent(settings, prompt, workdir, emit, cancel, schema=strict_schema(Investigation.model_json_schema()))  # Stream all CLI events.
    result = Investigation.model_validate(response.structured) if response.structured is not None else Investigation.model_validate_json(response.text)  # Invalid final payload raises.
    validated = validate_investigation(result, inventory)  # Bind every assessment to an observed asset ID.
    validated.advisories = [advisory for advisory in validated.advisories if advisory.sources]  # Uncited news is not publishable evidence.
    known_advisories = {item.id for item in validated.advisories} | {item.id for item in advisories}  # Only publishable records can support findings.
    validated.findings = [finding for finding in validated.findings if finding.advisory_id in known_advisories or store.get("advisory", store.canonical(finding.advisory_id))]  # Never persist orphan applicability claims.
    emit("phase", "Validating and publishing evidence")  # Progress text is separate from authoritative results.
    store.save_investigation(run_id, validated)  # Retain older unassessed occurrences as visibly stale.
    incomplete = any(item.status != "ok" for item in inventory.coverage) or response.web_searches == 0  # Never hide incomplete collection.
    if response.web_searches == 0:  # A successful CLI answer alone does not prove actual web research.
        validated.coverage_notes.append("No live web-search event was observed; research checkpoint was not advanced.")  # Explain degraded capability.
    else:  # Update incremental cursor only after actual web research and valid structured output.
        store.put("meta", "research_checkpoint", {"at": inventory.captured_at})  # Collection time is conservative for overlap.
    summary = validated.summary + "\n" + "\n".join(validated.coverage_notes)  # Preserve all model-stated limitations.
    return {"status": "partial" if incomplete else "completed", "summary": summary, "session_id": response.session_id, "actual_model": response.model, "web_searches": response.web_searches}  # Coordinator owns final run transition.
