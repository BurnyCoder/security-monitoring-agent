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
from .models import Inventory, Investigation, Settings  # One final result schema for both agents.
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


async def _storage_phase(operation, *args):
    """Global: keep dashboard requests responsive. Local: finish an outstanding database worker before ending ownership.

    Source: https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread . Cancelling an
    await cannot stop an already-running thread, so shield and drain it before propagating cancellation.
    """
    worker = asyncio.create_task(asyncio.to_thread(operation, *args))  # Store methods open and close their own thread-local SQLite connections.
    try:  # Preserve the coordinator's normal cancellation result without abandoning writes.
        return await asyncio.shield(worker)  # Cancellation must not detach the still-running database operation.
    except asyncio.CancelledError:  # The scan lock remains owned until this cleanup finishes.
        await asyncio.gather(worker, return_exceptions=True)  # Drain the worker and retrieve any exception before releasing ownership.
        raise  # Cancellation remains the terminal result even if the last write finishes successfully.


def _publishable_result(result: Investigation, inventory: Inventory, store: Store) -> tuple[Investigation, bool]:
    """Global: publish grounded records with visible omissions. Local: distinguish validation gaps from free-text scope notes."""
    validated = validate_investigation(result, inventory)  # Unknown assets are rejected and unsupported certainty is qualified.
    incomplete = len(validated.findings) != len(result.findings)  # Unknown assets are a concrete validation gap.
    asset_ids = {asset.id for asset in inventory.assets}  # Pair retained findings with their original statuses without guessing from prose.
    original_findings = [finding for finding in result.findings if finding.asset_id in asset_ids]  # The evidence validator preserves this occurrence order.
    for before, after in zip(original_findings, validated.findings, strict=True):  # Repeated identities still compare against their own original assessments.
        if before.status != after.status:  # A structural evidence failure weakened a definitive claim.
            incomplete = True  # An unsupported clearance cannot appear as a fully validated workflow.
            validated.coverage_notes.append(f"Downgraded finding: {after.advisory_id} / {after.asset_id} from {before.status} to {after.status}; definitive applicability lacked cited or observed evidence.")  # Make the change visible in run summary and logs.
    for advisory in validated.advisories:  # Uncited intelligence is omitted explicitly, never silently.
        if not advisory.sources:  # Even plausible model news needs a supporting source link.
            incomplete = True  # Rejected output is an objective validation gap.
            validated.coverage_notes.append(f"Rejected uncited advisory: {advisory.id}")  # Retain its identity for auditing against raw provider logs.
    validated.advisories = [advisory for advisory in validated.advisories if advisory.sources]  # Filter before evaluating finding references.
    known_advisories = {advisory.id for advisory in validated.advisories}  # Earlier deterministic intelligence is checked through the store below.
    findings = []  # Build only occurrences with a publishable advisory identity.
    for finding in validated.findings:  # Existing aliases can legitimately refer to earlier source intelligence.
        if finding.advisory_id in known_advisories or store.get("advisory", store.canonical(finding.advisory_id)):  # Do not persist orphan applicability claims.
            findings.append(finding)  # Preserve supported and explicitly uncertain assessments.
        else:  # Rejected news must not leave behind an unexplained occurrence.
            incomplete = True  # Surface the actual evidence gap in final status.
            validated.coverage_notes.append(f"Rejected finding with unknown advisory: {finding.advisory_id} / {finding.asset_id}")  # Show the discarded identity without inventing a source.
    validated.findings = findings  # Original result remains complete in provider logs.
    return validated, incomplete  # Generic model notes remain visible but do not automatically mean failed coverage.


async def run_scan(settings: Settings, root: Path, store: Store, run_id: str, emit, cancel: asyncio.Event) -> dict:
    """Global: complete monitoring pipeline. Local: expose phases, preserve partial successes."""
    workdir = root / "data" / "runs" / run_id  # Agents may inspect only this run's prepared context by default.
    workdir.mkdir(parents=True, exist_ok=True)  # These ignored files never enter a public commit.
    emit("phase", "Collecting Windows, WSL and project inventory")  # Explain current work immediately.
    inventory = await collect_inventory(settings, root, emit)  # Read-only deterministic collection.
    await _storage_phase(store.save_inventory, run_id, inventory)  # Preserve facts off-loop even if a later source is unavailable.
    if cancel.is_set():  # Stop before starting another potentially expensive phase.
        raise asyncio.CancelledError  # The coordinator records cancellation, not success.
    emit("phase", "Collecting CISA intelligence and OSV dependency evidence")  # APIs complement web search.
    advisories, findings, coverage = await collect_intelligence(settings, inventory, root, emit)  # Full source records.
    inventory.coverage.extend(coverage)  # Source failures are visible alongside collector coverage.
    await _storage_phase(store.save_inventory, run_id, inventory)  # Dependency scanning may have added observed lockfile assets.
    deterministic = Investigation(summary="Source collection completed", advisories=advisories, findings=findings, coverage_notes=[])  # Preserve non-model findings independently.
    deterministic, source_gap = await _storage_phase(_publishable_result, deterministic, inventory, store)  # Validate source occurrences without blocking on identity lookups.
    await _storage_phase(store.save_investigation, run_id, deterministic)  # Full KEV persistence must not freeze the dashboard event loop.
    for note in deterministic.coverage_notes:  # Source validation gaps remain visible even if the model phase later fails.
        emit("coverage", note)  # Complete notes reach timestamped logs and terminal output.
    for name, body in [("inventory.json", inventory.model_dump(mode="json")), ("intelligence.json", deterministic.model_dump(mode="json"))]:  # Complete agent evidence files.
        (workdir / name).write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")  # No token-based evidence truncation.
    checkpoint = await _storage_phase(store.get, "meta", "research_checkpoint")  # Only validated web-enabled runs advance this cursor.
    start = datetime.now(timezone.utc) - timedelta(days=settings.news_days)  # Default initial news window.
    if checkpoint:  # Include overlap for delayed publication or corrected advisories.
        start = max(start, datetime.fromisoformat(checkpoint["at"]) - timedelta(hours=24))  # Do not search beyond chosen history unnecessarily.
    emit("phase", "Investigating applicability with live web search")  # Provider selection belongs to this run.
    prompt = scan_prompt(settings, inventory, start.isoformat())  # Explicitly scopes inspection and copyable fixes.
    response = await run_agent(settings, prompt, workdir, emit, cancel, schema=strict_schema(Investigation.model_json_schema()))  # Stream all CLI events.
    result = Investigation.model_validate(response.structured) if response.structured is not None else Investigation.model_validate_json(response.text)  # Invalid final payload raises.
    validated, model_gap = await _storage_phase(_publishable_result, result, inventory, store)  # Validate and expose omitted or weakened model claims.
    emit("phase", "Validating and publishing evidence")  # Progress text is separate from authoritative results.
    await _storage_phase(store.save_investigation, run_id, validated)  # Retain older unassessed occurrences as visibly stale without blocking requests.
    incomplete = source_gap or model_gap or any(item.status != "ok" for item in inventory.coverage) or response.web_searches == 0  # Objective collection/research/validation gaps determine partial status.
    if response.web_searches == 0:  # A successful CLI answer alone does not prove actual web research.
        validated.coverage_notes.append("No live web-search event was observed; research checkpoint was not advanced.")  # Explain degraded capability.
    else:  # Update incremental cursor only after actual web research and valid structured output.
        await _storage_phase(store.put, "meta", "research_checkpoint", {"at": inventory.captured_at})  # Collection time is conservative for overlap.
    for note in validated.coverage_notes:  # Preserve every original model note as well as concrete validation messages.
        emit("coverage", note)  # Stream complete qualifications in the same timestamped log as prompts and output.
    summary = "\n".join([validated.summary, *deterministic.coverage_notes, *validated.coverage_notes])  # Completed means workflow completion, not exhaustive or factually guaranteed assessment.
    return {"status": "partial" if incomplete else "completed", "summary": summary, "session_id": response.session_id, "actual_model": response.model, "web_searches": response.web_searches}  # Coordinator owns final run transition.
