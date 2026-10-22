"""Global: one readable provider workflow. Local: prepare, stream, and validate a run.

Sources: https://docs.python.org/3/library/tempfile.html and provider references
in commands.py/events.py; prompt policy belongs to the application's pipeline.
"""

import asyncio  # Caller-owned cancellation crosses the transport boundary.
from collections.abc import Callable  # Synchronous log callbacks preserve event ordering.
from pathlib import Path  # All invocation artifacts remain under the supplied workdir.
from tempfile import TemporaryDirectory  # Remove only this invocation's owned artifacts.

from ..models import Settings  # Common user-visible preferences.
from ..process import run_process  # Reuse collector-grade process lifecycle handling.
from .commands import command  # Provider-specific argv stays out of orchestration.
from .events import AgentEvents  # Provider-specific parsing stays out of orchestration.
from .types import AgentResult  # Public result contract.


async def run_agent(settings: Settings, prompt: str, workdir: Path, emit: Callable[[str, str], None], cancel: asyncio.Event, schema: dict | None = None, session_id: str | None = None) -> AgentResult:
    """Global: shared agent facade. Local: prepare artifacts, invoke CLI, validate final output."""
    emit("prompt", prompt)  # Persist the complete user/application prompt before any inference.
    events = AgentEvents(settings.provider, emit)  # Fresh state prevents stale scan findings.
    def receive(kind: str, text: str) -> None:
        """Global: log raw evidence before interpretation. Local: dispatch stdout JSONL."""
        emit(kind, text)  # No raw stdout/stderr line is truncated or hidden.
        if kind == "stdout":  # Provider protocol lives on stdout; stderr is diagnostic.
            events.feed(text)  # A complete line can exceed the default asyncio size limit.
    with TemporaryDirectory(prefix=".agent-", dir=workdir) as temporary:  # Own a unique verified subtree of the workdir.
        directory = Path(temporary).resolve()  # Absolute CLI artifact paths avoid cwd ambiguity.
        args = command(settings, directory, schema, session_id)  # Assemble literal, provider-specific argv.
        emit("progress", f"Starting {settings.provider} with model {settings.model}")  # Expose the requested selection.
        result = await run_process(args, cwd=workdir, stdin=prompt, emit=receive, cancel=cancel, timeout=settings.timeout_seconds)  # Stream while process runs.
        if result.returncode != 0:  # Transport success is distinct from a valid agent answer.
            raise RuntimeError(f"{settings.provider} exited with code {result.returncode}: {result.stderr.strip() or events.error or 'See complete run log'}")  # Keep all diagnostics in emitted logs.
        final_path = directory / "final.txt"  # Codex writes the authoritative final response here.
        final_text = final_path.read_text(encoding="utf-8") if settings.provider == "codex" and final_path.exists() else None  # Fall back to completed event text only if absent.
        output = events.finish(require_structured=schema is not None, final_text=final_text)  # Reject incomplete or refused data.
        if output.session_id is None and session_id:  # A resumed provider may omit its unchanged ID.
            output = AgentResult(output.text, output.structured, session_id, output.model, output.web_searches)  # Preserve the explicitly requested chat identity.
        emit("agent_result", output.text)  # The complete final result survives temporary-file cleanup.
        return output  # Domain validation is the caller's next clearly separated phase.
