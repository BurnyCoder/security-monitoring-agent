"""Global: discoverable local response contracts. Local: extend shared evidence with persistence metadata.

Source: https://fastapi.tiangolo.com/tutorial/response-model/ ; response validation detects contract drift.
"""

from typing import Literal  # Lifecycle states remain independent of vulnerability applicability.

from pydantic import Field  # Mutable message collections need independent defaults.

from .models import Advisory, Asset, Contract, Finding, Inventory, Settings  # Reuse domain fields without copying them.


class RunRecord(Contract):
    """Global: durable scan/chat lifecycle. Local: optional details arrive only after execution."""

    id: str  # Stable run identifier doubles as a local transcript name.
    status: Literal["queued", "running", "completed", "partial", "failed", "cancelled", "interrupted"]  # Explicit terminal outcomes.
    kind: Literal["scan", "chat"]  # Both workflows share cancellation and events.
    provider: Literal["codex", "claude"]  # Provider identity remains fixed for a run.
    model: str  # Any identifier supported by the provider is accepted.
    started_at: str  # UTC timestamp set before launching the job.
    finished_at: str | None = None  # Running jobs have no terminal timestamp.
    summary: str = ""  # Complete validated summary, not a truncated preview.
    error: str = ""  # Failures remain visible alongside retained findings.
    chat_id: str | None = None  # Only chat runs belong to a conversation.
    session_id: str | None = None  # Exact CLI session used for explicit resume.
    actual_model: str | None = None  # Some CLIs do not emit the resolved model.
    web_searches: int = 0  # Count observed search tool events, not search quality.
    cancel_requested: bool = False  # Shared signal for separately owned runs.


class StoredAdvisory(Advisory):
    """Global: dated intelligence records. Local: observation time differs from disclosure."""

    observed_at: str  # Last local source observation.


class InventorySnapshot(Inventory):
    """Global: reproducible installation evidence. Local: attach the collecting run."""

    run_id: str  # Reference the log and coverage outcome that produced these facts.


class StoredFinding(Finding):
    """Global: installation assessment response. Local: retain its original evidence snapshot."""

    id: str  # Stable advisory-and-installation occurrence key.
    run_id: str  # Run that last assessed this occurrence.
    checked_at: str  # Assessment time, not source publication time.
    asset: Asset | None = None  # Preserve recorded installation even after later inventory changes.
    advisory: StoredAdvisory | None = None  # Joined current intelligence, possibly absent in legacy records.
    stale: bool = False  # A newer inventory has not reassessed this occurrence.


class ChatMessage(Contract):
    """Global: complete conversation transcript. Local: store visible user and assistant messages."""

    role: Literal["user", "assistant"]  # Internal CLI events stay in the separate raw transcript.
    content: str  # Preserve the complete submitted or emitted message.
    created_at: str  # Record each turn's observation time.


class Conversation(Contract):
    """Global: immutable conversation binding. Local: provider switches create another identity."""

    id: str  # Application-level chat ID.
    provider: Literal["codex", "claude"]  # Subscription authentication belongs to this provider.
    model: str  # Explicit selected model for every turn.
    session_id: str | None = None  # Assigned by the first successful CLI response.
    finding_id: str | None = None  # Optional finding context selected by the user.
    created_at: str  # Creation date persists across server restarts.
    messages: list[ChatMessage] = Field(default_factory=list)  # Lists can omit messages for lightweight summaries.


class ConversationDetail(Contract):
    """Global: reconnectable chat view. Local: include independent active-turn status."""

    chat: Conversation  # Conversation identity and exact CLI session.
    messages: list[ChatMessage]  # Existing frontend contract exposes messages directly too.
    active_run: RunRecord | None  # Chat can remain active while a scan is also running.


class DashboardStatus(Contract):
    """Global: concise dashboard state. Local: zero findings does not assert complete coverage."""

    active_run: RunRecord | None  # Prefer scan activity, otherwise an active chat.
    next_scan_at: str | None  # Null means automatic scans are paused.
    last_successful: RunRecord | None  # Most recent workflow completed without objective gaps.
    counts: dict[str, int]  # Counts concern stored assessments, not a risk probability.
    settings: Settings  # Only public named configuration fields are exposed.


class CancellationResponse(Contract):
    """Global: idempotent stop acknowledgement. Local: completion remains in the run record."""

    requested: bool  # False means the target had already stopped.
