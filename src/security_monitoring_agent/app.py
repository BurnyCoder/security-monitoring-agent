"""Global: local HTTP boundary. Local: typed requests delegate work to the monitor service.

Sources: https://fastapi.tiangolo.com/advanced/events/ and
https://fastapi.tiangolo.com/tutorial/server-sent-events/ .
"""

import asyncio  # Lifespan owns long-lived scheduler and cancellation tasks.
from collections.abc import AsyncIterable  # FastAPI recognizes typed async SSE generators.
from contextlib import asynccontextmanager  # Startup/shutdown are one explicit resource scope.
from datetime import datetime, timedelta, timezone  # Filter news without altering stored device findings.
from pathlib import Path  # Packaged templates and static assets live beside this module.
from typing import Literal  # Provider choices are fixed; model identifiers remain open.
from urllib.parse import urlsplit  # Compare browser Origin with this same local server.

from fastapi import FastAPI, HTTPException, Request  # Typed API, errors, and same-origin checks.
from fastapi.responses import FileResponse, JSONResponse  # Download complete logs and return validation errors.
from fastapi.sse import EventSourceResponse, ServerSentEvent  # Native SSE provides heartbeats and framing.
from fastapi.staticfiles import StaticFiles  # Serve local assets without third-party CDNs.
from fastapi.templating import Jinja2Templates  # Autoescaped initial dashboard shell.
from pydantic import Field  # Reject empty messages and invalid ranges at the HTTP boundary.
from starlette.middleware.trustedhost import TrustedHostMiddleware  # Reject arbitrary Host headers on loopback.

from .config import load_settings, save_settings  # UI edits use the same dotenv config as the CLI.
from .diagnostics import diagnostics  # Read-only runtime probes.
from .models import Contract, RunEvent, Settings  # Keep public request and event shapes strict.
from .api_models import CancellationResponse, Conversation, ConversationDetail, DashboardStatus, InventorySnapshot, RunRecord, StoredAdvisory, StoredFinding  # Named responses document the local API.
from .service import BusyError, Monitor  # No scan logic lives in HTTP route functions.


class ScanRequest(Contract):
    """Global: per-run overrides. Local: absent selections inherit saved preferences."""

    provider: Literal["codex", "claude"] | None = None  # Either installed provider is selectable.
    model: str | None = Field(default=None, min_length=1)  # Provider decides whether a model is available.
    news_days: Literal[1, 7, 30] | None = None  # News recency does not prune unresolved findings.


class ChatRequest(Contract):
    """Global: explicitly scoped conversation. Local: bind provider/model and optional finding."""

    provider: Literal["codex", "claude"]  # Session identity is immutable after creation.
    model: str = Field(min_length=1)  # No hard-coded model allowlist.
    finding_id: str | None = None  # A finding-specific chat includes its evidence automatically.


class MessageRequest(Contract):
    """Global: preserve complete questions. Local: reject empty submissions."""

    message: str = Field(min_length=1)  # Input remains literal text, never shell syntax.


def create_app(root: Path | None = None) -> FastAPI:
    """Global: testable app factory. Local: own one monitor per explicit workspace."""
    root = (root or Path.cwd()).resolve()  # Respect the user's current working directory.
    monitor = Monitor(root)  # Construction initializes only local persistence.

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Global: deterministic lifecycle. Local: start workers once and cancel them on exit."""
        monitor.recover()  # Mark only unowned interrupted jobs before launching new ones.
        workers = [asyncio.create_task(monitor.scheduler()), asyncio.create_task(monitor.watch_cancellations())]  # Single process owns these loops.
        yield  # HTTP requests and SSE proceed while workers run.
        await monitor.close()  # Reap owned CLI subprocesses before closing the app.
        for worker in workers:  # Stop polling after all owned scans/chats have ended.
            worker.cancel()  # Prompt shutdown even if the poll interval has not elapsed.
        await asyncio.gather(*workers, return_exceptions=True)  # Consume expected cancellation exceptions.

    app = FastAPI(title="Security monitoring agent", lifespan=lifespan)  # OpenAPI documents the typed local boundary.
    app.state.monitor = monitor  # Tests and route handlers share one explicit service instance.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])  # Local access only.
    assets = Path(__file__).parent  # Works from the editable checkout and packaged distributions.
    app.mount("/static", StaticFiles(directory=assets / "static"), name="static")  # No runtime frontend build.
    templates = Jinja2Templates(directory=assets / "templates")  # Jinja escapes dynamic template values.

    @app.middleware("http")
    async def same_origin(request: Request, call_next):
        """Global: local UI cannot be driven by another website. Local: reject foreign mutation origins."""
        origin = request.headers.get("origin")  # Non-browser CLI clients may omit Origin.
        if request.method not in {"GET", "HEAD", "OPTIONS"} and origin:  # Reading public UI assets requires no token.
            parsed = urlsplit(origin)  # Compare exact scheme/authority, not string suffixes.
            if parsed.scheme != request.url.scheme or parsed.netloc != request.headers.get("host"):  # Same-origin browser requests only.
                return JSONResponse({"detail": "Cross-origin requests are not accepted"}, status_code=403)  # No agent invocation occurs.
        return await call_next(request)  # Normal local API behavior remains unrestricted.

    @app.exception_handler(BusyError)
    async def busy(request: Request, error: BusyError):
        """Global: explain duplicate jobs. Local: map shared-lock contention to a useful API response."""
        return JSONResponse({"detail": str(error)}, status_code=409)  # Browser can reconnect to the current run.

    @app.get("/")
    async def index(request: Request):
        """Global: dashboard entrypoint. Local: serve the packaged application shell."""
        return templates.TemplateResponse(request=request, name="index.html")  # All live data comes from typed APIs.

    @app.get("/api/status", response_model=DashboardStatus)
    async def status():
        """Global: concise operational overview. Local: count assessed occurrences, not raw feed size."""
        runs = monitor.store.all("run")  # Includes standalone scheduler runs through shared SQLite.
        findings = monitor.store.findings()  # Older findings stay visible with stale indicators.
        counts = {value: sum(row["status"] == value for row in findings) for value in ("affected", "potentially_affected", "unknown")}  # Explicit applicability counts.
        counts["advisories"] = len(monitor.store.advisories())  # Full intelligence baseline count.
        return {"active_run": monitor.active() or monitor.active("chat"), "next_scan_at": monitor.next_scan(), "last_successful": next((run for run in runs if run["kind"] == "scan" and run["status"] == "completed"), None), "counts": counts, "settings": load_settings(root)}  # Stable dashboard contract.

    @app.get("/api/findings", response_model=list[StoredFinding])
    async def findings():
        """Global: persistent device exposure. Local: do not apply the news date filter here."""
        return monitor.store.findings()  # The frontend filters status, scope, severity and source.

    @app.get("/api/advisories", response_model=list[StoredAdvisory])
    async def advisories():
        """Global: recent intelligence view. Local: preserve separately recorded publication/addition dates."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=load_settings(root).news_days)).isoformat()[:10]  # Compare ISO calendar dates safely.
        rows = monitor.store.advisories()  # Storage retains the complete baseline regardless of this view.
        return [row for row in rows if max([row.get(field, "")[:10] for field in ("published_at", "modified_at", "kev_added_at") if row.get(field)] or [row["observed_at"][:10]]) >= cutoff]  # Corrected or newly exploited older disclosures can be news.

    @app.get("/api/inventory", response_model=InventorySnapshot | None)
    async def inventory():
        """Global: transparent coverage. Local: return the latest actual snapshot or null."""
        return monitor.store.inventory()  # Do not invent demo inventory for an unscanned machine.

    @app.get("/api/runs", response_model=list[RunRecord])
    async def runs():
        """Global: full scan/chat audit history. Local: newest persisted job first."""
        return monitor.store.all("run")  # The UI can inspect failures and partial runs alike.

    @app.post("/api/runs", status_code=202, response_model=RunRecord)
    async def start_scan(body: ScanRequest):
        """Global: manual trigger. Local: validate overrides and reuse the shared scan coordinator."""
        values = load_settings(root).model_dump()  # Capture a stable configuration snapshot.
        values.update(body.model_dump(exclude_none=True))  # Do not overwrite defaults with null.
        return monitor.start_scan(Settings.model_validate(values))  # Return immediately with a durable run ID.

    @app.get("/api/runs/{run_id}", response_model=RunRecord)
    async def run_detail(run_id: str):
        """Global: inspect one lifecycle. Local: reject unknown IDs before accessing paths."""
        run = monitor.store.get("run", run_id)  # Parameterized database lookup.
        if run is None:  # No implicit new run on a read request.
            raise HTTPException(404, "Run not found")  # Clear missing-resource response.
        return run  # Contains final coverage summary and diagnostics.

    @app.post("/api/runs/{run_id}/cancel", response_model=CancellationResponse)
    async def cancel_run(run_id: str):
        """Global: explicit cancel control. Local: signal only a known owned or scheduled run."""
        await run_detail(run_id)  # Validate before mutating cancellation state.
        return {"requested": monitor.cancel(run_id)}  # Cross-process owners observe the shared flag.

    @app.get("/api/runs/{run_id}/events", response_class=EventSourceResponse)
    async def events(run_id: str, request: Request, after: int = 0) -> AsyncIterable[ServerSentEvent]:
        """Global: reconnectable live activity. Local: browser disconnect never cancels the underlying job."""
        await run_detail(run_id)  # Unknown run IDs must not create infinite streams.
        try:  # Browsers send Last-Event-ID on reconnect; explicit after supports initial pagination.
            cursor = max(after, int(request.headers.get("last-event-id", "0")))  # Replay only unseen events.
        except ValueError:  # Reject malformed cursors instead of crashing the generator.
            raise HTTPException(400, "Invalid event cursor")  # Clear client error.
        async def stream():
            """Global: bounded durable replay. Local: fetch pages until a terminal run has no remaining events."""
            nonlocal cursor  # Keep the last emitted ID for this connection only.
            while not await request.is_disconnected():  # The monitor task remains independent.
                batch = monitor.store.events(run_id, after=cursor)  # Each record retains its complete text.
                for event in batch:  # EventSourceResponse performs JSON escaping and SSE framing.
                    cursor = event["id"]  # Advance only when the event is emitted.
                    yield ServerSentEvent(data=RunEvent.model_validate(event), id=str(cursor))  # Validate the shared payload and preserve its reconnect cursor.
                run = monitor.store.get("run", run_id)  # A separate scheduled process can update this record.
                if not batch and run["status"] not in {"running", "queued"}:  # Drain terminal events before closing.
                    break  # Frontend reconnect can still request prior events explicitly.
                await asyncio.sleep(0.3)  # Keep event latency low without an unbounded in-memory queue.
        async for event in stream():  # FastAPI's route layer owns event serialization and keepalives.
            yield event  # Returning a bare response would bypass native SSE encoding.

    @app.get("/api/runs/{run_id}/log")
    async def log_file(run_id: str):
        """Global: complete transcript download. Local: derive paths only from persisted run IDs."""
        run = await run_detail(run_id)  # Prevent arbitrary filesystem reads through route parameters.
        path = root / "logs" / f"{run['id']}.jsonl"  # Same filename convention as RunLog.
        if not path.is_file():  # A just-created run may not yet have emitted an event.
            raise HTTPException(404, "Log not available yet")  # Retry after the first phase starts.
        return FileResponse(path, media_type="application/x-ndjson", filename=path.name)  # No truncation or transformation.

    @app.get("/api/settings", response_model=Settings)
    async def settings():
        """Global: editable public preferences. Local: return only named configuration fields."""
        return load_settings(root)  # Never expose unrelated dotenv values or credentials.

    @app.patch("/api/settings", response_model=Settings)
    async def update_settings(body: Settings):
        """Global: persist user changes. Local: reconcile optional Windows tasks only when needed."""
        previous = load_settings(root)  # Avoid re-registering tasks on unrelated model edits.
        fields = ("schedule_mode", "interval_minutes", "auto_scan")  # Changes that affect Windows triggers.
        if any(getattr(previous, field) != getattr(body, field) for field in fields) and (body.schedule_mode != "app" or previous.schedule_mode != "app"):  # Default mode never touches Task Scheduler.
            from .scheduling import configure_schedule  # Keep optional Windows integration isolated.
            try:  # Failed registration must not advertise a schedule that does not exist.
                await configure_schedule(root, body)  # User selected this mode explicitly in Settings.
            except Exception as error:  # Keep the prior valid dotenv preferences intact.
                raise HTTPException(400, f"Windows scheduling could not be updated: {error}") from error  # Explain actual failure.
        save_settings(root, body)  # Atomically persist after required integration succeeds.
        return body  # Browser displays the exact saved preferences.

    @app.get("/api/diagnostics")
    async def runtime_diagnostics():
        """Global: explain setup failures. Local: probe tool versions without inspecting secrets."""
        return await diagnostics(root)  # Independent checks stay responsive and bounded.

    @app.get("/api/chats", response_model=list[Conversation], response_model_exclude={"__all__": {"messages"}})
    async def chats():
        """Global: persist investigations across browser sessions. Local: list explicit conversation IDs."""
        return [{key: value for key, value in chat.items() if key != "messages"} for chat in monitor.store.all("chat")]  # Load messages only when selected.

    @app.post("/api/chats", status_code=201, response_model=Conversation)
    async def create_chat(body: ChatRequest):
        """Global: bind conversation context. Local: validate an optional finding before creation."""
        if body.finding_id and monitor.store.get("finding", body.finding_id) is None:  # No invented finding references.
            raise HTTPException(404, "Finding not found")  # User can choose an existing row.
        return monitor.create_chat(body.provider, body.model, body.finding_id)  # Provider/model remain fixed per session.

    @app.get("/api/chats/{chat_id}", response_model=ConversationDetail)
    async def chat_detail(chat_id: str):
        """Global: reconnectable chat. Local: return saved messages and any live turn."""
        chat = monitor.store.get("chat", chat_id)  # Lookup before path-dependent operations.
        if chat is None:  # Missing conversation IDs never create a new provider session.
            raise HTTPException(404, "Chat not found")  # Explicit absence.
        return {"chat": chat, "messages": chat["messages"], "active_run": monitor.active("chat", chat_id)}  # UI can resume event streaming.

    @app.post("/api/chats/{chat_id}/messages", status_code=202, response_model=RunRecord)
    async def send_message(chat_id: str, body: MessageRequest):
        """Global: launch a follow-up turn. Local: preserve the full question and stream asynchronously."""
        await chat_detail(chat_id)  # Reject unknown IDs before acquiring a filesystem lock.
        return monitor.start_chat(chat_id, body.message)  # Busy conversations return 409 rather than fork silently.

    return app  # Factory supports production startup and isolated test workspaces.
