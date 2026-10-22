"""Global: run lifecycle independent of HTTP connections. Local: locks, scheduling and chat ownership.

Sources: https://portalocker.readthedocs.io/ and https://docs.python.org/3/library/asyncio-task.html
"""

import asyncio  # Background tasks persist while the app, rather than its browser tab, runs.
import json  # Chat evidence uses the same complete inventory serialization as scans.
import sys  # Login tasks may run without a terminal stream.
from datetime import datetime, timedelta, timezone  # Store schedule times in UTC.
from pathlib import Path  # All runtime files remain beneath the workspace.
from uuid import uuid4  # Distinguish simultaneous chat and scan runs within one timestamp.

import portalocker  # Cross-process locks coordinate optional Windows tasks with the web app.

from .agents import run_agent  # Follow-up chats reuse the tested provider adapters.
from .config import load_settings  # Reload changes made by the UI or a separate process.
from .models import Settings, utc_now  # Persist explicit state transitions.
from .pipeline import run_scan  # The CLI and UI share one workflow.
from .prompts import chat_prompt  # Chat has the same proposal-only task scope.
from .runlog import RunLog  # All jobs have complete local transcripts.
from .storage import Store  # Persist results before notifying the browser.


class BusyError(RuntimeError):
    """Global: a duplicate trigger is not a new run. Local: transport maps this to HTTP 409."""


def run_identifier() -> str:
    """Global: collision-resistant local log names. Local: include a human-readable UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:10]  # Safe filename characters only.


class Monitor:
    """Global: shared application service. Local: owns tasks, cancellation and durable run transitions."""

    def __init__(self, root: Path):
        """Global: bind one workspace. Local: do not launch network or agent work in construction."""
        self.root = root.resolve()  # All configuration and state are rooted explicitly.
        self.store = Store(self.root / "data" / "monitor.sqlite3")  # Ignored local database.
        self.tasks: dict[str, asyncio.Task] = {}  # Strong references keep background tasks alive.
        self.cancellations: dict[str, asyncio.Event] = {}  # Cancel button signals the running adapter.
        self.started: set[str] = set()  # Avoid cancelling a coroutine before its cleanup scope begins.
        self.stopping = asyncio.Event()  # Scheduler exits promptly when the app stops.

    def lock(self, name: str):
        """Global: coordinate every process. Local: nonblocking acquisition never queues duplicate scans."""
        lock = portalocker.Lock(self.root / "data" / f"{name}.lock", mode="a", timeout=0, flags=portalocker.LOCK_EX | portalocker.LOCK_NB)  # The OS releases this on process exit.
        try:  # A competing standalone scanner may own the same workspace.
            lock.acquire()  # Hold across the run, not across SQLite transactions.
        except portalocker.exceptions.LockException as error:  # Distinguish busy from collector failure.
            raise BusyError(f"{name} is already running") from error  # Caller can show the existing run.
        return lock  # The executor releases exactly this acquired handle.

    def recover(self) -> None:
        """Global: never leave dead jobs running forever. Local: test each lock before marking interruption."""
        for run in self.store.all("run"):  # Active records may belong to a live scheduled process.
            if run["status"] not in {"running", "queued"}:  # Completed history needs no recovery.
                continue  # Preserve its original outcome.
            name = "scan" if run["kind"] == "scan" else f"chat-{run['chat_id']}"  # Recover at the same scope as execution.
            try:  # A held OS lock proves another process still owns the job.
                handle = self.lock(name)  # Do not infer liveness from timestamps alone.
            except BusyError:  # The scheduled scanner or another UI instance remains active.
                continue  # Leave its record untouched.
            try:  # No owner exists; this record reflects an interrupted prior process.
                self.store.update("run", run["id"], status="interrupted", finished_at=utc_now(), error="Application stopped before this run finished.")  # Visible restart recovery.
            finally:  # Recovery does not reserve execution capacity.
                handle.release()  # Subsequent manual scans can proceed immediately.

    def active(self, kind: str = "scan", chat_id: str | None = None) -> dict | None:
        """Global: inspect cross-process state. Local: select one currently active scoped job."""
        return next((run for run in self.store.all("run") if run["kind"] == kind and run["status"] in {"running", "queued"} and (chat_id is None or run.get("chat_id") == chat_id)), None)  # Database is the shared source of truth.

    def next_scan(self, settings: Settings | None = None) -> str | None:
        """Global: predictable hourly schedule. Local: use last attempt, so failures cannot spin."""
        settings = settings or load_settings(self.root)  # UI edits take effect without restarting.
        if not settings.auto_scan:  # Manual-only mode must never schedule inference.
            return None  # UI displays paused rather than a fake countdown.
        latest = next((run for run in self.store.all("run") if run["kind"] == "scan"), None)  # Includes failed attempts.
        if latest is None:  # A fresh app starts one baseline scan.
            return utc_now()  # The scheduler coalesces this to one job through the lock.
        return (datetime.fromisoformat(latest["started_at"]) + timedelta(minutes=settings.interval_minutes)).isoformat()  # Cadence starts with each attempt.

    async def scheduler(self) -> None:
        """Global: app-lifetime polling. Local: coalesce missed intervals and avoid multi-process overlap."""
        while not self.stopping.is_set():  # Closing the browser does not affect this lifecycle.
            try:  # A bad external configuration should not kill the whole web server.
                settings = load_settings(self.root)  # Respect saved intervals and optional task mode.
                self.recover()  # Reconcile crashed standalone scanners even while this UI stays open.
                due = self.next_scan(settings)  # No accumulating queue after sleep/resume.
                if settings.schedule_mode != "task" and due and datetime.fromisoformat(due) <= datetime.now(timezone.utc) and not self.active():  # Task Scheduler owns recurring task mode.
                    self.start_scan(settings)  # Lock acquisition arbitrates simultaneous manual requests.
            except BusyError:  # A scheduled process won the race.
                pass  # Its results will appear through the same database.
            except Exception as error:  # Surface operational errors without a tight retry loop.
                if sys.stdout is not None:  # Background login tasks have no console to write to.
                    print(f"[{utc_now()}] scheduler: {error}", flush=True)  # No credentials are included in settings errors.
            try:  # Wake early on app shutdown.
                await asyncio.wait_for(self.stopping.wait(), timeout=5)  # Short periodic checks reflect UI changes.
            except TimeoutError:  # Normal polling interval completed.
                pass  # Continue with a fresh settings snapshot.

    def create_run(self, settings: Settings, kind: str, **extra) -> dict:
        """Global: persist intent before execution. Local: snapshot provider/model for reproducibility."""
        run = {"id": run_identifier(), "status": "running", "kind": kind, "provider": settings.provider, "model": settings.model, "started_at": utc_now(), "finished_at": None, "summary": "", "error": "", **extra}  # Explicit lifecycle fields.
        self.store.put("run", run["id"], run)  # SSE can subscribe immediately after the HTTP response.
        return run  # Starting a job and displaying it share the same identifier.

    def start_scan(self, settings: Settings | None = None) -> dict:
        """Global: manual and scheduled entry point. Local: acquire shared ownership before creating a job."""
        settings = settings or load_settings(self.root)  # A manual override is local to this run.
        handle = self.lock("scan")  # This also protects against standalone scan --once.
        run = self.create_run(settings, "scan")  # No duplicate record when acquisition fails.
        self.launch(run, handle, lambda emit, cancel: run_scan(settings, self.root, self.store, run["id"], emit, cancel))  # One shared pipeline.
        return run  # Callers can stream its progress without awaiting the whole scan.

    def launch(self, run: dict, handle, operation) -> None:
        """Global: own the task lifetime. Local: pair each task with its cancellation signal."""
        cancel = asyncio.Event()  # Cooperative cancellation also reaches provider subprocesses.
        self.cancellations[run["id"]] = cancel  # The cancel endpoint addresses this owned job.
        task = asyncio.create_task(self.execute(run, handle, operation, cancel))  # Browser requests can finish now.
        self.tasks[run["id"]] = task  # Avoid garbage collection of unreferenced tasks.
        task.add_done_callback(lambda completed: self.tasks.pop(run["id"], None))  # Drop only finished tasks.

    async def execute(self, run: dict, handle, operation, cancel: asyncio.Event) -> None:
        """Global: every job reaches a recorded terminal state. Local: errors preserve prior results."""
        emit = RunLog(self.root, self.store, run["id"])  # One complete transcript for all phases.
        try:  # All job paths, including cancellation, must release the lock.
            self.started.add(run["id"])  # Cancellation can now safely enter this finally block.
            if cancel.is_set():  # A user may cancel immediately after task creation.
                raise asyncio.CancelledError  # Release the lock without starting any subprocess.
            emit("state", f"Starting {run['kind']} with {run['provider']} / {run['model']}")  # Visible invocation metadata.
            outcome = await operation(emit, cancel)  # Workflow returns validated state only.
            self.store.update("run", run["id"], **outcome, finished_at=utc_now())  # Commit terminal state before event.
            emit("done", outcome.get("summary", "Completed"))  # Reconnecting clients can stop streaming.
        except asyncio.CancelledError:  # Deliberate interruption is not an empty successful assessment.
            self.store.update("run", run["id"], status="cancelled", finished_at=utc_now(), error="Cancelled by user or application shutdown")  # Keep partial evidence.
            emit("done", "Cancelled; previous findings and collected evidence are retained.")  # Explain outcome.
        except Exception as error:  # Invalid JSON, unavailable models, source bugs and timeouts remain explicit.
            self.store.update("run", run["id"], status="failed", finished_at=utc_now(), error=str(error))  # Never erase older findings.
            emit("error", str(error))  # Full diagnostics remain local rather than being cut off.
            emit("done", "Run failed; inspect the full log and coverage details.")  # Terminal event for the UI.
        finally:  # Successful and failed runs release exactly their owned resources.
            handle.release()  # Another trigger can start after this point.
            self.started.discard(run["id"])  # No later cancellation may target this finished coroutine.
            self.cancellations.pop(run["id"], None)  # Stale cancel buttons cannot target another run.

    def create_chat(self, provider: str, model: str, finding_id: str | None = None) -> dict:
        """Global: explicit conversation identity. Local: provider/model remain fixed for the session."""
        settings = Settings(provider=provider, model=model)  # Validate provider and nonempty model.
        chat = {"id": uuid4().hex, "provider": settings.provider, "model": settings.model, "session_id": None, "finding_id": finding_id, "created_at": utc_now(), "messages": []}  # No generic --continue behavior.
        self.store.put("chat", chat["id"], chat)  # Persist before sending the first message.
        return chat  # UI uses this ID for all subsequent messages.

    def start_chat(self, chat_id: str, message: str) -> dict:
        """Global: scope follow-ups to one conversation. Local: serialize messages per chat across processes."""
        chat = self.store.get("chat", chat_id)  # User-supplied ID is looked up, never used as an arbitrary path.
        if chat is None:  # Missing sessions should produce a visible 404.
            raise KeyError(chat_id)  # HTTP layer maps domain absence to a response.
        handle = self.lock(f"chat-{chat_id}")  # Prevent two turns from racing the same CLI session.
        settings = load_settings(self.root).model_copy(update={"provider": chat["provider"], "model": chat["model"]})  # Keep selected session identity.
        chat["messages"].append({"role": "user", "content": message, "created_at": utc_now()})  # Record the exact question.
        self.store.put("chat", chat_id, chat)  # Persist user input even if a CLI is unavailable.
        run = self.create_run(settings, "chat", chat_id=chat_id)  # Chats share log and cancellation infrastructure.
        self.launch(run, handle, lambda emit, cancel: self.chat_turn(settings, chat, message, emit, cancel))  # One owned background turn.
        return run  # The frontend attaches the same SSE viewer used for scans.

    async def chat_turn(self, settings: Settings, chat: dict, message: str, emit, cancel: asyncio.Event) -> dict:
        """Global: contextual investigation assistance. Local: resume only the exact saved CLI session."""
        workdir = self.root / "data" / "chats" / chat["id"]  # Stable cwd for that conversation only.
        workdir.mkdir(parents=True, exist_ok=True)  # Retain evidence locally for reproducibility.
        inventory = self.store.inventory()  # Follow-ups can inspect the latest complete snapshot.
        (workdir / "inventory.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")  # No unrelated project crawl.
        finding = self.store.get("finding", chat["finding_id"]) if chat["finding_id"] else None  # Optional selected finding.
        if finding:  # Include advisory provenance rather than an orphan vulnerability identifier.
            finding["advisory"] = self.store.get("advisory", finding["advisory_id"])  # Preserve remediation citations.
        prompt = chat_prompt(message, finding, inventory, fresh=not chat["session_id"])  # Resumes retain provider history.
        answer = await run_agent(settings, prompt, workdir, emit, cancel, session_id=chat["session_id"])  # Unstructured prose is appropriate for chat.
        chat["session_id"] = answer.session_id  # Subsequent turns bind to this exact provider session.
        chat["messages"].append({"role": "assistant", "content": answer.text, "created_at": utc_now()})  # Store the entire visible response.
        self.store.put("chat", chat["id"], chat)  # Commit before marking the turn complete.
        return {"status": "completed", "summary": answer.text, "session_id": answer.session_id, "actual_model": answer.model}  # UI reloads persisted messages.

    def cancel(self, run_id: str) -> bool:
        """Global: cancellation across UI and scheduled processes. Local: persist a request for the owner."""
        run = self.store.get("run", run_id)  # Reject unknown or already completed IDs.
        if not run or run["status"] not in {"running", "queued"}:  # No process is eligible for interruption.
            return False  # Idempotent UI can refresh the current state.
        self.store.update("run", run_id, cancel_requested=True)  # A separate owner polls this shared flag.
        if run_id in self.cancellations:  # Fast path when this process owns the job.
            self.cancellations[run_id].set()  # Provider drains logs while terminating descendants.
            if run_id in self.started and not self.tasks[run_id].cancelling():  # Never interrupt an in-progress cleanup.
                self.tasks[run_id].cancel()  # Also interrupt inventory or a stalled network phase.
        return True  # Cancellation is requested, not falsely reported already complete.

    async def watch_cancellations(self) -> None:
        """Global: cancellation works for standalone scheduled jobs. Local: poll only owned active IDs."""
        while not self.stopping.is_set():  # This watcher shares application lifecycle.
            for identifier in list(self.tasks):  # Tasks can finish while database queries run.
                run = self.store.get("run", identifier)  # Read cross-process cancellation requests.
                if run and run.get("cancel_requested") and identifier in self.tasks:  # Target current owned job only.
                    self.cancellations[identifier].set()  # Propagate to the reusable process runner.
                    if identifier in self.started and not self.tasks[identifier].cancelling():  # Repeated polling must not re-cancel cleanup.
                        self.tasks[identifier].cancel()  # Stop non-provider phases too.
            await asyncio.sleep(1)  # Responsiveness without busy-polling the database.

    async def close(self) -> None:
        """Global: stop cleanly with the app. Local: cancel and reap all owned background work."""
        self.stopping.set()  # Stop scheduling new work immediately.
        for identifier in list(self.tasks):  # Snapshot because done callbacks remove entries.
            self.cancel(identifier)  # Reuse the user cancellation path and complete logging.
        await asyncio.gather(*list(self.tasks.values()), return_exceptions=True)  # Release subprocesses and locks before exit.
