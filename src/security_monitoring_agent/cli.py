"""Global: one launch path for humans and Windows tasks. Local: delegate to the same web/scan services.

Sources: https://docs.python.org/3/library/argparse.html and https://www.uvicorn.org/settings/
"""

import argparse  # Standard-library CLI avoids another command-framework dependency.
import asyncio  # Standalone scans use the same asynchronous pipeline as HTTP-triggered scans.
import json  # Diagnostics and final standalone outcomes are machine-readable.
import sys  # Configure Unicode logging and report meaningful process exit codes.
import webbrowser  # Open the local dashboard only for explicitly interactive launches.
from pathlib import Path  # All commands share an explicit workspace root.

import uvicorn  # Single worker preserves application scheduling ownership.

from .config import load_settings  # Honor .env in UI and scheduled execution alike.
from .diagnostics import diagnostics  # Reuse non-inference capability probes.
from .service import BusyError, Monitor  # Same locks, logs and run lifecycle as the web app.


async def scan_once(root: Path, provider: str | None = None, model: str | None = None) -> int:
    """Global: scheduled/manual terminal scan. Local: wait for one owned job and return its outcome."""
    monitor = Monitor(root)  # Do not start the repeating app scheduler in standalone mode.
    monitor.recover()  # Recover only unowned stale run records.
    settings = load_settings(root)  # Existing native CLI logins remain external to this project.
    changes = {key: value for key, value in {"provider": provider, "model": model}.items() if value is not None}  # Optional command overrides.
    settings = settings.model_copy(update=changes)  # Overrides do not rewrite user preferences.
    try:  # A duplicate external trigger should skip, not queue another scan.
        run = monitor.start_scan(settings)  # Acquire the same cross-process scan lock.
    except BusyError as error:  # Windows task and UI can trigger simultaneously.
        if sys.stdout is not None:  # pythonw.exe has no console stream.
            print(str(error), flush=True)  # Explain a skipped standalone attempt.
        return 0  # Skipping an already-running scan is an operational success.
    watcher = asyncio.create_task(monitor.watch_cancellations())  # Browser can cancel this standalone job.
    try:  # Wait for its final transition without retaining a daemon process.
        await monitor.tasks[run["id"]]  # Service catches workflow errors and records them.
    finally:  # Cancel watcher even if the terminal itself is interrupted.
        await monitor.close()  # Reap any still-owned subprocesses and release locks.
        watcher.cancel()  # No polling should remain after the single scan.
        await asyncio.gather(watcher, return_exceptions=True)  # Consume expected cancellation.
    result = monitor.store.get("run", run["id"])  # Read the committed outcome.
    if sys.stdout is not None:  # Background scheduled runs still have complete log files.
        print(json.dumps(result, ensure_ascii=False), flush=True)  # Preserve the full summary for terminal users.
    return 0 if result["status"] == "completed" else 2  # Partial/failed coverage is actionable to schedulers.


def main() -> None:
    """Global: documented user entrypoint. Local: select server, one-shot scan or diagnostics."""
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):  # Windows consoles need explicit Unicode support.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Preserve all valid emitted Unicode text.
    parser = argparse.ArgumentParser(description="Local Windows/WSL vulnerability monitoring")  # Standard --help works offline.
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Workspace containing .env, data and logs")  # Defaults to this folder.
    commands = parser.add_subparsers(dest="command")  # Running without a subcommand opens the dashboard.
    serve = commands.add_parser("serve", help="Run the local dashboard and configured app timer")  # Main interactive path.
    serve.add_argument("--no-browser", action="store_true", help="Do not automatically open a browser tab")  # Background login task uses this.
    serve.add_argument("--port", type=int, default=8765)  # Host stays fixed to loopback.
    scan = commands.add_parser("scan", help="Run one scan using the same pipeline as the dashboard")  # Task Scheduler entrypoint.
    scan.add_argument("--once", action="store_true", help="Explicitly request one scan (the default)")  # Readable automation command.
    scan.add_argument("--provider", choices=["codex", "claude"])  # Provider override is validated by argparse.
    scan.add_argument("--model", help="Provider-supported model identifier")  # Model names remain unrestricted.
    commands.add_parser("diagnostics", help="Inspect CLI versions without running inference")  # Setup troubleshooting.
    arguments = parser.parse_args()  # Reject unknown options instead of silently ignoring them.
    root = arguments.root.resolve()  # Absolute paths make scheduled execution independent of cwd.
    if not root.is_dir():  # Never create arbitrary requested directories from an invalid argument.
        parser.error("--root must be an existing project directory")  # Immediate actionable error.
    if arguments.command == "scan":  # Single-run automation path.
        raise SystemExit(asyncio.run(scan_once(root, arguments.provider, arguments.model)))  # Return meaningful exit status.
    if arguments.command == "diagnostics":  # Pure inspection path.
        print(json.dumps(asyncio.run(diagnostics(root)), indent=2, ensure_ascii=False))  # No auth secrets are included.
        return  # Do not launch a server after diagnostics.
    from .app import create_app  # Load HTTP/frontend dependencies only for serving.
    port = getattr(arguments, "port", 8765)  # No-subcommand path uses the documented default.
    if not getattr(arguments, "no_browser", False):  # Explicit background tasks never open visible windows.
        import threading  # Delay browser opening until uvicorn can bind its socket.
        timer = threading.Timer(1, webbrowser.open, args=[f"http://127.0.0.1:{port}"])  # Browser is a view, not the scheduler.
        timer.daemon = True  # A failed server start must not leave a helper alive.
        timer.start()  # Open asynchronously without blocking server initialization.
    uvicorn.run(create_app(root), host="127.0.0.1", port=port, workers=1, loop="asyncio", log_config=None if sys.stdout is None else uvicorn.config.LOGGING_CONFIG)  # No reload subprocess or multiple schedulers.
