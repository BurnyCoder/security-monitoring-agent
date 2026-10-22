"""Global: one process lifecycle for collectors and agents. Local: lossless pipe drains.

Sources: https://docs.python.org/3/library/asyncio-subprocess.html and
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill .
"""

import asyncio  # Keep scans, logging, and cancellation responsive together.
import codecs  # Decode UTF-8 correctly across arbitrary pipe chunk boundaries.
from collections.abc import Callable, Mapping, Sequence  # Shared transport contracts.
from dataclasses import dataclass  # Preserve outputs and status without interpretation.
import os  # Native cancellation and inherited environment.
from pathlib import Path  # Explicit process working directory.
import shutil  # Resolve executable names without a command shell.
import signal  # POSIX process groups receive one owned-tree termination signal.
import subprocess  # Windows creation flags hide noninteractive helper windows.


@dataclass(frozen=True)
class ProcessResult:
    """Global: callers decide whether an exit means findings. Local: retain full outputs."""

    returncode: int  # OS exit status, including OSV's findings-present status.
    stdout: str  # Complete decoded stdout, never clipped for UI convenience.
    stderr: str  # Complete decoded diagnostic stream.


async def _drain(stream: asyncio.StreamReader, kind: str, emit: Callable[[str, str], None] | None) -> str:
    """Global: prevent pipe deadlocks. Local: chunk-read unlimited-length JSON lines."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")  # Split multibyte characters survive.
    chunks: list[str] = []  # Returning full output is part of the collector contract.
    pending = ""  # Emit complete protocol lines without StreamReader.readline's size limit.
    while data := await stream.read(65536):  # Fixed reads bound the transport buffer only.
        text = decoder.decode(data)  # Decoder retains incomplete byte sequences.
        chunks.append(text)  # Do not truncate the raw output.
        pending += text  # A JSON event may be larger than one read.
        while "\n" in pending:  # Preserve event boundaries for provider adapters.
            line, pending = pending.split("\n", 1)  # Retain trailing partial line.
            if emit is not None:  # Collectors can opt out of streaming.
                emit(kind, line + "\n")  # Preserve the original line ending bytes as text.
    tail = decoder.decode(b"", final=True)  # Flush any final decoding state.
    chunks.append(tail)  # Include the EOF suffix in returned output.
    if emit is not None and pending + tail:  # Some commands omit their final newline.
        emit(kind, pending + tail)  # Flush that output instead of losing it.
    return "".join(chunks)  # Joining once avoids quadratic full-output concatenation.


async def _write_stdin(process: asyncio.subprocess.Process, value: str | None) -> None:
    """Global: prompts never enter shell syntax. Local: write UTF-8 and signal EOF."""
    if process.stdin is None:  # The launcher always pipes stdin; retain a clear invariant.
        return  # No interactive prompt is allowed to inherit the app's terminal.
    try:  # A failed CLI can exit before consuming the whole prompt.
        if value is not None:  # None means no supplied input.
            process.stdin.write(value.encode("utf-8"))  # Preserve all prompt characters.
            await process.stdin.drain()  # Apply backpressure while output drains concurrently.
    except (BrokenPipeError, ConnectionResetError):  # Match communicate() early-exit behavior.
        pass  # The return code and diagnostic pipes explain the actual failure.
    finally:  # EOF is necessary for one-shot print/exec operation.
        process.stdin.close()  # Do not leave Claude waiting for another user message.


async def _stop_tree(process: asyncio.subprocess.Process) -> None:
    """Global: cancel this invocation only. Local: terminate its owned descendant tree."""
    if process.returncode is not None:  # Never target a PID after observing its exit.
        return  # Avoid killing a reused process identity.
    if os.name == "nt":  # terminate() alone does not stop Windows descendants.
        killer = await asyncio.create_subprocess_exec("taskkill.exe", "/PID", str(process.pid), "/T", "/F", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)  # Target only our PID tree.
        await killer.wait()  # Let Windows complete child termination before returning.
    else:  # Every child inherits the fresh process group unless it deliberately detaches.
        try:  # The process can finish between the status check and signal.
            os.killpg(process.pid, signal.SIGKILL)  # Kill only the group we created.
        except ProcessLookupError:  # Natural completion already removed the group.
            pass  # No remaining process needs cancellation.
    if process.returncode is None:  # Fallback when taskkill could not stop the parent.
        try:  # A concurrent exit can race this final fallback.
            process.kill()  # Close the owned parent without name-based broad termination.
        except ProcessLookupError:  # The parent already exited.
            pass  # Nothing remains to signal.
    await process.wait()  # Reap the parent and release its process handle.


async def _cleanup(process: asyncio.subprocess.Process, completion: asyncio.Task) -> None:
    """Global: cleanup owns its lifetime. Local: terminate, drain final bytes, and reap."""
    await _stop_tree(process)  # Stop descendants before releasing the scan lock.
    try:  # Preserve diagnostic bytes the CLI wrote immediately before termination.
        await asyncio.wait_for(asyncio.shield(completion), timeout=5)  # Drain EOF without waiting forever on a detached pipe.
    except BaseException:  # A failed callback cannot prevent remaining task cleanup.
        pass  # The outer invocation retains the original error or cancellation.
    completion.cancel()  # A malformed callback must not leave drain tasks running.
    await asyncio.gather(completion, return_exceptions=True)  # Retrieve every lifecycle exception.


async def _reap_uninterrupted(process: asyncio.subprocess.Process, completion: asyncio.Task) -> None:
    """Global: repeated Cancel cannot interrupt cleanup. Local: shield and await its task.

    Source: https://docs.python.org/3/library/asyncio-task.html#shielding-from-cancellation .
    """
    cleanup = asyncio.create_task(_cleanup(process, completion))  # Retain a strong reference independent of caller cancellation.
    while not cleanup.done():  # Repeated caller cancellations still must wait for owned processes.
        try:  # shield protects the cleanup task, while caller cancellation still raises here.
            await asyncio.shield(cleanup)  # Never detach cleanup and return prematurely.
        except asyncio.CancelledError:  # A watcher or shutdown may issue cancel more than once.
            continue  # Keep waiting without forwarding cancellation into cleanup.
    cleanup.result()  # Surface an actual cleanup failure instead of silently orphaning it.


async def run_process(args: Sequence[str], *, cwd: Path, stdin: str | None = None, emit: Callable[[str, str], None] | None = None, cancel: asyncio.Event | None = None, timeout: float = 1800, env: Mapping[str, str] | None = None) -> ProcessResult:
    """Global: shared subprocess facade. Local: launch, stream, await, and clean up.

    Timeout raises TimeoutError; cancellation raises asyncio.CancelledError. Nonzero
    exits return normally because vulnerability scanners use them for findings.
    """
    if not args:  # Empty argv cannot identify an owned process.
        raise ValueError("A process executable is required")  # Fail before spawning anything.
    if cancel is not None and cancel.is_set():  # Do not launch work already cancelled.
        raise asyncio.CancelledError("Process cancelled before launch")  # Preserve scan state.
    executable = shutil.which(str(args[0])) or str(args[0])  # Native Windows requires PATH resolution.
    if os.name == "nt" and Path(executable).suffix.lower() in {".cmd", ".bat", ".ps1"}:  # Batch files reinterpret arguments through shells.
        raise ValueError("Configure a native executable path, not a shell wrapper (.cmd/.bat/.ps1)")  # Keep prompts and model IDs literal.
    options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}  # Isolate process ownership without sandboxing.
    process = await asyncio.create_subprocess_exec(executable, *map(str, args[1:]), cwd=str(cwd), env={**os.environ, **(env or {})}, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, **options)  # Argument arrays avoid a shell.
    async def complete() -> ProcessResult:
        """Global: all pipes progress together. Local: await drains, input, and exit."""
        out, err, _, code = await asyncio.gather(_drain(process.stdout, "stdout", emit), _drain(process.stderr, "stderr", emit), _write_stdin(process, stdin), process.wait())  # No stream can fill while another is read.
        return ProcessResult(code, out, err)  # Return only after final output reaches EOF.
    completion = asyncio.create_task(complete())  # Own a single lifecycle task.
    cancellation = asyncio.create_task(cancel.wait()) if cancel is not None else None  # Optional external cancellation signal.
    watched = {completion, cancellation} if cancellation is not None else {completion}  # Wait only for relevant events.
    try:  # Every exceptional path must clean up the owned child.
        done, _ = await asyncio.wait(watched, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)  # Wall-clock budget includes I/O.
        if cancellation is not None and cancellation in done:  # Explicit cancellation takes priority over simultaneous completion.
            raise asyncio.CancelledError("Process cancelled")  # The caller records cancelled, not failed.
        if completion not in done:  # Neither result nor cancellation arrived within the budget.
            raise TimeoutError(f"Process exceeded {timeout:g} seconds")  # Preserve the configured timeout in diagnostics.
        return completion.result()  # Surface callback failures and transport errors too.
    except BaseException:  # Includes task cancellation, not just ordinary errors.
        await _reap_uninterrupted(process, completion)  # Shield slow tree cleanup against repeated cancellation.
        raise  # Keep the original error type for lifecycle classification.
    finally:  # The event waiter has no useful work once the child finishes.
        if cancellation is not None:  # No waiter was created when cancellation is unused.
            cancellation.cancel()  # Release the Event waiter's task reference.
            await asyncio.gather(cancellation, return_exceptions=True)  # Avoid leaked pending tasks.
