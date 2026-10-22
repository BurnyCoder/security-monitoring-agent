"""Global: verify real process lifecycle. Local: exercise pipes and owned children.

Source: https://docs.python.org/3/library/asyncio-subprocess.html .
"""

import asyncio  # Concurrent cancellation is part of the public launcher contract.
import os  # Select the native process-existence check.
from pathlib import Path  # Keep fixtures inside the repository's pytest directory.
import sys  # Spawn the same interpreter without relying on PATH.

import pytest  # Assertions test behavior rather than private implementation details.

from security_monitoring_agent.process import run_process  # Shared production launcher.


@pytest.mark.asyncio
async def test_large_stdout_and_stderr_are_complete(tmp_path: Path) -> None:
    """Global: logs must not truncate. Local: exceed asyncio's default line limit."""
    events = []  # Retain emitted output independently of the returned buffers.
    script = "import sys; s=sys.stdin.read(); print(s); print('e'*100000, file=sys.stderr)"  # Flood both pipes.
    result = await run_process([sys.executable, "-c", script], cwd=tmp_path, stdin="x" * 100000, emit=lambda *event: events.append(event))  # Exercise real I/O.
    assert result.returncode == 0  # Neither filled pipe deadlocked the child.
    assert result.stdout.strip() == "x" * 100000  # Stdin and stdout remain complete.
    assert result.stderr.strip() == "e" * 100000  # Stderr drains independently.
    assert "".join(text for kind, text in events if kind == "stdout") == result.stdout  # Events preserve exact output.


@pytest.mark.asyncio
async def test_nonzero_exit_and_unterminated_unicode_line(tmp_path: Path) -> None:
    """Global: callers classify exits. Local: preserve UTF-8 at EOF without newline."""
    result = await run_process([sys.executable, "-c", "import sys; sys.stdout.buffer.write('žluťoučký'.encode()); sys.exit(7)"], cwd=tmp_path)  # Do not auto-raise on scanner findings.
    assert (result.returncode, result.stdout) == (7, "žluťoučký")  # Exit and bytes survive.


@pytest.mark.asyncio
async def test_timeout_raises_after_process_cleanup(tmp_path: Path) -> None:
    """Global: a hung CLI cannot block hourly scans. Local: enforce wall-clock timeout."""
    with pytest.raises(TimeoutError):  # Timeout is distinct from provider failure.
        await run_process([sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout=0.15)  # One owned sleeper.


def process_exists(pid: int) -> bool:
    """Global: test only owned PIDs. Local: query native handles without dependencies."""
    if os.name == "nt":  # Windows does not support kill(pid, 0) as POSIX does.
        import ctypes  # Standard library exposes the read-only process-handle API.
        from ctypes import wintypes  # Win32 handles are pointer-sized, not C integers.
        kernel = ctypes.windll.kernel32  # Query only the test's owned process IDs.
        kernel.OpenProcess.restype = wintypes.HANDLE  # Preserve 64-bit handles.
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]  # Declare the real ABI.
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]  # Avoid handle truncation on cleanup.
        handle = kernel.OpenProcess(0x1000, False, pid)  # Query-limited access.
        if not handle:  # The process object has already disappeared.
            return False  # No live process owns this PID.
        code = wintypes.DWORD()  # Windows can retain an exited process object temporarily.
        kernel.GetExitCodeProcess(handle, ctypes.byref(code))  # Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess .
        kernel.CloseHandle(handle)  # Avoid test handle leaks.
        return code.value == 259  # STILL_ACTIVE means running; an open handle alone does not.
    try:  # POSIX signal zero only checks existence.
        os.kill(pid, 0)  # Do not send a real signal.
    except ProcessLookupError:  # The kernel no longer knows this PID.
        return False  # Cleanup succeeded.
    return True  # A live process still owns this PID.


@pytest.mark.asyncio
async def test_cancel_stops_owned_parent_and_child(tmp_path: Path) -> None:
    """Global: Cancel must stop agent tools too. Local: create one owned child tree."""
    cancel = asyncio.Event()  # The UI uses this same cooperative cancellation primitive.
    pids = []  # Only process IDs produced by this test are inspected.
    script = "import subprocess,sys,time,os; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); print(str(os.getpid())+','+str(p.pid),flush=True); time.sleep(30)"  # Parent reports child before sleeping.
    def emit(kind: str, text: str) -> None:
        """Global: synchronize without a race. Local: cancel after both PIDs exist."""
        if kind == "stdout":  # The emitted line contains the two owned PIDs.
            pids.extend(int(value) for value in text.strip().split(","))  # Preserve identities.
            cancel.set()  # Trigger production tree cancellation.
    with pytest.raises(asyncio.CancelledError):  # Cancellation must propagate to scan state.
        await run_process([sys.executable, "-c", script], cwd=tmp_path, emit=emit, cancel=cancel)  # Launch real tree.
    assert len(pids) == 2  # Test actually reached the child-creation stage.
    assert all(not process_exists(pid) for pid in pids)  # No background tool was orphaned.
