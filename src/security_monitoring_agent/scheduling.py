"""Global: optional same-user Windows scheduling. Local: register only this root's task.

Sources: https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/ and
https://docs.python.org/3/library/subprocess.html#subprocess.list2cmdline .
"""

import hashlib  # Stable root identities keep different clones' tasks separate.
import json  # User paths cross the PowerShell boundary as stdin data.
import os  # Select Windows integration without invoking it on other platforms.
from pathlib import Path  # The task launches this checkout's uv environment.
import subprocess  # Quote Windows process arguments according to the CRT convention.

from .models import Settings  # Scheduling uses the same user-visible configuration.
from .process import run_process  # Reuse hidden launch, pipe draining, and timeout cleanup.

WINDOWS = os.name == "nt"  # Keep platform selection explicit and testable.

# Global: one static management program; local: JSON stdin prevents path interpolation.
SCHEDULE_SCRIPT = r"""
# Source: https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/ .
$ErrorActionPreference = 'Stop' # Fail registration instead of silently claiming success.
$ProgressPreference = 'SilentlyContinue' # Keep stdout a single machine-readable result.
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new() # Match Python's UTF-8 stdin.
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new() # Preserve Unicode paths in results.
try {
    $spec = [Console]::In.ReadToEnd() | ConvertFrom-Json # Parse values as data, never commands.
    $ownerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value # Reuse this signed-in account.
    $existing = Get-ScheduledTask -TaskName $spec.task_name -TaskPath '\' -ErrorAction SilentlyContinue # Look up only our exact name.
    $existingSid = $null # No ownership comparison is needed for an absent task.
    if ($existing) {
        $identity = $existing.Principal.UserId # Task Scheduler may normalize a SID to an account name.
        $existingSid = if ($identity -match '^S-1-') { $identity } else { ([System.Security.Principal.NTAccount]::new($identity)).Translate([System.Security.Principal.SecurityIdentifier]).Value } # Compare canonical SIDs, not display names.
    }
    if ($existing -and ($existing.Description -ne $spec.description -or $existingSid -ne $ownerSid)) {
        throw 'The matching task is not owned by this root and current user; it was left unchanged.' # Never replace unrelated automation.
    }
    if ($spec.mode -eq 'status') {
        $state = if ($existing) { [string]$existing.State } else { 'Absent' } # Read-only inspection.
        @{mode='status';task_name=$spec.task_name;installed=[bool]$existing;state=$state;detail='Interactive current-user task status'} | ConvertTo-Json -Compress # Return registration evidence.
        exit 0 # Status must not pass into the mutation branches.
    }
    if ($spec.mode -eq 'app') {
        if ($existing) { Unregister-ScheduledTask -InputObject $existing -Confirm:$false } # Remove only the verified owned definition.
        @{mode='app';task_name=$spec.task_name;installed=$false;state='Absent';detail='Automatic scans run while the dashboard is open'} | ConvertTo-Json -Compress # Existing app process is unaffected.
        exit 0 # No executable or trigger is needed for removal.
    }
    $action = New-ScheduledTaskAction -Execute $spec.executable -Argument $spec.arguments -WorkingDirectory $spec.working_directory # Absolute local venv and root.
    $principal = New-ScheduledTaskPrincipal -UserId $ownerSid -LogonType Interactive -RunLevel Limited # No stored password, SYSTEM identity, or elevation.
    if ($spec.mode -eq 'login') {
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $ownerSid # Start the dashboard at this user's next sign-in.
        $limit = [TimeSpan]::Zero # A dashboard remains running until the user closes it.
    } else {
        $interval = New-TimeSpan -Minutes $spec.interval_minutes # Respect the user-selected interval.
        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).Add($interval)) -RepetitionInterval $interval # Omitted duration repeats indefinitely.
        $limit = New-TimeSpan -Seconds ($spec.timeout_seconds + 300) # Allow inventory and persistence around the agent budget.
    }
    $options = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit $limit -Hidden # Coalesce missed or overlapping starts.
    if ($spec.disabled) { $options.Enabled = $false } # Validation can register a task that cannot launch.
    $registered = Register-ScheduledTask -TaskName $spec.task_name -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $options -Description $spec.description -Force # Update only after ownership verification.
    @{mode=$spec.mode;task_name=$spec.task_name;installed=$true;state=[string]$registered.State;detail='Runs as the current user while signed in; existing CLI login is reused'} | ConvertTo-Json -Compress # Report verified registration state.
} catch {
    [Console]::Error.WriteLine($_.Exception.Message) # Preserve an actionable Task Scheduler diagnostic.
    exit 1 # The UI must not save an unsuccessful background configuration.
}
"""


def task_name(root: Path) -> str:
    """Global: scope automation to this checkout. Local: hash a canonical Windows root."""
    identity = str(root.resolve()).casefold()  # Windows paths are normally case-insensitive.
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]  # Stable, task-name-safe identity.
    return f"SecurityMonitoringAgent-{suffix}"  # No wildcard characters or user-controlled task names.


def build_schedule(root: Path, settings: Settings) -> dict:
    """Global: make configuration reviewable. Local: produce a plain task specification."""
    root = root.resolve()  # Task working directory and --root use the same absolute path.
    spec = {"mode": settings.schedule_mode, "task_name": task_name(root), "description": f"Security Monitoring Agent | {root}", "working_directory": str(root), "interval_minutes": settings.interval_minutes, "timeout_seconds": settings.timeout_seconds, "disabled": settings.schedule_mode == "task" and not settings.auto_scan}  # Pause applies to external scans too; no credentials enter tasks.
    if settings.schedule_mode == "app":  # Returning to app-only mode removes the owned task.
        return spec  # Removal remains possible after the virtual environment disappears.
    executable = root / ".venv" / "Scripts" / "pythonw.exe"  # Native windowless Python prevents a console at login.
    if not executable.is_file():  # A non-Windows test environment may only provide python.exe.
        executable = executable.with_name("python.exe")  # Documented fallback still uses the local venv.
    if not executable.is_file():  # Task Scheduler does not validate executable availability itself.
        raise FileNotFoundError("Run uv sync in this repository before enabling Windows scheduling")  # Give a replicable setup step.
    action = ["-m", "security_monitoring_agent", "--root", str(root)]  # Explicit root precedes the CLI subcommand.
    action.extend(["serve", "--no-browser"] if settings.schedule_mode == "login" else ["scan", "--once"])  # Background dashboard or one scan per trigger.
    spec.update(executable=str(executable), arguments=subprocess.list2cmdline(action))  # Quote argument values for Windows process parsing.
    return spec  # Registration and tests consume the identical definition.


async def _apply(root: Path, spec: dict) -> dict:
    """Global: one management transport. Local: execute static PowerShell with JSON stdin."""
    result = await run_process(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", SCHEDULE_SCRIPT], cwd=root, stdin=json.dumps(spec, ensure_ascii=False), timeout=60)  # No dynamic values enter shell source.
    if result.returncode != 0:  # Permission policy or scheduler errors are not successful saves.
        raise RuntimeError(f"Windows scheduling failed: {result.stderr.strip() or result.stdout.strip()}")  # Retain complete cmdlet diagnostics.
    try:  # Read only the single machine-readable status object.
        status = json.loads(result.stdout.lstrip("\ufeff"))  # Windows PowerShell may prefix a UTF-8 BOM.
    except json.JSONDecodeError as error:  # Unexpected output must not become false success.
        raise RuntimeError(f"Windows scheduling returned invalid output: {result.stdout}") from error  # Expose full diagnostic output.
    if not isinstance(status, dict):  # UI expects named state fields.
        raise RuntimeError("Windows scheduling returned no task status object")  # Reject incompatible output.
    return status  # Caller persists settings only after this successful operation.


async def configure_schedule(root: Path, settings: Settings) -> dict:
    """Global: UI-triggered integration only. Local: register, replace, or remove our task."""
    if not WINDOWS:  # Normal app scheduling remains available on other operating systems.
        if settings.schedule_mode == "app":  # No Windows cleanup is necessary off Windows.
            return {"mode": "app", "installed": False, "state": "Unsupported", "detail": "Windows task integration is unavailable on this platform"}  # Honest platform status.
        raise RuntimeError("Login and scheduled-task modes require native Windows")  # Never claim a task was installed.
    return await _apply(root.resolve(), build_schedule(root, settings))  # No registration occurs merely by importing this module.


async def schedule_status(root: Path) -> dict:
    """Global: distinguish preferences from actual registration. Local: query only our task."""
    if not WINDOWS:  # Avoid invoking nonexistent PowerShell on Linux-only hosts.
        return {"mode": "app", "installed": False, "state": "Unsupported"}  # The UI can explain platform support.
    spec = build_schedule(root, Settings(schedule_mode="app"))  # Status needs ownership identity only.
    spec["mode"] = "status"  # The static script exits before any mutation.
    return await _apply(root.resolve(), spec)  # Reuse the same verified owner check.
