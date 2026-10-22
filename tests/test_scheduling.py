"""Global: background startup must preserve this account and root. Local: pure task fixtures.

Source: https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/ .
"""

import json  # Assert structured stdin data rather than shell interpolation.
from pathlib import Path  # Simulated local venv lives inside the pytest fixture.

import pytest  # No test below registers an actual Windows task.

from security_monitoring_agent.models import Settings  # Real user preference contract.
from security_monitoring_agent.process import ProcessResult  # Fake subprocess output.
from security_monitoring_agent.scheduling import build_schedule, configure_schedule, task_name  # Public scheduling boundary.


def fixture_root(tmp_path: Path) -> Path:
    """Global: tests own their files. Local: create a minimal native interpreter fixture."""
    root = tmp_path / "a root with spaces"  # Windows action arguments must quote this path.
    executable = root / ".venv" / "Scripts" / "pythonw.exe"  # Match uv's native venv layout.
    executable.parent.mkdir(parents=True)  # Fixture directories contain no user state.
    executable.touch()  # The pure command builder checks presence, not PE metadata.
    return root  # Each test gets its own scoped root identity.


@pytest.mark.parametrize(("mode", "suffix"), [("login", "serve --no-browser"), ("task", "scan --once")])
def test_task_action_uses_local_venv_and_explicit_root(tmp_path: Path, mode: str, suffix: str) -> None:
    """Global: preserve installed app and authentication. Local: validate action argv."""
    root = fixture_root(tmp_path)  # No global interpreter lookup.
    spec = build_schedule(root, Settings(schedule_mode=mode, interval_minutes=75))  # Pure definition only.
    assert spec["executable"] == str(root / ".venv" / "Scripts" / "pythonw.exe")  # Hidden native Python.
    assert spec["arguments"].startswith('-m security_monitoring_agent --root "')  # Explicit root precedes subcommand.
    assert spec["arguments"].endswith(suffix)  # Correct one-shot or persistent mode.
    assert spec["interval_minutes"] == 75  # User-configured cadence survives.
    assert spec["working_directory"] == str(root.resolve())  # Relative app paths resolve predictably.


def test_task_names_are_stable_and_root_scoped(tmp_path: Path) -> None:
    """Global: don't modify another checkout's task. Local: hash canonical root identity."""
    assert task_name(tmp_path) == task_name(tmp_path / ".")  # Equivalent roots share ownership.
    assert task_name(tmp_path) != task_name(tmp_path / "other")  # Different clones get different tasks.


@pytest.mark.asyncio
async def test_configuration_passes_data_on_stdin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Global: task paths never become PowerShell source. Local: inspect transport inputs."""
    root = fixture_root(tmp_path)  # Root includes whitespace to exercise quoting.
    captured = {}  # Only the transport boundary is mocked.
    async def fake_process(args: list[str], **kwargs) -> ProcessResult:
        """Global: don't register tasks during unit tests. Local: return valid status JSON."""
        captured.update(args=args, **kwargs)  # Capture the actual production script and payload.
        return ProcessResult(0, '{"installed":true,"state":"Ready"}', "")  # Expected cmdlet result.
    monkeypatch.setattr("security_monitoring_agent.scheduling.run_process", fake_process)  # Stub only process launch.
    monkeypatch.setattr("security_monitoring_agent.scheduling.WINDOWS", True)  # Exercise Windows branch on any CI OS.
    result = await configure_schedule(root, Settings(schedule_mode="task"))  # Use the public UI operation.
    script = captured["args"][-1]  # Static command text is the final argument.
    payload = json.loads(captured["stdin"])  # User-specific values arrive as data.
    assert str(root) not in script and payload["working_directory"] == str(root)  # No string-built shell interpolation.
    assert "-LogonType Interactive" in script and "-RunLevel Limited" in script  # Existing current-user credentials only.
    assert "-MultipleInstances IgnoreNew" in script  # Coalesce overlapping scheduler starts.
    assert "-WorkingDirectory $spec.working_directory" in script  # Task Scheduler supplies no useful cwd by default.
    assert result["installed"] is True  # Return useful persisted-task state.


def test_app_mode_removal_does_not_require_venv(tmp_path: Path) -> None:
    """Global: uninstall must work after environment removal. Local: skip action building."""
    spec = build_schedule(tmp_path, Settings(schedule_mode="app"))  # Existing task can outlive a venv.
    assert spec["mode"] == "app" and "executable" not in spec  # Removal only needs ownership identity.


def test_pause_disables_scheduled_scan_trigger(tmp_path: Path) -> None:
    """Global: one pause preference covers all automation. Local: disable task-mode triggers."""
    root = fixture_root(tmp_path)  # Native interpreter path is present for action creation.
    spec = build_schedule(root, Settings(schedule_mode="task", auto_scan=False))  # UI pause must stop external triggers.
    assert spec["disabled"] is True  # Registration persists the paused state.
