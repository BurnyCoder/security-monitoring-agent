"""Global: explain missing runtime capabilities. Local: inspect executables without exposing logins.

Sources: https://learn.chatgpt.com/docs/non-interactive-mode and https://code.claude.com/docs/en/headless
"""

import asyncio  # Independent version checks can run together.
from pathlib import Path  # Settings resolve executable paths from the workspace.

from .config import load_settings  # Reuse the exact runtime preferences.
from .process import run_process  # Diagnostics use the same quoting and timeout behavior as scans.


async def diagnostics(root: Path) -> dict:
    """Global: actionable setup status. Local: return versions and concise errors, never auth tokens."""
    settings = load_settings(root)  # Do not dump the process environment or CLI credential files.
    async def inspect(name: str, executable: str) -> tuple[str, dict]:
        """Global: isolate one unavailable executable. Local: bound the probe to fifteen seconds."""
        try:  # One broken provider must not hide the other provider's capability.
            result = await run_process([executable, "--version"], cwd=root, timeout=15)  # No inference or modifications.
            text = (result.stdout or result.stderr).replace("\x00", "").strip()  # WSL may produce UTF-16-like NUL text.
            return name, {"available": result.returncode == 0, "version": text, "executable": executable}  # Names/versions are safe metadata.
        except Exception as error:  # Missing executable or timeout becomes an actionable setup error.
            return name, {"available": False, "error": str(error), "executable": executable}  # No model access is assumed.
    items = await asyncio.gather(inspect("codex", settings.codex_path), inspect("claude", settings.claude_path), inspect("osv", settings.osv_path), inspect("wsl", "wsl.exe"))  # Independent read-only checks.
    return {"tools": dict(items), "authentication": "Uses existing CLI logins. Run codex login status or claude auth status locally to inspect them.", "root": str(root)}  # Browser never receives credential contents.
