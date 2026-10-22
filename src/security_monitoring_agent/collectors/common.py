"""Global: inventory primitives. Local: stable identities and the documented PowerShell JSON boundary.

Sources: https://docs.python.org/3/library/hashlib.html and
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json .
"""

import hashlib  # Stable installation IDs do not depend on Python's randomized hash.
import json  # PowerShell JSON preserves whitespace and Unicode in product names.
from pathlib import Path  # Subprocess working directory stays explicit.

from ..process import run_process  # Shared process lifetime and complete streaming logs.


def asset_id(*parts: str) -> str:
    """Global: identify an occurrence across scans. Local: hash unambiguous JSON identity parts."""
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()[:24]  # Version changes retain the same occurrence ID.


async def powershell_json(script: str, root: Path, emit, timeout: float = 120):
    """Global: reusable Windows collection boundary. Local: execute fixed scripts and decode JSON."""
    prefix = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); $OutputEncoding = [Console]::OutputEncoding; "  # Ensure subprocess UTF-8 output.
    result = await run_process(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefix + script], cwd=root, emit=emit, timeout=timeout)  # Arguments remain separate from shell interpolation.
    if result.returncode != 0:  # Failing scripts are collection errors.
        raise RuntimeError(f"PowerShell exited {result.returncode}: {result.stderr or result.stdout}")  # Preserve diagnostic evidence.
    return json.loads(result.stdout.lstrip("\ufeff"))  # Reject malformed JSON rather than assume empty data.
