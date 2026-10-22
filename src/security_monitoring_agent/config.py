"""Global: configuration stays local. Local: atomically persist only named app settings.

Sources: https://bbc2.github.io/python-dotenv/ and https://docs.python.org/3/library/os.html#os.replace
"""

import json  # Lists of explicit project roots are serialized without inventing a path format.
import os  # Environment variables support unattended CLI launches.
import tempfile  # A same-directory temporary file makes replacement atomic.
from pathlib import Path  # Resolve everything relative to the selected workspace.

from dotenv import dotenv_values, set_key  # Use the maintained dotenv parser and quoting rules.

from .models import ProjectRoot, Settings  # One contract validates both UI and disk settings.


def load_settings(root: Path) -> Settings:
    """Global: use the workspace configuration. Local: .env overrides process defaults."""
    values = {**os.environ, **dotenv_values(root / ".env")}  # UI changes must survive restarts.
    fields = {}  # Ignore unrelated credentials instead of reflecting them to the browser.
    for name in Settings.model_fields:  # The allowlist comes directly from the public contract.
        value = values.get(f"SMA_{name.upper()}")  # Prefix avoids collisions with OS variables.
        if value is not None:  # Missing values retain the documented default.
            fields[name] = json.loads(value) if name == "project_roots" else int(value) if name == "news_days" else value  # Numeric Literals require exact integers.
    fields.setdefault("project_roots", [ProjectRoot(path=str(root))])  # Never discover other projects.
    return Settings.model_validate(fields)  # Invalid settings produce a visible validation error.


def save_settings(root: Path, settings: Settings) -> None:
    """Global: durable preferences without partial writes. Local: preserve unrelated dotenv keys."""
    destination = root / ".env"  # No credentials or settings go into tracked files.
    descriptor, temporary = tempfile.mkstemp(prefix=".env.", suffix=".tmp", dir=root)  # Same volume.
    os.close(descriptor)  # dotenv opens the temporary path itself.
    path = Path(temporary)  # Keep cleanup explicit even when replacement fails.
    try:  # A failed edit must leave the original configuration intact.
        if destination.exists():  # Preserve comments and user-added keys.
            path.write_text(destination.read_text(encoding="utf-8"), encoding="utf-8")  # Local only.
        for name, value in settings.model_dump().items():  # Serialize exactly the known settings.
            serialized = json.dumps(value) if isinstance(value, (list, bool)) else str(value)  # dotenv text.
            set_key(path, f"SMA_{name.upper()}", serialized, quote_mode="always")  # Library handles escaping.
        os.replace(path, destination)  # Readers see either the old complete file or the new one.
    finally:  # A temporary file must not remain after an unsuccessful update.
        path.unlink(missing_ok=True)  # Replacement already removed it on success.
