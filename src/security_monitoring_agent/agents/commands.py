"""Global: isolate provider CLI syntax. Local: build literal argv without shell code.

Sources: https://code.claude.com/docs/en/cli-reference and
https://developers.openai.com/codex/cli/reference ; flags checked against local help.
"""

import json  # Inline settings and schema must be serialized as single argv entries.
from pathlib import Path  # Codex reads schema and final-output artifact paths.

from ..models import Settings  # User can choose any provider-supported model ID.


def command(settings: Settings, directory: Path, schema: dict | None, session_id: str | None) -> list[str]:
    """Global: honor configured unrestricted CLIs. Local: choose fresh versus explicit resume."""
    if settings.provider == "claude":  # Retain normal subscription login; do not use --bare.
        args = [settings.claude_path, "-p", "--model", settings.model, "--dangerously-skip-permissions", "--settings", '{"sandbox":{"enabled":false}}', "--output-format", "stream-json", "--verbose", "--include-partial-messages", "--forward-subagent-text"]  # Enable complete streaming and requested permissions.
        if schema is not None:  # Scan results must follow the shared investigation shape.
            args.extend(["--json-schema", json.dumps(schema)])  # One literal argument, never shell-escaped text.
        if session_id:  # Chats may resume only their explicitly stored session.
            args.extend(["--resume", session_id])  # Avoid unrelated conversation history.
        return args  # Prompt is delivered through stdin by the shared runner.
    args = [settings.codex_path, "exec"]  # Fresh sessions are the default for scans.
    if session_id:  # Resume has fewer accepted switches than exec.
        args.append("resume")  # Use only options confirmed by exec resume --help.
    args.extend(["--model", settings.model, "--dangerously-bypass-approvals-and-sandbox", "--config", 'web_search="live"', "--json", "--skip-git-repo-check", "--output-last-message", str(directory / "final.txt")])  # Live search and native final artifact.
    if schema is not None:  # Codex expects its schema in a file instead of inline JSON.
        schema_path = directory / "schema.json"  # Invocation-private file inside the workdir.
        schema_path.write_text(json.dumps(schema), encoding="utf-8")  # Preserve the supplied domain contract.
        args.extend(["--output-schema", str(schema_path)])  # Flag also exists on resume.
    if session_id:  # Positional identity must precede the stdin prompt marker.
        args.append(session_id)  # Do not use --last or scan other sessions.
    args.append("-")  # Explicitly consume prompt bytes from stdin.
    return args  # No shell is involved in invocation.
