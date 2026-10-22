# Security monitoring agent

Local Windows and WSL vulnerability monitoring using Codex or Claude Code.

Implementation is in progress. The application combines observed software inventory,
source-linked web research, and OSV dependency checks. It proposes fixes for the user
to copy; it does not provide an automatic remediation action.

Development: `uv sync`, then `uv run pytest`.

Configuration, raw agent transcripts, and device inventories remain local and are ignored by Git.
