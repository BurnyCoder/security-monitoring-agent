# Contributor instructions

Keep the application local, modular, and executable with `uv run security-monitoring-agent`.
Use the shared contracts in `models.py`, the reusable process runner, and one scan pipeline.
Do not execute remediation: findings and chat propose commands for the user to copy.

Use existing Codex/Claude CLI authentication; never copy their credentials into this project.
Keep `.env`, `data/`, `logs/`, `.tools/`, and real device inventories out of Git.
Use synthetic test fixtures and sanitized validation reports for the public repository.

Write focused regression tests before changing evidence classification or lifecycle behavior.
Use source-linked file/function explanations with local and global context and explain non-obvious statements.
Preserve complete timestamped prompts and emitted CLI output in local logs and the terminal.
Do not equate incomplete coverage, a missing KB, or an uninstalled scanner with a clean device.

Update the README for user-facing changes, focused docs for technical details, and reports for validation evidence.
Use functional commits and feature PRs; run the relevant tests before merging.
