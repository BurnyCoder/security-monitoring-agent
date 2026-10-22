# Validation records

Author: Libor Burian. These are engineering integration experiments on one Windows machine with one Ubuntu WSL distribution. They do not estimate vulnerability-detection accuracy or compare provider quality.

| Record | Question | Evidence |
| --- | --- | --- |
| [Automated validation](00-automated-validation.md) | Do parsing, applicability boundaries, storage, cancellation, replay, and scheduling behave as specified? | Synthetic fixtures and native subprocess tests; strict frontend module checks. |
| [Luna scan and provider conversations](01-live-validation.md) | Do actual CLI logins, live research, structured results, and explicit session resume work? | Local transcript/database comparisons, representative official-source checks, and recorded corrections. |
| [Haiku full scan](02-haiku-scan.md) | Can the second provider complete the same inventory-to-dashboard workflow? | Independent live run through the dashboard; coverage and source review. |
| [Browser and operations](03-browser-operations.md) | Can a user navigate findings, copy proposed commands, reconnect, and inspect settings? | Actual local browser interactions, responsive views, restart, and scheduling checks. |
| [Primary-source regression](04-primary-source-regression.md) | Can contradictory Microsoft WSL ranges automatically qualify definitive claims? | Fixture tests plus a live-source replay of the unchanged Haiku result. |
| [Concise report source](validation-summary.md) / [PDF](validation-report.pdf) | What do these observations establish, and what remains untested? | Sanitized synthesis with explicit limits. |

## Terms and scope

- **Inventory:** software/version facts collected from the device; it is not a list of every running component.
- **Advisory:** a vulnerability report with identifiers, source links, and dates. **CVE** is a vulnerability identifier; **KEV** is CISA's known-exploited catalog.
- **Finding:** one advisory assessed against one particular installation or recorded project dependency.
- **OSV-Scanner:** the maintained dependency scanner that reads supported project artifacts and queries vulnerability records.
- **Backport:** a fix applied to a distribution's existing package version; an upstream version alone can misclassify it.
- **Partial:** an objective collection, research, or validation gap occurred. **Completed** describes workflow completion, not a device safety guarantee.
- **SSE:** server-sent events; the browser resumes the persisted event sequence using its last received cursor.

| Requested model | Execution interface | Architecture/training | Objective in these records | Evaluation limit |
| --- | --- | --- | --- | --- |
| `gpt-6-luna` | Codex CLI JSONL and final JSON schema | Not inspected or trained in this project | Research and explain inventory-specific evidence | One live scan plus scoped chats; no measured precision/recall. |
| `haiku` | Claude Code stream JSON and structured result | Not inspected or trained in this project | Same integration contract | Actual resolved model is recorded when emitted; no controlled provider comparison. |

There are no training datasets, learned weights, fine-tuning hyperparameters, seed sweeps, or Hugging Face model uploads in this implementation. Selecting sources for spot checks after reading model output is explicitly retrospective. It does not support p-values, confidence intervals, population accuracy, or causal claims. Unit-test pass counts measure the specified software checks only.

To regenerate the PDF after editing its Markdown source:

```powershell
uv sync --locked --group docs
uv run --group docs python scripts/build_report.py
```

Inspect rendered pages after regeneration. Raw transcripts and inventory snapshots stay under ignored `logs/` and `data/`; only sanitized results belong here.
