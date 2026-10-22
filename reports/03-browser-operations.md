# Browser and operating workflow checks

Author: Libor Burian. Observed 22 October 2026 using the Codex in-app browser against the actual local FastAPI server. This records manual integration checks, not an exhaustive accessibility, penetration, or cross-browser audit.

## Method and acceptance criteria

Use the real dashboard and live backend. A checked interaction passes when the UI reflects the intended persisted operation and no unintended remediation runs. Check desktop and mobile layouts, real findings, filters, details, copied command acknowledgement, conversation context, reload, and persisted state after server restart. Capture a clean independent workspace for public documentation so the screenshot contains no real device inventory.

## Observations

- The overview rendered at the normal desktop/sidebar width and at a 390-by-844 mobile test viewport. Mobile navigation scrolls horizontally inside its own navigation area; forms and metric cards fit the page. The temporary viewport override was reset.
- After fixing the initial settings-module syntax error, the browser loaded all modules. The strict module checker now parses and links all six modules; a plain Node syntax invocation had failed to catch the browser-module failure in this environment.
- A server restart retained the Luna findings and both provider conversations in SQLite. Reloading a browser during research retained the same running investigation rather than cancelling it. Automated SSE tests separately verify exact replay after an event cursor, including a 100,000-character event.
- The actual provider selector changed Codex to Claude Code and proposed `haiku`. Clicking **Run scan** started the live Haiku run. The button became disabled and **Stop scan** appeared while the scan was active.
- Combining WSL and `ubuntu.com` filters showed the expected four Ubuntu package assessment rows. Adding critical severity displayed **No matching findings**, without asserting the device was safe. Resetting filters restored the matching Windows findings.
- The 7-Zip detail drawer showed its recorded installation, cited version evidence, uncertainties, manual upgrade instructions, elevation requirement, and verification. The separate WSL detail drawer showed uncertain applicability, PowerShell commands, restart effects, and version verification.
- Clicking **Copy** for `wsl --update` changed its button to **Copied**. The application awaited the browser Clipboard API success; the automation bridge's separate clipboard read returned an empty value, so this check does not independently establish system-clipboard contents. No remediation command was executed.
- **Ask an agent about this finding** opened a new scoped conversation. Selecting Claude Code and submitting a question exercised the separate finding-context chat workflow while the full scan remained active. Its provider response is recorded with the live Haiku validation.
- A partial scan initially caused the overview to show a first-scan introduction despite stored results. The overview now displays the latest scan attempt and its outcome separately from the last fully successful scan timestamp.
- The real Settings form saved automatic scanning enabled with a 60-minute interval and app-only mode. The API confirmed the saved configuration and next scan time; optional Windows background modes remained disabled.

## Optional Windows scheduling

During implementation, a temporary disabled application-owned Windows task was registered under the signed-in user's limited interactive principal, inspected, and removed. Account-name normalization required resolving the user SID before the task registration check. This exercised task creation and removal without running an extra periodic scan. It did not simulate logoff/login, reboot, sleep, or a multi-day schedule. Default operation remains the in-process app timer; login and standalone task modes are opt-in.

The native process tests cover process-tree termination, timeout, repeated cancellation, and stdout/stderr draining. Shared-lock tests cover overlapping trigger attempts and recovery of unowned records. These checks are linked from the [automated record](00-automated-validation.md), rather than treated as observed long-duration production uptime.

## Public image and remaining limits

The [README image](../docs/images/dashboard.jpg) was captured from the actual application against a clean local workspace with automatic scans paused. It contains no synthetic findings and no real inventory. The screenshot therefore illustrates the initial state, not the live run's findings.

Browser coverage here does not establish compatibility with every browser, screen reader, clipboard policy, display scale, or task-scheduling account policy. Complete provider output is retained in local logs; the dashboard intentionally shows a bounded activity tail. See [the browser Clipboard API](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText), [FastAPI SSE](https://fastapi.tiangolo.com/tutorial/server-sent-events/), and [the application setup guide](../docs/setup.md).
