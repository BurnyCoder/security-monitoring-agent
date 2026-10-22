# Install and operate the local dashboard

Run Sentinel from a native Windows PowerShell terminal in the cloned repository. The app inspects Windows directly and invokes `wsl.exe` for each installed WSL distribution. Python dependencies live in this repository's `.venv`; an installed CLI and an authenticated account are needed for the provider you select. [Application entry point](../src/security_monitoring_agent/cli.py), [inventory coverage](coverage.md).

## Install tools and sign in

Install missing tools; existing working installations can be reused. These commands follow the upstream [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/), [Claude Code setup guide](https://code.claude.com/docs/en/setup), and [OSV-Scanner installation guide](https://google.github.io/osv-scanner/installation/).

```powershell
winget install --id astral-sh.uv -e
winget install Anthropic.ClaudeCode
winget install Google.OSVScanner
```

For Codex, use the native standalone installer in the [official Windows deployment instructions](https://learn.chatgpt.com/docs/enterprise/windows-deployment). From the repository root, the following saves the installer inside the ignored local tools directory and invokes it:

```powershell
New-Item -ItemType Directory -Force .tools | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri 'https://chatgpt.com/codex/install.ps1' -OutFile '.tools/codex-install.ps1'
powershell -ExecutionPolicy Bypass -File '.tools/codex-install.ps1'
```

Sentinel launches native executables and rejects `.cmd`, `.bat`, and `.ps1` wrappers. If an existing npm installation resolves `codex` to `codex.cmd`, select the underlying native `codex.exe` in **Settings → Advanced executable paths**, or install the standalone CLI. [Process launcher](../src/security_monitoring_agent/process.py). Node.js is needed to run the frontend validation command below; the dashboard itself has no npm build step or frontend package dependencies.

Open a new PowerShell terminal after installation so it receives updated executable paths, return to this repository, and check the tools:

```powershell
uv --version
codex --version
claude --version
osv-scanner --version
```

Authenticate the providers you intend to use, under the same Windows account that will run Sentinel:

```powershell
codex login
codex login status
claude auth login
claude auth status
```

Choose your existing ChatGPT or Claude subscription sign-in in the provider's flow. Sentinel reuses each CLI's login; no API key is required in the project `.env` for this mode. Provider account access and model availability are still determined by the provider. See [Codex CLI authentication options](https://learn.chatgpt.com/docs/cli/reference) and [Claude CLI authentication commands](https://code.claude.com/docs/en/cli-reference). Claude's `--bare` mode is not used because it skips subscription OAuth credentials. [Claude programmatic usage](https://code.claude.com/docs/en/headless).

## Create the local environment

Run these commands from the repository root:

```powershell
uv sync --locked
if (-not (Test-Path -LiteralPath .env)) {
    Copy-Item -LiteralPath .env.example -Destination .env
}
uv run security-monitoring-agent diagnostics
```

`uv sync --locked` installs the committed dependency versions in the local environment. Do not run `uv init` in a clone: the repository already contains its project metadata and lockfile. [uv project synchronization](https://docs.astral.sh/uv/concepts/projects/sync/).

Diagnostics checks executable availability and versions without running an LLM. A successful version probe does not prove authentication or access to a selected model; inspect the CLI login status above and then run an investigation. [Diagnostics implementation](../src/security_monitoring_agent/diagnostics.py).

The example configuration enables hourly automatic scans. Set `SMA_AUTO_SCAN='false'` before starting the app if you want to complete setup before the first provider invocation. Leave this value enabled to start an initial baseline scan when the app has no previous scan. [Scheduler implementation](../src/security_monitoring_agent/service.py).

## Configure `.env` and project scope

Use **Settings** in the dashboard to edit and save preferences, or edit `.env` directly. The tracked `.env.example` is the concise reference for default values. Current app fields are defined by [Settings](../src/security_monitoring_agent/models.py); `.env` persistence is implemented in [config.py](../src/security_monitoring_agent/config.py).

| Variable | Meaning |
| --- | --- |
| `SMA_PROVIDER` | `codex` or `claude`. |
| `SMA_MODEL` | A model identifier accepted by that provider; the lightweight test defaults are `gpt-6-luna` and `haiku`. |
| `SMA_INTERVAL_MINUTES` | Automatic scan interval, from 1 to 10,080 minutes; default 60. |
| `SMA_AUTO_SCAN` | Enable or pause automatic scans. Manual scans remain available. |
| `SMA_NEWS_DAYS` | Discovery window: `1`, `7`, or `30`; existing device findings are not hidden because they are older. |
| `SMA_TIMEOUT_SECONDS` | Agent invocation timeout, from 30 to 14,400 seconds; default 1,800. |
| `SMA_CODEX_PATH`, `SMA_CLAUDE_PATH`, `SMA_OSV_PATH` | Executable names or explicit executable paths when the tools are not on `PATH`. |
| `SMA_SCHEDULE_MODE` | `app`, `login`, or `task`; use the dashboard to register or remove Windows tasks. |
| `SMA_PROJECT_ROOTS` | JSON list of explicit project directories for dependency checks. If omitted or empty, the application workspace is the project scope. |

Example project-scope configuration; replace the example paths and distribution with actual folders you want checked:

```dotenv
SMA_PROJECT_ROOTS='[{"kind":"windows","path":"C:/projects/my-app","distribution":""},{"kind":"wsl","path":"/home/user/my-app","distribution":"Ubuntu"}]'
```

For a WSL project root, install OSV-Scanner v2 **inside that named distribution**, with `osv-scanner` available to `wsl.exe --distribution <name> --exec`. The Windows `SMA_OSV_PATH` setting does not select the Linux scanner. Follow the [official OSV installation methods](https://google.github.io/osv-scanner/installation/) for the distribution; release binaries are available for Linux and Windows. The app reports a project coverage error if the required scanner is missing. [Dependency scanner implementation](../src/security_monitoring_agent/intelligence/dependencies.py).

WSL operating-system and package inventory does not require a separate Codex or Claude installation inside each distribution. Windows and WSL CLI logins are distinct environments; this application launches the configured Windows agent CLI. Use `wsl --list --verbose` to inspect installed distribution names. [Microsoft WSL commands](https://learn.microsoft.com/en-us/windows/wsl/basic-commands), [collector implementation](../src/security_monitoring_agent/collectors/wsl.py).

## Start, scan, and stop

Start the dashboard and open its browser tab:

```powershell
uv run security-monitoring-agent serve
```

The server listens on [127.0.0.1:8765](http://127.0.0.1:8765). Use `serve --no-browser` to avoid opening a tab, or `serve --port 8766` to select another local port. Closing a browser tab leaves the server and its app timer running. Stop a foreground server with `Ctrl+C`; the service cancels its owned jobs and records interrupted work rather than reporting an empty successful scan. [CLI](../src/security_monitoring_agent/cli.py), [service lifecycle](../src/security_monitoring_agent/service.py).

**Run scan** uses the currently selected provider, model, and news window. These quick controls override the next manual scan; **Settings → Save settings** changes the defaults used by scheduled scans. Proposed fixes can be inspected and copied from a finding's detail panel. The UI does not execute remediation commands. [Frontend workflow](../src/security_monitoring_agent/static/app.js), [finding details](../src/security_monitoring_agent/static/views.js).

The same pipeline is available as a one-shot command:

```powershell
uv run security-monitoring-agent scan --once --provider codex --model gpt-6-luna
uv run security-monitoring-agent scan --once --provider claude --model haiku
```

Each command uses the selected provider's account. Use any provider-supported model identifier with `--model`; availability errors remain visible in the run history and log. The standalone command exits with `0` for a completed scan or an already-running scan that it skips, and `2` for an incomplete or failed result. [One-shot implementation](../src/security_monitoring_agent/cli.py).

## Choose an automatic schedule

Select a mode in **Settings → Scan schedule**, then save:

| Mode | Actual behavior |
| --- | --- |
| While the app is running (`app`) | The running server owns the timer. No Windows task is required. Returning to this mode removes the task owned by this checkout. |
| Start the dashboard at Windows login (`login`) | Registers an at-logon task for the current Windows user. It starts the local server without a browser or console window; the server's timer performs scans. |
| Windows scheduled scans (`task`) | Registers a repeating one-shot scan task. The server's own recurring timer is disabled in this mode; the dashboard reads results from the same local database. |

Both Windows task modes run as the current user with an interactive logon and without elevation or a stored password. The user must be signed in; these modes do not provide logged-out system-service monitoring. Tasks use this clone's `.venv`, so moving or deleting the clone or its environment breaks that registered action. Before moving a clone, switch to `app` mode and save to remove its owned task. At the restored/new location, save `app` mode, then select and save the desired background mode so task registration actually runs; saving unchanged settings alone does not re-register a task. [Task registration implementation](../src/security_monitoring_agent/scheduling.py), [settings reconciliation](../src/security_monitoring_agent/app.py), [Microsoft Task Scheduler cmdlets](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/).

Pausing automatic scans disables the recurring scan task in `task` mode and pauses the app timer in `app`/`login` modes. A login task may still start the dashboard while automatic scans are paused. Changing `.env` alone does not register or replace a Windows task; save settings through the dashboard to apply task integration. [Schedule configuration](../src/security_monitoring_agent/scheduling.py).

The app coalesces missed intervals into one due scan rather than replaying every missed hour. Windows tasks use `IgnoreNew`, and a cross-process scan lock prevents the dashboard and a scheduled scan from running duplicate device scans. A follow-up conversation has its own lock and can run alongside a scan. [Service locks and scheduling](../src/security_monitoring_agent/service.py), [Microsoft multiple-instance policy](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-multipleinstancespolicy-settingstype-element).

## Validate and troubleshoot

```powershell
uv run pytest
node --experimental-vm-modules scripts/check_frontend.mjs
```

The frontend check uses only Node's built-in modules. It strictly parses and links the browser's ECMAScript modules without evaluating DOM or network code. It detects malformed syntax, missing relative imports, and unavailable named exports; actual browser interaction is a separate check. [Validation script](../scripts/check_frontend.mjs), [Node SourceTextModule](https://nodejs.org/api/vm.html#class-vmsourcetextmodule).

- If an executable is missing, reopen PowerShell after installation or set its explicit path under **Settings → Advanced executable paths**. Re-run diagnostics.
- If provider authentication or model access fails, use the provider's native login/status commands, then repeat a manual scan with an available model. A CLI version probe alone cannot validate access.
- If a WSL distribution or project cannot be inspected, read its **Device inventory → Collection coverage** entry. A failed collector is an unknown coverage area, not evidence that no vulnerabilities exist.
- If the shell loads but dashboard content does not, open the browser developer console and run the strict frontend check above.
- Use **Scan history → Download full log** for complete prompts, outputs, and errors. Runtime evidence stays under local `data/` and `logs/`; `.env` and these runtime directories are excluded from Git. [Logging](../src/security_monitoring_agent/runlog.py), [Git exclusions](../.gitignore).

See [coverage.md](coverage.md) for the interpretation limits of Windows patch evidence, WSL packages, and project dependency findings. This setup guide describes execution; it does not establish detection accuracy or claim that an empty scan proves the device is safe.
