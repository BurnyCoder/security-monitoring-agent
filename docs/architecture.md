# Architecture and interfaces

This document describes the implemented local application. [Setup](setup.md) covers installation and configuration values; [coverage](coverage.md) explains the inventory sources, dependency matching, and their limits. Live-run observations belong in the reports rather than being treated as guarantees of detection accuracy.

## One workflow, several entry points

The application uses one FastAPI/Uvicorn process, SQLite, browser JavaScript modules, and native CLI subprocesses. There is no frontend build server, remote application backend, message broker, or remediation executor. The server binds to `127.0.0.1`; browser requests submit work to a service whose lifetime is independent of the browser connection. See [CLI startup](../src/security_monitoring_agent/cli.py), [HTTP application](../src/security_monitoring_agent/app.py), and [service coordinator](../src/security_monitoring_agent/service.py).

`pipeline.run_scan()` is the orchestration wrapper. Its imported phases perform these operations:

1. Collect Windows and WSL facts, preserving per-component coverage, and save the inventory immediately.
2. Fetch CISA intelligence and scan explicitly configured project roots with OSV-Scanner. Add dependency assets and save validated deterministic findings before starting the model.
3. Write the complete `inventory.json` and `intelligence.json` into that run's workspace. Build a compact prompt that refers to these full files, then invoke the selected agent with the `Investigation` JSON Schema.
4. Validate the final response, bind findings to observed asset IDs, reject uncited news, resolve advisory references, and persist the accepted records.
5. Mark the run `completed` or `partial`, retaining its summary, session identity, observed model when available, and observed web-search count.

Manual scans, the in-process timer, and `scan --once` all use this pipeline through `Monitor.start_scan()`. Chats use the same provider runner and persistence infrastructure, with a separate context and an explicit saved provider session. The model's requested task is inspection, research, and proposed commands/manual steps; the dashboard exposes commands for copying and does not execute fixes. These boundaries are in [pipeline.py](../src/security_monitoring_agent/pipeline.py) and [prompts.py](../src/security_monitoring_agent/prompts.py).

The web-research checkpoint advances only after a validated response with an observed search-tool event. Subsequent research uses a 24-hour overlap, bounded by the selected news window. The news endpoint filters advisory dates; it does not filter unresolved device findings. A run is `partial` when collection is incomplete, no web-search event is observed, structural output is rejected or downgraded, or the Microsoft WSL primary-range check finds unresolved evidence. This classification does not prove that the model inspected every asset.

## Evidence and persistence

[models.py](../src/security_monitoring_agent/models.py) defines Pydantic objects that forbid unknown fields. Their roles are:

| Contract | Meaning |
| --- | --- |
| `Settings`, `ProjectRoot` | Provider/model, cadence, operational limits, executable paths, and explicitly selected native/WSL project roots |
| `Asset`, `Inventory`, `Coverage` | Observed identity/version/location, a timestamped snapshot, and `ok`/`partial`/`error`/`unsupported` collection outcomes |
| `Advisory`, `Source` | Vulnerability intelligence, distinct publication/modification/KEV dates, and supporting HTTP(S) URLs |
| `Finding` | One advisory assessed against one asset, with `affected`, `potentially_affected`, `not_affected`, or `unknown` applicability |
| `Remediation` | Proposed steps/commands, shell context, elevation/reboot requirements, and verification guidance |
| `Investigation` | Final model summary, advisories, findings, and coverage notes |
| `RunEvent` | Complete event text, kind, timestamp, run identity, and durable replay cursor |

[api_models.py](../src/security_monitoring_agent/api_models.py) adds named response models for run lifecycle, persisted findings/inventory, dashboard status, and conversations. FastAPI validates these responses and exposes their schemas in `/openapi.json`. SSE payloads are validated as `RunEvent` before transport framing. `GET /api/advisories?news_days=1`, `7`, or `30` overrides the news view without mutating saved settings; omitting it uses the saved default.

The provider schema makes every declared object property required, rejects additional properties, and removes JSON Schema defaults; nullable properties remain explicitly nullable. Runtime validation still uses the original Pydantic models. [Pydantic's model documentation](https://docs.pydantic.dev/latest/concepts/models/) describes the underlying validation behavior.

[evidence.py](../src/security_monitoring_agent/evidence.py) is a structural gate, not an independent factual verifier. It rejects findings for unknown asset IDs and downgrades definitive assessments that lack citations or observed evidence. A separate narrow [Microsoft WSL check](../src/security_monitoring_agent/intelligence/wsl_primary.py) retrieves primary CNA records for definitive WSL-platform CVE claims and qualifies conflicting numeric bounds or unavailable primary evidence. It does not match installed versions or prove unaffectedness. The application does not verify every citation, prove all affected-version predicates, or establish exploitability; see [coverage](coverage.md).

[storage.py](../src/security_monitoring_agent/storage.py) stores JSON documents in an `objects` table, advisory aliases in an `aliases` table, and complete stream records in an append-only `events` table. SQLite uses WAL and short transactions; no model invocation or network request runs inside a transaction. Advisory merges retain source URLs, the strongest observed exploitation category, established dates, and aliases. Unambiguous equivalent advisories and their finding identities are consolidated atomically; notices spanning multiple CVEs remain separate. Finding IDs derive from the canonical advisory plus asset ID, so separate installations remain separate occurrences. Consolidation retains the most recent assessment and its original freshness timestamps. A missing finding in a later run is retained and displayed as stale when its run differs from the latest inventory; it is not silently marked fixed. See [SQLite transaction behavior](https://docs.python.org/3/library/sqlite3.html).

Runtime paths under the selected root are:

| Path | Stored data |
| --- | --- |
| `.env` | Named application preferences plus preserved unrelated user entries |
| `data/monitor.sqlite3` | Inventories, advisories, findings, runs, chats, checkpoints, and stream events |
| `data/runs/<run-id>/` | Prepared evidence files for one scan |
| `data/chats/<chat-id>/` | The latest inventory supplied to that conversation |
| `data/*.lock` | OS-backed scan and per-chat ownership locks |
| `logs/<timestamp-and-id>.jsonl` | Complete application prompts and emitted process/event records |

These paths are ignored by Git. Temporary provider schema/final-message files are created inside the invocation workspace and removed after parsing. Native Codex/Claude session history remains managed by those CLIs; removing the application's temporary files does not remove provider-managed history.

## Provider invocation and logs

[agents/runner.py](../src/security_monitoring_agent/agents/runner.py) exposes the shared asynchronous boundary:

```python
await run_agent(settings, prompt, workdir, emit, cancel, schema=None, session_id=None)
# AgentResult(text, structured, session_id, model, web_searches)
```

`emit(kind, text)` is synchronous. The runner emits the complete application prompt, raw stdout/stderr lines, derived progress/text events, and the complete final result. It passes prompts through stdin and uses an argument array rather than interpolating them into a shell command. Windows tool paths must resolve to native executables; `.cmd`, `.bat`, and `.ps1` wrappers are rejected because they reinterpret arguments through a shell. Scan invocations start fresh; chat turns resume only the exact stored session ID. Provider/model selections remain fixed for an existing chat. Arbitrary model strings are passed to the selected CLI, whose account and backend decide availability.

| Provider | Implemented command behavior |
| --- | --- |
| Codex | `exec`, `--model`, `--dangerously-bypass-approvals-and-sandbox`, `--config web_search="live"`, `--json`, `--skip-git-repo-check`, and `--output-last-message`; scans add `--output-schema`; chat follow-ups use `exec resume <session-id> -` |
| Claude Code | `-p`, `--model`, `--dangerously-skip-permissions`, `--settings {"sandbox":{"enabled":false}}`, `--output-format stream-json`, `--verbose`, `--include-partial-messages`, and `--forward-subagent-text`; scans add `--json-schema`; follow-ups add `--resume <session-id>` |

The implementation uses the installed CLI's normal authentication and inherited environment. It does not copy credentials into `.env`, request an API key, or log authentication files. Claude's `--bare` is deliberately absent because that mode does not reuse subscription OAuth authentication. The command construction is documented against the official [Codex noninteractive interface](https://developers.openai.com/codex/noninteractive), [Claude CLI reference](https://code.claude.com/docs/en/cli-reference), and [Claude headless interface](https://code.claude.com/docs/en/headless).

The application adds no CLI sandbox or approval layer. The task instructions still limit what the agent is asked to do. Provider policies, managed settings, model availability, web-tool availability, and operating-system permissions continue to apply. Claude's native Windows shell commands are unsandboxed; WSL/Linux sandbox settings are separate from permission modes. See [Claude sandbox behavior](https://code.claude.com/docs/en/sandboxing) and [permission modes](https://code.claude.com/docs/en/permission-modes).

[agents/events.py](../src/security_monitoring_agent/agents/events.py) ignores unknown/non-object events. Codex requires a completed turn and uses the native final-message file when present; schema output is parsed as a whole JSON object. Claude requires a terminal `result` and, for scans, its `structured_output` object. Nonzero exits, failed turns, missing final events, and missing required structured output are failures, not clean-device results. Search counts deduplicate emitted search-tool IDs; they are not counts of backend queries. `AgentResult.model` records emitted model metadata only and can be null.

[runlog.py](../src/security_monitoring_agent/runlog.py) timestamps each record, appends it to JSONL, persists it to SQLite, and prints it to an attached terminal. There is no payload truncation in this path. The browser renders a recent event tail and offers the complete log separately. Repeated raw and derived events are intentional: the raw protocol remains available for auditing.

The logging guarantee covers the supplied application prompt and what the CLI emits. It cannot expose provider-internal prompts, un-emitted reasoning, redacted content, or raw web pages that a provider tool only summarizes. Pipe bytes are decoded as UTF-8 with replacement for invalid sequences; the application does not retain a separate binary stream. The process result also buffers complete stdout/stderr, so memory use grows with emitted output. Logs and local inventory can contain sensitive device facts and model/tool output; Git ignores them, but there is no automatic log retention policy or content-redaction layer.

## Lifecycle, cancellation, and configuration

`data/scan.lock` is acquired nonblocking before a scan record is created. Manual, timer, and standalone attempts therefore share one scan owner. A collision returns HTTP 409 to the UI; standalone `scan --once` reports a skip and exits zero. Each chat has its own lock, so chats are serialized individually and may run alongside a scan. SQLite transactions remain independent of these long-lived locks. [Portalocker](https://portalocker.readthedocs.io/) provides the cross-process lock implementation.

The in-process scheduler reloads settings and checks for due work every five seconds. A fresh automatically enabled workspace starts a baseline scan. Later cadence is based on the last scan attempt's start time, including failed attempts; missed intervals coalesce instead of accumulating jobs. Pausing disables automatic launches. Closing the browser only disconnects its view; stopping the server cancels its owned work. Run outcomes are `running`, `completed`, `partial`, `failed`, `cancelled`, or `interrupted`; recovery also recognizes legacy/queued active records.

Cancellation is stored on the run record, with a one-second watcher allowing the UI to cancel an independently running standalone job. Local owners also receive an immediate event/task cancellation. Repeated cancellation requests do not interrupt cleanup. [process.py](../src/security_monitoring_agent/process.py) drains both pipes concurrently using chunked reads, supports lines larger than 64 KiB, applies the configured wall-clock timeout, terminates the owned Windows process tree with `taskkill /PID ... /T /F`, and awaits shielded cleanup before returning. On POSIX it uses a new process group. This is explicit cancellation cleanup, not a Windows Job Object or a guarantee against deliberately detached descendants or abrupt power loss. See [Python subprocess support](https://docs.python.org/3/library/asyncio-subprocess.html), [shielded cancellation](https://docs.python.org/3/library/asyncio-task.html#shielding-from-cancellation), and [taskkill semantics](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill).

Startup and periodic recovery inspect active run records. If the corresponding OS lock can be acquired, the old record becomes `interrupted`; a live owner keeps its record unchanged. Recovery does not resume an interrupted model turn. Deterministic findings and already collected evidence remain available after later failures.

[config.py](../src/security_monitoring_agent/config.py) reads known `SMA_` fields only. Precedence is workspace `.env`, then inherited process environment, then `Settings` defaults. Missing project roots default to the current workspace. Saving uses python-dotenv's quoting and an atomic same-directory replacement while preserving unrelated entries. UI edits therefore survive restarts without exposing arbitrary environment variables through the API. See [python-dotenv](https://bbc2.github.io/python-dotenv/) and the concrete values in [setup](setup.md).

Optional Windows integration is separate from the app timer. `login` registers this user's logon trigger to launch the local venv's windowless Python with `serve --no-browser`; the app then owns the timer. `task` registers a repeating `scan --once` action and disables the in-process timer. Tasks use the interactive current-user identity, limited run level, the explicit workspace, and `IgnoreNew`; they do not store passwords or run as SYSTEM. Task mode registers disabled when automatic scans are paused. Switching to `app` removes only the verified root-owned task definition and does not kill an existing dashboard. Registration is reconciled when UI settings change mode, interval, or pause state, not merely at startup. A root-derived hash scopes task names, and stored account names are translated back to SIDs for ownership comparison. [scheduling.py](../src/security_monitoring_agent/scheduling.py) uses the official [ScheduledTasks cmdlets](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/).

## Local HTTP API and verification

The server's `/docs` and `/openapi.json` describe typed requests. Many read responses are assembled dictionaries rather than separately declared response-model classes. `Contract` request bodies forbid extra fields. Local Host validation and rejection of foreign browser mutation origins protect the control endpoint; these checks are separate from provider tool permissions. This is a single-user loopback service with no remote-user authentication system.

| Method and route | Request / result |
| --- | --- |
| `GET /api/status` | Active scan/chat, app-derived next-scan estimate, last fully completed scan, counts, and settings; it does not query the actual Windows trigger's next-run time |
| `GET /api/findings`, `/api/advisories`, `/api/inventory`, `/api/runs` | Persisted findings, date-filtered news, latest inventory or null, and run history |
| `POST /api/runs` | Optional `provider`, `model`, `news_days` overrides; HTTP 202 with the created run |
| `GET /api/runs/{id}` | Run state or HTTP 404 |
| `POST /api/runs/{id}/cancel` | `{requested: boolean}`; a request is not a claim that cleanup has already finished |
| `GET /api/runs/{id}/events?after=N` | SSE replay/live stream; each data object contains `id`, `run_id`, `kind`, `text`, `created_at` |
| `GET /api/runs/{id}/log` | Complete JSONL download, or HTTP 404 before a log exists |
| `GET`, `PATCH /api/settings` | `Settings`; PATCH submits the full object, because omitted properties receive model defaults |
| `GET /api/diagnostics` | Bounded runtime/version probes without model inference |
| `GET`, `POST /api/chats` | Conversation summaries, or creation using `provider`, `model`, optional `finding_id` |
| `GET /api/chats/{id}` | Conversation, full messages, and active turn |
| `POST /api/chats/{id}/messages` | `{message: string}`; HTTP 202 with the asynchronous chat run |

SSE uses native FastAPI `EventSourceResponse`. The larger of `after` and `Last-Event-ID` determines replay position; malformed header cursors return HTTP 400. SQLite reads pages of up to 200 complete events. The stream drains terminal events before closing, and a disconnected client does not cancel the job. See the [SSE route implementation](../src/security_monitoring_agent/app.py) and [FastAPI SSE documentation](https://fastapi.tiangolo.com/tutorial/server-sent-events/).

[Windows CI](../.github/workflows/tests.yml) installs the locked Python environment and runs fixture-based tests plus strict JavaScript module parsing. Provider transports and source APIs are mocked where needed; subprocess tests use disposable Python helpers. CI does not install/authenticate Codex or Claude, submit paid model requests, or register actual scheduled tasks. Separate local live runs are required to validate a particular account/model's web search and schema behavior. The CI setup follows [uv's GitHub Actions guide](https://docs.astral.sh/uv/guides/integration/github/).
