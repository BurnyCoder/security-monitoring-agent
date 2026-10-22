# Engineering validation: local monitoring integration

Author: Libor Burian  
Validation date: 2026-10-22, Europe/Berlin  
Scope: repository working tree, automated integration behavior and one focused code review. This record contains synthetic test outcomes and sanitized implementation observations, not device inventory, account details, credentials, or raw agent transcripts.

## Question, hypothesis, and acceptance criteria

The engineering question is whether the local pipeline preserves explicit evidence and run state across configuration, subprocesses, storage, HTTP streaming, and frontend module loading. The hypothesis is that the implemented boundaries behave according to their contracts under the tested success, failure, cancellation, and reconnect scenarios. A failed assertion, malformed frontend module, lost event payload, leaked owned test process, or incorrect identity merge falsifies that hypothesis for its specific scenario.

These criteria are recorded after the debugging work; this is a retrospective engineering validation record, not a preregistered experiment. The suite is a selected set of regressions and integration cases, not a random sample from all possible failures. Passing test cases is not a detection-accuracy estimate.

| Acceptance criterion | Executable evidence |
| --- | --- |
| A fresh workspace has an actual empty state, settings survive a save/load round trip, and numeric news-window literals retain their type. | [HTTP tests](../tests/test_api.py), [configuration regression](../tests/test_config.py) |
| Concurrent scan triggers share ownership; cancellation releases that ownership, including cancellation before the task's first execution tick. | [service/API tests](../tests/test_api.py), [immediate-cancel regression](../tests/test_immediate_cancel.py) |
| Both process pipes drain completely, large lines and unterminated UTF-8 text survive, and timeouts/cancellation reap the tested owned processes before returning. | [real subprocess tests](../tests/test_process.py) |
| SSE reconnect replays unseen complete records and preserves a 100,000-character event payload. | `test_sse_replays_large_events_from_cursor` in [HTTP tests](../tests/test_api.py), [storage event test](../tests/test_storage.py) |
| Provider success requires the expected terminal result; failed/missing structured results cannot silently become successful empty findings. | [provider contract tests](../tests/test_agents.py) |
| Inventory/source gaps remain explicit, lockfile evidence is distinguished from deployed state, and source-specific exit codes retain their meaning. | [collector tests](../tests/test_collectors.py), [dependency tests](../tests/test_dependencies.py), [intelligence tests](../tests/test_intelligence.py) |
| Findings bind to observed assets; unsupported definitive conclusions are downgraded; advisory identity consolidation preserves installations and handles ambiguous multi-CVE notices. | [evidence tests](../tests/test_evidence.py), [alias and transaction regressions](../tests/test_storage.py) |
| Scheduling specifications use the local environment, explicit root, current-user behavior, and a disabled task when automatic scans are paused. | [scheduling tests](../tests/test_scheduling.py) |
| Every shipped browser module parses as ECMAScript and links its relative imports and named exports. | [strict frontend checker](../scripts/check_frontend.mjs) |

## Method and observed results

The validation commands ran from the repository root on native Windows AMD64 with Python 3.14.2 and Node.js 24.13.0. Python dependencies were already installed in the local `.venv`; invoking that interpreter directly avoided changing the environment while collecting this result. Tests use isolated temporary state and synthetic source/provider records where appropriate. Process tests launch disposable Python helpers to exercise real pipe handling and termination. The suite does not invoke paid LLM requests or install real Windows scheduled tasks. See the [test sources](../tests) and [Windows CI configuration](../.github/workflows/tests.yml).

```powershell
.venv/Scripts/python.exe -m pytest -q
node --experimental-vm-modules scripts/check_frontend.mjs
```

| Check | Observed outcome | Interpretation |
| --- | --- | --- |
| Python suite | **88 passed in 8.46s**, exit code 0 | Final local run after news-window and Microsoft WSL primary-range/news-caveat regressions. All 88 collected cases passed, including parameterized cases; this is not 88 independent statistical observations. Earlier checkpoints were 56 passed in 7.77s and 66 passed in 7.23s. |
| Browser module check | **6 ECMAScript modules parsed and linked**, exit code 0 | `api.js`, `app.js`, `chat.js`, `settings.js`, `ui.js`, and `views.js` passed the strict parser/linker. DOM interaction and rendering are outside this check. |
| Focused code review | **One pass completed**, followed by correction of identified issues | Review covered correctness, local control endpoints, maintainability, tests, process reliability, evidence identity, and architecture. This is not an exhaustive security audit. |
| Browser layout checks | Parent session inspected desktop viewports at 815 px and the default 1,265 px, plus a 390 px mobile viewport; no page-level horizontal overflow was observed. | These are concrete viewport observations, not an exhaustive device/browser matrix. The initial JavaScript syntax failure was fixed before the overview loaded successfully. |

The table distinguishes directly observed validation from the parent integration session's reported final checks. These checks should be repeated after later code changes; passing a previous working-tree snapshot does not establish the behavior of an untested future revision. Deterministic integration assertions do not justify confidence intervals, statistical significance claims, seed-power calculations, or model-accuracy statistics.

## Fixes and lessons from the validation cycle

| Observed issue or regression target | Correction and why it was selected | Evidence and remaining boundary |
| --- | --- | --- |
| Native SSE needed the framework's typed async-generator/marker path; an incompatible response shape prevented the intended event handling. | The route declares `AsyncIterable[ServerSentEvent]`, yields native `ServerSentEvent` values, and delegates framing to `EventSourceResponse`. This reuses the framework's documented transport instead of maintaining custom SSE serialization. | [SSE route](../src/security_monitoring_agent/app.py), [FastAPI SSE documentation](https://fastapi.tiangolo.com/tutorial/server-sent-events/), and the large-event cursor regression. The test covers replay of an ended run, not every browser/proxy reconnect condition. |
| The browser stopped at the dashboard shell with `Missing initializer in const declaration`. A deeply nested settings expression contained an extra closing parenthesis. Ordinary Node 24 `--check file.js` had not exposed this failure in the observed environment. | Split the settings form into named sections and a shallow composition. Added an explicit `vm.SourceTextModule` parse/link check for every browser module. This catches syntax using the ECMAScript module parser without evaluating browser globals. | [Settings form](../src/security_monitoring_agent/static/settings.js), [frontend checker](../scripts/check_frontend.mjs), [Node module-parser documentation](https://nodejs.org/api/vm.html#class-vmsourcetextmodule). The parent validation session reported the overview loading after this correction; that browser observation is distinct from the automated syntax result. |
| `.env` is textual, while `news_days` is an integer-valued `Literal`; reloading a saved setting needed explicit numeric conversion. | Convert the news-window value to an integer before Pydantic validation and keep the shared Settings contract as the boundary. | [Configuration implementation](../src/security_monitoring_agent/config.py), [round-trip test](../tests/test_config.py), [Pydantic Literal types](https://docs.pydantic.dev/latest/api/standard_library_types/#literals). The regression exercises local configuration values, not every malformed `.env` input. |
| Cancelling a newly created task before it entered its cleanup scope could leave a scan lock held. Repeated cancellation could also interrupt slow process-tree cleanup. | Track entry into the run lifecycle, avoid repeatedly cancelling an already-cancelling task, and await a separately owned shielded cleanup task until process termination and pipe cleanup finish. This retains the original cancellation outcome while preserving cleanup ownership. | [Service lifecycle](../src/security_monitoring_agent/service.py), [process cleanup](../src/security_monitoring_agent/process.py), [immediate-cancel test](../tests/test_immediate_cancel.py), [repeated-cancel test](../tests/test_process.py), [Python shielding semantics](https://docs.python.org/3/library/asyncio-task.html#shielding-from-cancellation). Tests verify owned helper trees; deliberately detached descendants and abrupt host power loss are not covered. |
| Different source IDs for one vulnerability could remain duplicated after a later alias link. Conversely, treating a multi-CVE notice as identity equivalence could merge distinct vulnerabilities. Generic enrichment could weaken known exploitation evidence. | Consolidate unambiguous identity links and occurrence keys transactionally, preserve the newest installation assessment and its timestamps, retain stronger exploitation evidence, and avoid collapsing conflicting/multi-CVE identities. | [Storage implementation](../src/security_monitoring_agent/storage.py), [alias/order/rollback tests](../tests/test_storage.py), [OSV aliases definition](https://ossf.github.io/osv-schema/#aliases-field). The guards reduce the tested merge errors; they do not independently establish that every upstream alias is correct. |

The practical lesson across these fixes is to validate boundaries with their actual consumers: browser module syntax, framework SSE behavior, typed `.env` values, kernel process lifecycle, and source-specific identity semantics. A superficially valid output or an early successful phase is insufficient evidence that the complete boundary behaved correctly.

## Coverage gaps and limits of the claims

- Automated provider tests exercise recorded/synthetic protocol shapes and command construction. They do not establish current account access, current model behavior, live web-source quality, or that an agent checked every installed asset. Live Luna/Haiku investigations require separate run records.
- The Python API suite uses FastAPI's test client. The strict frontend checker parses and links modules but does not render CSS, operate dropdowns, copy a command, test screen-reader behavior, or exercise a browser's network reconnection. The reported viewport checks supplement it but do not establish those behaviors. Further filter and latest-scan-state interaction checks belong to the parent browser-validation session.
- Scheduling tests validate generated specifications and mocked registration transport. They do not substitute for testing real Task Scheduler registration, logoff/login, sleep/resume, battery behavior, or an organization's Windows policy.
- Collector fixtures cover selected Windows and WSL formats and failure states. They do not establish exhaustive support for every Windows installation mechanism, Linux distribution, package manager, patch-supersedence case, or project manifest. See [coverage documentation](../docs/coverage.md).
- Evidence validation checks structure, provenance presence, and asset binding. It does not independently verify every cited page, prove affected-version relationships, establish runtime reachability, or demonstrate exploitability. Source corrections and unavailable data remain possible.
- The focused review and passing suite do not prove the application is free of vulnerabilities or that unrestricted agents cannot take unintended actions. The implemented task is monitoring and proposed remediation; the UI has no remediation-execution operation. The scope and logging limitations are described in [architecture](../docs/architecture.md).

No real exploit was required by these automated checks. No vulnerability-detection precision, recall, false-positive rate, causal efficacy, or remediation-success claim is inferred from their outcomes.
