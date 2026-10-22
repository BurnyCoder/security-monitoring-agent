# Haiku scan and finding-context validation

Author: Libor Burian. Observation date: 22 October 2026. All times are UTC.

This report covers the separate dashboard-triggered Haiku scan and a conversation opened for a selected finding. The evidence-review method and statistical limits are described in [the first live-validation report](01-live-validation.md). These are individual functionality observations, not an accuracy benchmark or a controlled comparison with Luna. Device versions, provider session identifiers, installation paths, and raw transcripts remain in ignored local evidence.

## Full dashboard scan

Run `20261022T194323Z-783f350abf` started at 19:43:23.983682 and finished at 19:47:50.924029, taking 266.940 seconds. The requested model alias was `haiku`; the CLI reported `claude-haiku-5-5`. The provider emitted a successful terminal result with native `structured_output`, which exactly matched the application's logged final JSON and passed the `Investigation` schema.

The prepared inventory reports ten collector/source coverage entries, all `ok`, including Windows metadata and hotfix evidence, WSL discovery/platform/dpkg inventory, CISA KEV, and the explicitly configured project dependency scan. OSV-Scanner reported 47 recorded project dependencies. This differs from the earlier Luna run's 33 because the repository dependency set had changed while documentation support was added; it is not evidence of a model-dependent collection difference. The source log records the official CISA feed and catalog version `2026.10.21`, containing 1,754 entries. `ok` means that the specified collection operation succeeded within its documented scope; it does not establish complete software coverage or that every package is unaffected. See [coverage boundaries](../docs/coverage.md).

The recorded provider tools included nine distinct `WebSearch` calls and three `WebFetch` calls. The raw final result contained eight advisories, ten findings, and fourteen coverage notes. All finding asset IDs matched the captured inventory, and the existing structural evidence gate initially retained the output without changes. Subsequent independent source review found unsupported certainty and factual errors described below.

| Finding status | Original model response | After independent source correction |
| --- | --- | --- |
| affected | 2 | 0 |
| potentially_affected | 4 | 6 |
| not_affected | 3 | 3 |
| unknown | 1 | 1 |

The initial run status was `completed`; after review it is `partial`. At original completion, the JSONL transcript contained 5,268 events and 2,889,308 bytes, including the entire 3,146-character application prompt and 28,828-character final result. After the correction audit event it contains 5,269 events and 2,890,336 bytes. All ordered `(kind, text)` events match SQLite. The four stderr events were OSV-Scanner diagnostics; the provider reported no terminal failure. Individual source limitations, including unreadable MSRC page content, were disclosed in the model's coverage notes.

## Focused source review and corrections

The source review selected WSL applicability and a project dependency conclusion. It was performed after seeing the output, not as a random or preregistered accuracy sample.

| Claim reviewed | Primary-source check | Outcome |
| --- | --- | --- |
| WSL is definitively affected by CVE-2026-57968 | Microsoft's CNA record specifies a lower bound of `5.0.0.0` and upper bound `<2.7.8`, while the cited OSV-derived range uses a broader lower bound. | The conflicting range prevents the definite conclusion used by the model. The occurrence was downgraded to `potentially_affected`, with the exact source conflict retained. [Microsoft CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/57xxx/CVE-2026-57968.json). |
| WSL is definitively affected by CVE-2026-57973 | Microsoft's CNA record likewise gives `5.0.0.0` as its lower bound but `<2.7.10` as its upper bound, conflicting with the OSV-derived range. | The same downgrade and explicit uncertainty apply. This does not establish that the device is unaffected. [Microsoft CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/57xxx/CVE-2026-57973.json). |
| The recorded Starlette dependency is not affected by CVE-2026-48710 | The upstream maintainer advisory identifies affected releases through `1.0.0` and patched release `1.0.1`; the exact recorded lockfile version lies beyond the affected range. | The narrow recorded-dependency conclusion is supported. Installed environments, deployment, and reachability were not established. [Upstream Starlette advisory](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr). |

The two WSL downgrades were persisted at 19:51:16 with source URLs, evidence, and uncertainty added to the finding records. Their original inventory and assessment timestamps were retained. The run was marked `partial`, and a timestamped `coverage` event recorded the correction. This was an independent source-review correction, not a fresh scan or new model response; the original JSON remains unchanged in the transcript.

Two prose issues were also corrected in the displayed run summary. First, one coverage note asserted that unmatched server products were not installed; the collector only establishes that they were not observed in its scope. Second, the model described Chrome 156 as apparently early-stable only. Google's dated release announcement had already promoted Chrome 156 to stable on October 20, with rollout over subsequent days or weeks. The review corrected that statement without claiming to recheck every browser vulnerability. [Official Chrome stable release](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02018666648.html).

The task prompt was strengthened to inspect Microsoft CNA version ranges when MSRC pages are unreadable, retain uncertainty for inverted or conflicting bounds, and distinguish missing inventory matches from proof of noninstallation. These prompt changes do not guarantee that future research will be complete or factually correct. No new inference was performed to estimate their effect during this review.

## Conversation opened for the selected finding

Run `20261022T194509Z-033560520f` started at 19:45:09.615847 and finished at 19:45:19.977636, taking 10.362 seconds. Its persisted status is `completed`; the requested alias was `haiku` and the CLI reported `claude-haiku-5-5` with `bypassPermissions`.

The question asked why the selected WSL finding was only potentially affected and what its proposed commands would do, without running them. The logged prompt embedded the exact saved finding identifier, `potentially_affected` status, cited advisory, uncertainty, and proposed remediation. This verifies that the finding-specific conversation received the selected record rather than an unrelated global summary.

The response retained the uncertainty caused by conflicting version bounds in Microsoft's CVE record. Independent review of the Microsoft CNA data in the CVE Program repository confirmed a lower bound of `5.0.0.0` and an upper bound of `<3.0.1` in both affected-version and CPE fields. This source inconsistency supports retaining uncertainty; it does not establish a repaired affected range. [CVE-2026-96206 CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/96xxx/CVE-2026-96206.json).

The command explanation matches Microsoft's documented behavior: `wsl --update` updates WSL, `wsl --shutdown` terminates running distributions and the WSL 2 utility VM, and `wsl --version` reports component versions. No tool calls were recorded in this conversation, so these commands remained explanations rather than execution. [Microsoft WSL command reference](https://learn.microsoft.com/en-us/windows/wsl/basic-commands).

The response answered both substantive questions but exceeded the requested two-sentence format: two main sentences were followed by two additional sentences about non-execution and saving work before shutdown. This formatting deviation is retained as an observed limitation.

The 97,868-byte JSONL transcript contains 116 events, including the complete 5,549-character application prompt and 676-character final answer. Its entire ordered `(kind, text)` sequence matches SQLite. The final `agent_result` exactly matches the saved assistant message, and the provider session identifier matches between the initialization event, run object, and saved conversation. Observation timestamps in the JSONL file and SQLite are separate, as described in the first report.

## Scope of the evidence

The scan demonstrates a functioning collection, research, native structured-output, and publication path. Its source-review corrections also demonstrate that schema validity and successful execution are insufficient to establish factual accuracy. The finding-context check shows that a selected record can be passed to the provider and explained with its uncertainty intact. Neither observation establishes exhaustive detection, successful remediation, or device safety. No exploit payload or proposed remediation command was executed in these checks.
