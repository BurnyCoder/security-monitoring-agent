# Live provider integration validation

Author: Libor Burian. Observation date: 22 October 2026. Times below are UTC.

This report records one local Codex scan, two turns of one Claude Code conversation, and two turns of a separate Codex conversation. It checks provider execution, retained evidence, structured output, session continuity, and selected source claims. It is an integration case study, not a measurement of vulnerability-detection accuracy or a comparison of model quality. The analysis below is retrospective; no statistical hypothesis test, training experiment, or population-level estimate was performed.

## Method and evidence

The application ran its ordinary local workflow with the user's existing CLI authentication. The requested models were `gpt-6-luna` for the scan and `haiku` for the conversation. The review read the persisted run/chat objects in `data/monitor.sqlite3`, timestamped JSONL events under `logs/`, and the scan's prepared inventory. It compared reported observations against that captured inventory and consulted the official sources linked below. The [architecture](../docs/architecture.md) describes the execution flags, event protocol, and validation boundary; [coverage](../docs/coverage.md) defines what the inventory can establish.

Raw logs, provider session identifiers, local paths, installed versions, and the complete software inventory are intentionally excluded from this public report. The local run identifiers below identify the original evidence without publishing its contents. Counts and lengths describe the retained application records, not hidden provider reasoning or inaccessible internal execution.

## Claude Code: initial conversation and explicit resume

| Observation | Initial turn | Resumed turn |
| --- | --- | --- |
| Run ID | `20261022T193011Z-57154ab0b1` | `20261022T193406Z-6f4b0bfd12` |
| Requested model | `haiku` | `haiku` |
| Model reported by CLI | `claude-haiku-5-5` | `claude-haiku-5-5` |
| Persisted terminal status | completed | completed |
| Start | 19:30:11.161673 | 19:34:06.935611 |
| Finish | 19:30:31.106556 | 19:34:15.353865 |
| Application elapsed time | 19.945 seconds | 8.418 seconds |
| JSONL file size | 221,508 bytes | 62,390 bytes |
| Retained JSONL events | 332 | 48 |
| Complete application prompt | 2,055 characters | 171 characters |
| Final answer | 967 characters | 261 characters |

The initial question requested the captured Windows build, WSL platform version, Ubuntu release, and one inventory limitation. Each reported version was checked against its corresponding captured field or the recorded WSL component output. Those comparisons matched. This establishes agreement with the collector snapshot, not an independent audit of the operating systems.

The follow-up asked for one sentence explaining why the missing-hotfix evidence could not establish vulnerability, using the existing conversation. The CLI initialization events, both persisted run objects, and the saved conversation all contained the same provider session identifier. The follow-up command uses explicit `--resume` in the adapter, and the follow-up prompt contained the new question without resending the original inventory prompt. The returned explanation retained the earlier limitation. This is an observed continuation of that one session; it does not measure long-context reliability. Claude documents explicit session continuation in its [headless guide](https://code.claude.com/docs/en/headless).

For both turns, the entire ordered `(kind, text)` event sequence in JSONL matched the corresponding SQLite event sequence. Each prompt contained the complete saved user message, and each `agent_result` exactly matched the corresponding saved assistant message. JSONL and SQLite use their own observation timestamps, so this comparison does not assert identical timestamps. The CLI initialization events reported `bypassPermissions`. The initial response's recorded tool calls were `Glob`, `Grep`, and `Read`; the resumed response recorded no tool calls. No mutating tool call was observed in these two transcripts. A complete before/after filesystem audit was not performed.

The hotfix limitation was source-checked separately: Microsoft documents that `Get-HotFix` relies on `Win32_QuickFixEngineering` and does not return every update mechanism. Microsoft also describes Windows quality updates as cumulative. Together these support the narrow conclusion that a missing individual KB in this collector output cannot, by itself, prove a missing fix. They do not establish that this particular device is patched for an arbitrary CVE. [Get-HotFix documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix), [Windows quality-update cycle](https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle).

## Codex: inventory, live research, and structured scan

Run `20261022T192430Z-7f4ce7fa6f` started at 19:24:30.168072 and finished at 19:40:35.940749, taking 965.773 seconds. It requested `gpt-6-luna`; this Codex event stream did not report an actual model identifier, so the application correctly retained `actual_model: null`. The observed transcript included 23 distinct web-tool IDs. That count includes the provider's web searches, page opens, and finds; it is not a count of independent search queries or verified sources.

The full final response was valid JSON and passed the `Investigation` Pydantic contract. It contained 12 advisories and 15 proposed installation findings: four `affected`, four `potentially_affected`, and seven `not_affected`. One proposed finding used an asset identifier missing its last character. Exact inventory binding rejected that finding, leaving 14 persisted findings: four affected, four potential, and six not affected. This is a model output error caught by the structural gate, not an inferred repair of an asset identity.

The server version already running when the scan began initially recorded `completed` despite that rejection. At 19:42:09, the unchanged original payload was replayed through the updated publication gate, and the persisted status was corrected to `partial` with an explicit audit event. This replay performed no new model inference, web research, or device inspection. The [pipeline regression tests](../tests/test_pipeline.py) cover rejected asset references and other publication gaps. The original provider output was retained unchanged.

At original completion, the JSONL file held 1,891 events and 2,507,819 bytes; the application prompt was 3,146 characters and the final JSON was 35,999 characters. After the validation-status correction and the source correction below, it held 1,893 events and 2,508,855 bytes. The entire ordered `(kind, text)` sequence still matched SQLite. Native CLI stderr included credential-store fallback and inherited MCP initialization warnings; these remained visible in the log while the research and structured response completed. Successful completion did not imply that every inherited MCP integration worked.

### Two checked applicability claims

These examples were selected after the scan to cover one Windows application finding and one Ubuntu package finding. They are not a random sample, a precision estimate, or validation of every returned advisory. Actual installed versions and installation paths remain in the private local evidence.

| Returned assessment | Independent check | Supported interpretation |
| --- | --- | --- |
| Ubuntu package, `not_affected`, USN-8951-1 | The finding referenced an exact observed package asset. Canonical's notice names the relevant distribution release and its patched package version; the captured package met that release-specific threshold. | The package-version conclusion for that notice is supported. This does not establish runtime use or coverage of other package sources. [Official Ubuntu notice](https://ubuntu.com/security/notices/USN-8951-1). |
| Windows application, `affected`, GHSA-x8g2-7r3w-h44p | The exact observed ImageMagick installation was within the vendor's affected release range. The vendor lists the patched release, low severity, and a local symlink race involving policy-denied file access. The model retained the unverified workload/configuration conditions. | The version exposure and proposed vendor upgrade threshold are supported. Exploitation of this device was not demonstrated. [Official ImageMagick advisory](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-x8g2-7r3w-h44p). |

### Source-classification discrepancy and correction

An additional source check found that the model had classified GHSL-2026-140 as `none_known`, although the cited research advisory publishes a proof-of-concept generator. The same official advisory supports the affected range and fixed release, but the public exploit demonstration warranted `public_poc` under this application's categories. This is distinct from evidence of exploitation in the wild. [GitHub Security Lab advisory](https://securitylab.github.com/advisories/GHSL-2026-140_7-Zip/).

At 19:43:50 the persisted advisory was updated through `Store.save_advisory` to `public_poc`, retaining its sources and other evidence. A `coverage` audit event documented the independently verified correction; the original model response was not rewritten. No exploit payload was downloaded or executed. The task prompt now explicitly asks the model to inspect cited vendor/research advisories for public PoC code or generators and apply the corresponding category. This prompt change has not been shown to eliminate classification errors; it addresses the observed omission without claiming a guarantee.

## Codex: initial conversation and explicit resume

| Observation | Initial turn | Resumed turn |
| --- | --- | --- |
| Run ID | `20261022T194015Z-4f95a732e4` | `20261022T194134Z-c0f4f55965` |
| Requested model | `gpt-6-luna` | `gpt-6-luna` |
| Model reported by CLI | unavailable | unavailable |
| Persisted terminal status | completed | completed |
| Application elapsed time | 26.351 seconds | 15.282 seconds |
| JSONL file size | 1,020,897 bytes | 9,392 bytes |
| Retained JSONL events | 37 | 25 |
| Complete application prompt | 2,143 characters | 117 characters |
| Final answer | 296 characters | 78 characters |

The initial question asked for the recorded Ubuntu package count and why upstream versions alone cannot establish vulnerability; the follow-up asked whether that count included Windows applications. Both counts were checked against the captured inventory categories and matched. The answer correctly kept Windows applications separate. Its backport explanation is consistent with [Canonical's security-update documentation](https://documentation.ubuntu.com/security/security-updates/).

Both raw `thread.started` events and both persisted run objects used the exact session identifier saved on the conversation, confirming explicit resume. The follow-up prompt contained only the new question and its wrapper. For each turn, the complete user question was present in the logged prompt, final output exactly matched the stored assistant message, and all ordered `(kind, text)` events matched SQLite. The initial turn retained an 820,056-character event, providing one live example of a record larger than the usual 64 KiB stream-reader limit. This demonstrates retention of that observed event; it is not an unbounded-memory guarantee.

## Interpretation and limits

The completed conversations demonstrate native provider execution, explicit session reuse in both adapters, agreement with selected inventory fields, and preservation of the application prompt/final answer through the observed storage paths. The scan demonstrates collection, live research, structured publication, and rejection of a malformed asset reference, with one additional source-classification correction. Different elapsed times cannot be interpreted as a speed comparison: the tasks, context, and tool use differ, and each was run once.

Source citations and schema validation do not make every model conclusion correct. This review does not establish exhaustive vulnerability coverage, exploit reachability, successful remediation, or absence of compromise. No proposed remediation was executed as part of these checks. The selected applicability checks and the observed classification error do not support a general model-accuracy claim.
