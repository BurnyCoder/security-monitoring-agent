# Microsoft WSL primary-source regression

Author: Libor Burian. Observed 22 October 2026. This is a post-hoc software correction motivated by the [Haiku source review](02-haiku-scan.md), not a new model experiment or a general vulnerability matcher.

## Question and acceptance criterion

Could a narrow source-consistency check automatically prevent the two overconfident WSL-platform findings observed in the live run? The criterion, specified before replay, was that the unchanged original Haiku JSON and original inventory should produce exactly two `affected` → `potentially_affected` changes when checked against the live Microsoft CNA records, with an incomplete/partial indicator and retained primary citations. A zero-change replay, an unsupported definitive clearance, or an invented installed-version comparison would fail this criterion.

## Method

The checker validates CVE identifiers before constructing paths under the official CVE Program repository. It checks published, identity-matching Microsoft CNA records and their WSL product ranges. It compares only all-numeric dotted lower/upper bounds, padding missing trailing components with zero; it does not compare any installed version against a vulnerability range. Inverted bounds are contradictory source evidence. Missing or unavailable primary evidence prevents a definitive WSL-platform claim from passing this additional check. Results are cached per CVE within the scan.

The module is integrated after ordinary structural validation, so adding a primary-source URL cannot rescue an originally uncited definitive claim. Other products, distro backport applicability, nonnumeric/custom version semantics, exploitation, and runtime reachability are outside this checker. See [implementation](../src/security_monitoring_agent/intelligence/wsl_primary.py), [tests](../tests/test_wsl_primary.py), and the [CVE schema](https://cveproject.github.io/cve-schema/schema/docs/).

## Observed result

The live replay fetched the primary records for [CVE-2026-57968](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/57xxx/CVE-2026-57968.json) and [CVE-2026-57973](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/57xxx/CVE-2026-57973.json). Both contained the conflicting bounds identified in the source review. Exactly two findings changed from affected to potentially affected and the incomplete flag was true. The original output's affected count was two; the checked replay's affected count was zero. Assertions verified these results.

The replay appended timestamped source/review events to the original local scan log. It made no model call, performed no new inventory scan, and did not replace the untouched raw agent result. Persisted findings had already received the same qualified statuses during the explicit review. This establishes the targeted regression behavior for the two observed source contradictions; it does not establish accuracy for other CVEs or guarantee that primary records themselves are correct.
