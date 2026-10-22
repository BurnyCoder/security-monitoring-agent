# What the monitor checks

The monitor records device/package facts, fetches known-exploitation intelligence, scans configured project dependencies, and gives that evidence to the selected agent for web research. Coverage is reported per collector, feed, distribution, and project. An unavailable source or failed command is an error or partial result; it is not evidence that the device is unaffected.

A run marked `completed` means the configured workflow finished with no detected collector failure, missing live-search event, rejected record, or structurally unsupported definitive assessment. It does not guarantee exhaustive coverage, factual accuracy of agent conclusions, or that the device is unaffected. Those observable gaps produce `partial`; model-written coverage notes remain verbatim in the run summary and coverage log events, but arbitrary note text is not interpreted as a failure signal. This behavior is implemented in [the scan pipeline](../src/security_monitoring_agent/pipeline.py) and tested with synthetic results in [the pipeline tests](../tests/test_pipeline.py).

## Windows and WSL inventory

Windows collection reads the OS caption, architecture, edition, display version, build, and revision. It reads application names, versions, publishers, and occurrence locations from system/current-user uninstall registry scopes, including the 32-bit scopes, and current-user AppX packages. It does not inspect other users' profiles or enumerate portable programs. The registry approach follows [Microsoft's inventory guidance](https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations); it avoids `Win32_Product`, whose queries can initiate MSI consistency checks and repairs.

`Get-HotFix` supplies supplementary installed KB evidence. It is not a complete update inventory, and absence of a KB does not establish that a fix is missing. Windows applicability still needs the exact supported product/build and vendor evidence about cumulative-update supersedence. See [Get-HotFix limitations](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix) and the [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/).

The implementation discovers WSL distributions registered for the current Windows user from the `Lxss` registry subtree. It obtains WSL platform component versions with `wsl.exe --version`, then runs the fixed collector through `wsl.exe --distribution <name> --exec sh -c <script>` for each distribution. Inspecting a stopped distribution starts it. The script reads `/etc/os-release`, runs `uname -r`, and runs the following query when `dpkg-query` is present:

```sh
dpkg-query -W -f='${db:Status-Status}\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n'
```

Only rows with status `installed` become package assets. Source package names and versions remain separate from binary package names and versions. Epochs and distro revisions are preserved. These are documented [dpkg-query virtual fields](https://manpages.debian.org/unstable/dpkg/dpkg-query.1.en.html); WSL invocation follows [Microsoft's command reference](https://learn.microsoft.com/en-us/windows/wsl/basic-commands).

Missing OS metadata, malformed package rows, unsupported package managers, failed commands, and timeouts appear in coverage. Non-dpkg package managers, snaps, manually copied software, and arbitrary Python/Node environments are not enumerated. The WSL kernel/platform is kept separate from distro userland: the [Microsoft WSL2 kernel](https://github.com/microsoft/WSL2-Linux-Kernel) must not be treated as an ordinary Ubuntu kernel package.

There is no custom deterministic Windows or Linux OS CVE matcher in this version. Agents assess inventory against cited vendor advisories. Upstream version comparisons alone are insufficient for distro packages because [Ubuntu backports security fixes](https://documentation.ubuntu.com/security/security-updates/).

## Known exploitation and web research

Every scan fetches the entire [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json). If that fails, it tries the [official CISA GitHub mirror](https://github.com/cisagov/kev-data). The returned coverage records the actual endpoint and catalog version; fallback failures are logged. If both sources fail, source coverage is an error.

KEV IDs are normalized by CVE, retaining descriptions, product/vendor context, CISA's action text, notes links, and addition dates. The news window does not remove old KEV records from this baseline. KEV addition is not disclosure time. A feed entry establishes known exploitation of the vulnerability, not that this device is affected. Web research by the selected agent supplies additional recent advisories and device applicability evidence; a KEV feed is not an exhaustive stream of newly disclosed vulnerabilities.

## Configured project dependencies

Dependency analysis delegates parsing and matching to [OSV-Scanner v2](https://google.github.io/osv-scanner/). With no configured roots, only the dashboard's current project folder is scanned. Additional Windows folders and WSL `(distribution, absolute Linux path)` pairs must be explicitly configured. The monitor does not discover sibling projects or scan a whole drive automatically.

The Windows executable comes from `osv_path`; a relative file path is resolved against the dashboard project folder, otherwise the executable is resolved from `PATH`. WSL projects use `osv-scanner` installed in that distribution's `PATH`:

```text
osv-scanner scan source --format=json --all-packages --no-call-analysis=go --no-resolve --recursive <project-folder>
wsl.exe --distribution <distro> --exec osv-scanner scan source --format=json --all-packages --no-call-analysis=go --no-resolve --recursive <absolute-linux-folder>
```

These flags select source/dependency scanning, include clean packages in JSON, disable default Go call analysis, and disable manifest dependency resolution. Recursive scanning is limited to the configured project tree. Scanner `.gitignore` behavior and project `osv-scanner.toml` settings apply; those settings can suppress packages or advisories. The monitor does not invoke the scanner's `fix` command or enable optional Rust build analysis. See [source scanning](https://google.github.io/osv-scanner/usage/scan-source), [general usage](https://google.github.io/osv-scanner/usage/), and [configuration](https://google.github.io/osv-scanner/configuration/).

The scanner supports resolved lockfiles including `uv.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, and the other formats in its [supported-artifacts table](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/). Resolved lockfiles are preferable to manifests containing ranges. Disabling manifest resolution means unresolved manifests do not receive an inferred complete transitive dependency graph. Source scanning of a WSL project does not inspect installed apt packages.

JSON stdout and diagnostic stderr are retained through the shared process logger. Exit `0` means packages were scanned without findings; exit `1` is successful scanning with findings. Exit `128` is reported as unsupported/no packages, and other unsuccessful exits, unavailable binaries, bad JSON, timeouts, and missing folders produce errors. These meanings follow [OSV-Scanner's output contract](https://google.github.io/osv-scanner/output/). A project scan is bounded to five minutes or the configured scan timeout, whichever is shorter.

Each dependency asset retains project, source file, ecosystem, package, and recorded version. Findings describe an affected **recorded dependency version**; they do not establish installation, deployment, environment selection, runtime reachability, or exploitation. Distinct projects and locked versions remain distinct occurrences. Withdrawn advisories do not produce active findings. Unambiguous CVE aliases join OSV records to CVE intelligence; multi-CVE notices retain their own identifier. Categorical severity is used when supplied; unsupported or absent severity remains unknown.

Proposed dependency remediations retain published fixed versions for the matching package/ecosystem, ask the user to choose a compatible release, regenerate the project's lockfile, run its tests, and rescan. They do not assume the numerically largest version is appropriate or claim that absence of a `fixed` event means no fix exists elsewhere. The monitor does not modify dependency files during inspection.

Install the native scanner using [official installation instructions](https://google.github.io/osv-scanner/installation/). Windows supports `winget install Google.OSVScanner`; official release binaries are also available for Windows and Linux. WSL project scans require a Linux scanner installation inside each configured distribution.

## Verification of these boundaries

The automated collector/intelligence tests cover independent Windows installation identities, supplemental KB preservation, collector failures, dpkg source/binary differences, exclusion of non-installed packages, unsupported package managers, malformed/incomplete WSL metadata, legacy WSL version NUL padding, and cancellation propagation. KEV fixtures verify preservation of old CVEs, addition-versus-publication dates, source provenance, and invalid feed rejection. Scanner fixtures verify lockfile-scoped findings, published fix evidence, clean-package inventory, withdrawn advisories, and exit `0`/`1`/`127`/`128` handling.

Pipeline tests verify that blocked inventory and investigation writes leave the event loop responsive, cancellation waits for an outstanding database worker, rejected or downgraded claims produce visible partial results, and ordinary model scope notes remain visible without automatically changing workflow status. Blocking database phases use [`asyncio.to_thread`](https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread); cancellation is reported after the active database worker finishes, so a cancelled run cannot continue writing after scan ownership is released.

Run the focused checks with:

```powershell
uv run pytest tests/test_collectors.py tests/test_intelligence.py tests/test_dependencies.py tests/test_pipeline.py
```

Live run results belong in the experiment reports and timestamped local logs; the tests above use synthetic fixtures and are not measurements of real-world vulnerability-detection accuracy.
