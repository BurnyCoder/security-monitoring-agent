"""Global: reuse OSV-Scanner rather than implement lockfile parsing. Local: preserve package occurrence and scan coverage.

Sources: https://google.github.io/osv-scanner/usage/scan-source ,
https://google.github.io/osv-scanner/output/ , https://google.github.io/osv-scanner/usage/ .
"""

import json  # Scanner stdout is a documented JSON interface.
import re  # Validate CVE aliases without inferring arbitrary identities.
from pathlib import Path, PurePosixPath  # Keep Windows and WSL paths in their own namespaces.
from urllib.parse import quote  # OSV identifiers become one escaped URL path segment.

from ..collectors.common import asset_id  # Reuse stable occurrence identities across phases.
from ..models import Advisory, Asset, Coverage, Finding, ProjectRoot, Remediation, Settings, Source  # Shared typed evidence.
from ..process import run_process  # Complete stdout/stderr capture and owned process lifecycle.


def advisory_identity(record: dict) -> tuple[str, list[str]]:
    """Global: join OSV aliases to KEV when unambiguous. Local: retain multi-CVE advisories under their source ID."""
    identifiers = sorted(set([record["id"], *record.get("aliases", [])]))  # Original identity is never lost.
    cves = [value for value in identifiers if re.fullmatch(r"CVE-\d{4}-\d{4,}", value)]  # Only exact CVE aliases are join candidates.
    identifier = cves[0] if len(cves) == 1 else record["id"]  # A multi-issue notice cannot be collapsed to one CVE.
    return identifier, [value for value in identifiers if value != identifier]  # Keep all other identifiers for provenance.


def normalize_advisory(record: dict) -> Advisory:
    """Global: normalize scanner-provided OSV data. Local: preserve source-backed severity and references."""
    identifier, aliases = advisory_identity(record)  # Reuse one consistent deduplication rule.
    sources = [Source(title=f"OSV {record['id']}", url=f"https://osv.dev/vulnerability/{quote(record['id'], safe='')}")]  # Link to the actual OSV record.
    for reference in record.get("references", []):  # Vendor advisories and fix commits remain inspectable.
        url = reference.get("url", "")  # Reject non-web links through explicit filtering.
        if url.startswith(("http://", "https://")):  # Source contract accepts HTTP(S) citations only.
            sources.append(Source(title=reference.get("type", "Advisory reference"), url=url))  # No fabricated citation labels.
    severity = str(record.get("database_specific", {}).get("severity", "unknown")).lower()  # Use categorical severity only when provided.
    if severity not in {"critical", "high", "medium", "low"}:  # CVSS vectors need a proper calculator, never string heuristics.
        severity = "unknown"  # The agent may enrich using authoritative severity evidence.
    return Advisory(id=identifier, aliases=aliases, title=record.get("summary") or record["id"], summary=record.get("details") or record.get("summary") or "OSV-Scanner matched this recorded dependency version.", severity=severity, published_at=record.get("published", ""), modified_at=record.get("modified", ""), sources=sources)  # Scanner evidence remains separate from exploit reports.


def remediation_for(record: dict, package: dict, project: ProjectRoot) -> Remediation:
    """Global: source-backed dependency proposals. Local: list published fixes without choosing incompatible branches."""
    fixed = set()  # One advisory may have multiple supported fixed branches.
    for affected in record.get("affected", []):  # Examine only this ecosystem/package entry.
        identity = affected.get("package", {})  # Package identity is part of OSV applicability.
        if identity.get("name") != package["name"] or identity.get("ecosystem") != package.get("ecosystem"):  # Other package fixes are not interchangeable.
            continue  # Keep remediation grounded in the matching dependency.
        for affected_range in affected.get("ranges", []):  # Preserve all source-reported fixed events.
            fixed.update(event["fixed"] for event in affected_range.get("events", []) if event.get("fixed"))  # Do not sort versions semantically ourselves.
    summary = "Published fixed releases for this package: " + ", ".join(sorted(fixed)) + ". Select a compatible fixed release after reviewing the advisory." if fixed else "Review the linked advisory for a supported fix or mitigation; this record provides no fixed release for the matching package."  # Unknown fix is not automatically unavailable forever.
    return Remediation(summary=summary, steps=[f"In {project.path}, update the dependency constraint and regenerate the lockfile with the project's package manager.", "Review release notes and compatibility, run the project's tests, then rescan this configured project."], shell=f"WSL:{project.distribution}" if project.kind == "wsl" else "PowerShell", reboot="Usually not required for a lockfile change; restart any affected running application after deployment.", verification="Run another dashboard scan and confirm the dependency's new version and absence of this advisory.")  # Proposed manual actions never mutate the project.


def parse_scanner_report(payload: dict, project: ProjectRoot) -> tuple[list[Asset], list[Advisory], list[Finding]]:
    """Global: normalize deterministic dependency evidence. Local: preserve lockfile/runtime distinction."""
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):  # Error objects cannot pass as empty reports.
        raise ValueError("OSV-Scanner JSON has no results array")  # Caller reports incomplete scanning.
    assets, advisories, findings = {}, {}, {}  # Deduplicate within a project while preserving distinct sources.
    for source in payload["results"]:  # Each lockfile/SBOM is an independent observed source.
        source_path = str(source.get("source", {}).get("path", project.path))  # Scanner normally reports its absolute source path.
        source_type = str(source.get("source", {}).get("type", "unknown"))  # SBOM/git sources are not mislabeled lockfiles.
        for entry in source.get("packages", []):  # --all-packages makes clean package coverage visible.
            package = entry["package"]  # Malformed records deliberately fail the project parser.
            name, version = package["name"], str(package.get("version", ""))  # Raw version retains ecosystem semantics.
            ecosystem = package.get("ecosystem", "")  # Registry namespace is part of package identity.
            occurrence = asset_id("project", project.kind, project.distribution, project.path, source_path, ecosystem, name, version)  # Multiple locked versions are separate occurrences.
            asset = Asset(id=occurrence, kind="project_dependency", name=name, version=version, platform=f"WSL:{project.distribution}" if project.kind == "wsl" else "Windows", location=source_path, metadata={"project_root": project.path, "ecosystem": ecosystem, "source_type": source_type, "evidence_scope": "Recorded project dependency; installation, deployment, and runtime reachability are not established."})  # Keep exact scope in the agent prompt.
            assets[occurrence] = asset  # Repeated identical records do not inflate coverage.
            for record in entry.get("vulnerabilities", []):  # Scanner already performed ecosystem-specific matching.
                if record.get("withdrawn"):  # Withdrawn advisory records are not active vulnerability claims.
                    continue  # Source remains in raw logs if supplied by the scanner.
                advisory = normalize_advisory(record)  # Shared typed source representation.
                advisories[advisory.id] = advisory  # Alias-equivalent records collapse within this project.
                finding = Finding(advisory_id=advisory.id, asset_id=occurrence, status="affected", rationale=f"OSV-Scanner matched {ecosystem} package {name} {version} recorded in {source_type} {source_path}.", evidence=[f"Configured project: {project.path}", f"Recorded dependency: {ecosystem}/{name}@{version}", f"OSV record: {record['id']}"], uncertainty="This establishes an affected recorded dependency version. Installed/deployed state, optional environment selection, configuration, and runtime reachability were not established; no exploit was executed.", sources=advisory.sources, remediation=remediation_for(record, package, project))  # Avoid claiming device exploitability from a lockfile.
                findings[(occurrence, advisory.id)] = finding  # One finding per occurrence and canonical advisory.
    return list(assets.values()), list(advisories.values()), list(findings.values())  # Preserve useful clean assets and all matching evidence.


async def scan_projects(settings: Settings, root: Path, emit) -> tuple[list[Asset], list[Advisory], list[Finding], list[Coverage]]:
    """Global: inspect only explicitly configured projects. Local: invoke the supported native scanner CLI."""
    assets, advisories, findings, coverage = [], [], [], []  # Preserve independent project outcomes.
    projects = settings.project_roots or [ProjectRoot(path=str(root))]  # Empty configuration defaults only to this repository.
    flags = ["scan", "source", "--format=json", "--all-packages", "--no-call-analysis=go", "--no-resolve", "--recursive"]  # Resolved dependency scanning needs no builds or lockfile rewrites.
    for project in projects:  # No discovery of unrelated sibling folders or drives.
        component = f"dependencies:{project.kind}:{project.distribution}:{project.path}"  # Coverage identifies the exact configured root.
        try:  # Missing binaries/roots are explicit project errors.
            if project.kind == "wsl":  # Linux paths belong to an explicitly named distro.
                if not project.distribution or not PurePosixPath(project.path).is_absolute():  # Never guess distro or translate paths.
                    raise ValueError("WSL project roots require a distribution and absolute Linux path")  # Report invalid scope without scanning elsewhere.
                args = ["wsl.exe", "--distribution", project.distribution, "--exec", "osv-scanner", *flags, project.path]  # Use the distro's Linux scanner installation.
            else:  # Windows scanner reads only the configured tree.
                path = Path(project.path).expanduser()  # Resolve a user-selected project path.
                path = path if path.is_absolute() else root / path  # Relative scope is anchored to this application workspace.
                if not path.is_dir():  # Missing path cannot become a successful empty scan.
                    raise ValueError(f"Configured project folder does not exist: {path}")  # Full path is useful setup evidence.
                executable = str((root / settings.osv_path).resolve()) if (root / settings.osv_path).is_file() else settings.osv_path  # Support repo-local .tools installs and PATH executables.
                args = [executable, *flags, str(path.resolve())]  # Pass each path as one subprocess argument.
            emit("source", f"Scanning configured dependency root {component}\n")  # Scope is visible before network work.
            result = await run_process(args, cwd=root, emit=emit, timeout=min(settings.timeout_seconds, 300))  # Complete scanner output streams to existing timestamped logs.
            if result.returncode == 128:  # Documented no-package result is not a clean dependency assessment.
                coverage.append(Coverage(component=component, status="unsupported", detail="OSV-Scanner found no supported dependency packages in this configured tree. " + result.stderr))  # Keep full diagnostic reason.
                continue  # No unsupported assets or vulnerability conclusions are invented.
            if result.returncode not in (0, 1):  # Exit one means findings, not execution failure.
                raise RuntimeError(f"OSV-Scanner exited {result.returncode}: {result.stderr or result.stdout}")  # Unknown exits remain failures.
            project_assets, project_advisories, project_findings = parse_scanner_report(json.loads(result.stdout), project)  # Validate before recording successful coverage.
            assets.extend(project_assets)  # Keep clean and vulnerable dependencies.
            advisories.extend(project_advisories)  # Cross-source history/dedup belongs to storage.
            findings.extend(project_findings)  # Project occurrence identity prevents cross-root merging.
            coverage.append(Coverage(component=component, status="ok", detail=f"OSV-Scanner read {len(project_assets)} recorded dependencies. Default gitignore and project scanner configuration apply; call analysis and manifest resolution are disabled. This does not establish installed/deployed state or scan OS packages.", asset_count=len(project_assets)))  # State actual scanner behavior and exclusions.
        except Exception as exc:  # Cancellation remains interruptible via the shared process helper.
            emit("error", f"Dependency scan failed for {component}: {exc}\n")  # Full actionable failure appears immediately.
            coverage.append(Coverage(component=component, status="error", detail=f"{exc}. Install OSV-Scanner v2 on Windows or inside the configured WSL distribution; see https://google.github.io/osv-scanner/installation/"))  # Never substitute a clean result on tool failure.
    return assets, advisories, findings, coverage  # All configured roots receive a visible outcome.
