"""Global: qualify definitive WSL claims when primary ranges conflict. Local: inspect Microsoft CNA rows only.

Sources: https://cveproject.github.io/cve-schema/schema/docs/ and https://github.com/CVEProject/cvelistV5 .
This is a numeric-bound contradiction check, not a version matcher or an independent applicability verdict.
"""

import re  # Validate CVE path components and the narrow all-numeric comparison domain.
from itertools import zip_longest  # Pad omitted trailing numeric components with zeros.

import httpx  # Reuse the existing async HTTP client with a short source timeout.

from ..models import Inventory, Investigation, Source  # Preserve typed source evidence and qualified findings.


def cve_record_url(identifier: str) -> str | None:
    """Global: fetch only the official CVEProject record. Local: derive repository buckets from strictly validated IDs."""
    match = re.fullmatch(r"CVE-([0-9]{4})-([0-9]{4,19})", identifier)  # Use the CVE schema's exact identifier domain.
    if not match:  # Model text cannot supply a different host, query, or path.
        return None  # Unsupported identifiers are outside this conditional check.
    year, number = match.groups()  # CVEProject groups records by year and thousand-number bucket.
    return f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{number[:-3]}xxx/{identifier}.json"  # No unvalidated input enters the URL.


def numeric_range_conflicts(record: dict, identifier: str) -> list[str]:
    """Global: reject demonstrably conflicting numeric bounds. Local: never compare an installed version or parse other version schemes."""
    metadata = record.get("cveMetadata", {})  # Primary identity and publication state belong to CVE metadata.
    if metadata.get("cveId") != identifier or metadata.get("state") != "PUBLISHED":  # A mismatched/rejected record cannot verify this claim.
        raise ValueError("Primary CVE identity or published state does not match the requested record")  # Caller reports unavailable verification.
    cna = record.get("containers", {}).get("cna", {})  # ADP and derived OSV ranges are deliberately outside this check.
    provider = cna.get("providerMetadata", {})  # Verify the organization that supplied these affected rows.
    if str(provider.get("shortName", "")).casefold() != "microsoft" and provider.get("orgId") != "f38d906d-7342-40ea-92c1-6c4a2c6478c8":  # Microsoft's CNA organization appears in its published records.
        raise ValueError("Microsoft CNA affected-product evidence is unavailable in this record")  # Do not use another publisher's version ranges as Microsoft evidence.
    products = [item for item in cna.get("affected", []) if str(item.get("vendor", "")).casefold() == "microsoft" and "windows subsystem for linux" in str(item.get("product", "")).casefold()]  # Restrict examination to Microsoft's named WSL products.
    if not products:  # A valid CVE about another product cannot verify a WSL platform finding.
        raise ValueError("Microsoft CNA Windows Subsystem for Linux affected-product evidence is unavailable")  # Keep the missing product scope explicit.
    conflicts = []  # Record exact contradictory source bounds for the finding's evidence.
    for product in products:  # A record can include multiple affected WSL product variants.
        for version in product.get("versions", []):  # CVE version rows carry their own affected status and range type.
            if version.get("status") != "affected":  # Do not reinterpret unaffected/unknown rows as affected ranges.
                continue  # Those rows remain available in the full source log.
            lower = version.get("version", "")  # The schema defines version as the range's inclusive starting value.
            for bound in ("lessThan", "lessThanOrEqual"):  # Preserve exclusive versus inclusive upper-bound semantics.
                upper = version.get(bound, "")  # Missing upper bounds are not a numeric interval to inspect.
                if not all(isinstance(value, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value) for value in (lower, upper)):  # No wildcard, prerelease, distro, or custom token comparison.
                    continue  # An unhandled version scheme is not automatically inconsistent.
                pairs = tuple(zip_longest(map(int, lower.split(".")), map(int, upper.split(".")), fillvalue=0))  # Compare numeric components after zero padding.
                start, end = tuple(pair[0] for pair in pairs), tuple(pair[1] for pair in pairs)  # Avoid lexicographic string ordering such as 2.10 before 2.9.
                if start > end or (start == end and bound == "lessThan"):  # Inverted or empty numeric intervals cannot support definitive applicability on their own.
                    conflicts.append(f"Microsoft CNA {product['product']} range has numerically conflicting bounds: version={lower}, {bound}={upper}, versionType={version.get('versionType', 'unspecified')}; vendor clarification is required.")  # Do not infer a corrected range or installed-version match.
    return conflicts  # No contradiction detected is not proof that this machine is affected or fixed.


async def check_wsl_primary_ranges(result: Investigation, inventory: Inventory, emit, *, client: httpx.AsyncClient | None = None) -> tuple[Investigation, bool]:
    """Global: qualify structurally validated WSL findings before publication. Local: cache primary checks within this scan only."""
    wsl_assets = {asset.id for asset in inventory.assets if asset.kind == "wsl_platform"}  # Distro packages and unrelated Windows assets are outside this guard.
    targets = [index for index, finding in enumerate(result.findings) if finding.asset_id in wsl_assets and finding.status in {"affected", "not_affected"} and cve_record_url(finding.advisory_id)]  # Already-uncertain and non-CVE findings require no extra network work.
    if not targets:  # Most investigations need no WSL range check.
        return result, False  # Preserve the inexpensive conditional path.
    if client is None:  # Tests may supply an in-memory transport; production owns its bounded client.
        async with httpx.AsyncClient(timeout=8, follow_redirects=False, headers={"User-Agent": "security-monitoring-agent/0.1"}) as owned_client:  # Stay on the exact official repository endpoint.
            return await check_wsl_primary_ranges(result, inventory, emit, client=owned_client)  # Reuse one client for every candidate in this scan.
    checked, cache, incomplete = result.model_copy(deep=True), {}, False  # Preserve raw model output and avoid duplicate source requests.
    scope = "This primary check only detects conflicting numeric bounds; it does not establish installed-version applicability or interpret custom version semantics."  # A successful structural check is not an independent applicability verdict.
    for index in targets:  # Each occurrence retains its own original facts and uncertainty.
        finding = checked.findings[index]  # Mutate only the result copy used for publication.
        identifier, url = finding.advisory_id, cve_record_url(finding.advisory_id)  # URL validity was established during target selection.
        if identifier not in cache:  # Cache successes and failures once per CVE per scan.
            try:  # Source outages must not leave a definitive WSL claim silently unverified.
                emit("source", f"Checking Microsoft CNA WSL ranges: {url}\n")  # Timestamped logging records the exact requested primary source.
                response = await client.get(url)  # Async I/O keeps the dashboard responsive during the short source request.
                emit("source", f"CVE primary response {identifier} HTTP {response.status_code}:\n{response.text}\n")  # Retain the full fetched evidence without truncation.
                response.raise_for_status()  # Error pages cannot count as a verified CNA record.
                cache[identifier] = (numeric_range_conflicts(response.json(), identifier), "")  # Only Microsoft CNA product/range rows are examined.
            except Exception as error:  # Cancellation remains BaseException and propagates to the scan owner.
                cache[identifier] = ([], f"Primary WSL evidence verification unavailable: {error}")  # Preserve operational and malformed-record diagnostics.
                emit("error", f"{identifier}: {cache[identifier][1]}\n")  # An unavailable check remains visible in the live transcript.
        conflicts, failure = cache[identifier]  # Repeated occurrences use the same source observation.
        title = "CVE primary record check (unavailable)" if failure else "Microsoft CNA CVE record"  # An attempted URL is never mislabeled as verified evidence.
        if not any(source.url == url for source in finding.sources):  # Preserve existing citations without duplicating a primary link.
            finding.sources.append(Source(title=title, url=url))  # The exact record is independently reviewable.
        finding.uncertainty = " ".join(filter(None, [finding.uncertainty, scope, failure, *conflicts]))  # Preserve original caveats and make the check's limits explicit.
        finding.evidence.extend(conflicts or [failure or "Fetched Microsoft CNA WSL rows; no clearly conflicting numeric bounds were detected. This is not an installed-version match."])  # Keep source evidence distinct from a local applicability conclusion.
        if conflicts or failure:  # Only observed contradictions or unavailable primary verification change certainty.
            previous = finding.status  # Retain the original classification in the explanatory note.
            finding.status = "potentially_affected" if conflicts or previous == "affected" else "unknown"  # Never turn a failed primary check into a definitive clearance.
            incomplete = True  # Pipeline exposes this concrete evidence gap as partial.
            checked.coverage_notes.append(f"WSL primary check downgraded {identifier} / {finding.asset_id} from {previous} to {finding.status}: " + (failure or " ".join(conflicts)))  # Summary and coverage events disclose why the model's certainty was reduced.
            caveat = f"Primary WSL check for {identifier}: " + (failure or " ".join(conflicts)) + " Definitive applicability requires verified, consistent primary evidence."  # News must disclose the same evidence gap as the associated occurrence.
            for advisory in checked.advisories:  # Qualify all matching source IDs without rewriting their original summaries.
                if identifier not in {advisory.id, *advisory.aliases}:  # Other news items do not inherit this CVE-specific uncertainty.
                    continue  # Preserve unrelated advisory content.
                if caveat not in advisory.summary:  # Multiple installations of the same CVE require only one news caveat.
                    advisory.summary += "\n\n" + caveat  # Append the exact primary-check limitation while retaining the original source claim.
                if not any(source.url == url for source in advisory.sources):  # Repeated occurrences must not duplicate citation links.
                    advisory.sources.append(Source(title=title, url=url))  # Failed retrieval remains clearly labeled as an unavailable check.
    return checked, incomplete  # Ordinary vendor ranges retain their prior status with an explicit structural caveat.
