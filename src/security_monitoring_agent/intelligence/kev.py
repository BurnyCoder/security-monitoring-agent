"""Global: authoritative known-exploitation baseline. Local: fetch complete CISA snapshots with mirror fallback.

Source: https://github.com/cisagov/kev-data documents feed fields, mirror timing and provenance.
"""

import re  # Extract cited vendor URLs from the feed's notes field.

import httpx  # Existing HTTP library provides TLS, timeouts and status validation.

from ..models import Advisory, Coverage, Source  # Shared intelligence evidence contracts.

KEV_URLS = ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json")  # Canonical feed first, official mirror second.


def parse_kev(payload: dict, source_url: str) -> list[Advisory]:
    """Global: keep the complete KEV baseline. Local: preserve addition dates without inventing disclosure dates."""
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):  # A server error page is not an empty catalog.
        raise ValueError("CISA KEV response has no vulnerabilities array")  # The fetcher records a failed source.
    advisories = []  # Every catalog entry remains available for inventory research.
    for entry in payload["vulnerabilities"]:  # Do not apply the news recency window here.
        identifier = str(entry.get("cveID", ""))  # CVE identity is the source's join key.
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):  # Reject malformed catalog records explicitly.
            raise ValueError(f"CISA KEV contains invalid CVE identifier: {identifier!r}")  # Never silently discard a baseline entry.
        sources = [Source(title="CISA Known Exploited Vulnerabilities catalog", url=source_url)]  # Keep actual fetched endpoint for provenance.
        for url in re.findall(r"https?://[^\s<>]+", str(entry.get("notes", ""))):  # Vendor references supply remediation context.
            sources.append(Source(title="CISA-linked advisory", url=url.rstrip(".,;")))  # Remove prose punctuation, not URL paths.
        summary = f"{entry.get('vendorProject', '')} {entry.get('product', '')}: {entry.get('shortDescription', '')}\nCISA required action: {entry.get('requiredAction', '')}"  # Preserve product and action evidence without synthesizing a fix.
        advisories.append(Advisory(id=identifier, title=entry.get("vulnerabilityName", identifier), summary=summary, exploitation="known_exploited", kev_added_at=entry.get("dateAdded", ""), sources=sources))  # Addition date is independent of publication/modification.
    return advisories  # Storage owns cross-run deduplication and history.


async def fetch_kev(emit) -> tuple[list[Advisory], list[Coverage]]:
    """Global: source fetch boundary. Local: retain failures while trying CISA's official mirror."""
    failures = []  # Expose fallback use rather than hiding upstream outages.
    async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers={"User-Agent": "security-monitoring-agent/0.1 (+local vulnerability monitoring)"}) as client:  # Bounded authenticated-TLS requests.
        for url in KEV_URLS:  # Only the official canonical and mirror endpoints are used.
            try:  # A transient canonical failure may still permit an official snapshot.
                emit("source", f"Fetching complete CISA KEV catalog: {url}\n")  # Record request provenance.
                response = await client.get(url)  # No API key is required for the feed.
                response.raise_for_status()  # HTTP errors cannot become successful empty intelligence.
                payload = response.json()  # Unexpected content becomes a recorded source failure.
                advisories = parse_kev(payload, url)  # Normalize before declaring source success.
                detail = f"Loaded all {len(advisories)} KEV entries, catalog {payload.get('catalogVersion', 'unknown')}, from {url}."  # Full baseline is explicitly counted.
                if failures:  # A mirror is still valid evidence, with a known freshness caveat.
                    detail += " Official mirror used after: " + "; ".join(failures)  # Preserve complete upstream diagnostics.
                emit("source", detail + "\n")  # Real-time source status reaches logs and dashboard.
                return advisories, [Coverage(component="cisa_kev", status="ok", detail=detail, asset_count=len(advisories))]  # Successful fallback does not discard valid intelligence.
            except Exception as exc:  # asyncio cancellation still propagates as BaseException.
                failures.append(f"{url}: {exc}")  # Keep each failed endpoint for auditability.
                emit("error", f"CISA source failed: {failures[-1]}\n")  # No silent fallback.
    return [], [Coverage(component="cisa_kev", status="error", detail="; ".join(failures))]  # Previous stored intelligence should remain stale rather than disappear.
