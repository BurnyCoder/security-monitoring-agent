"""Global: news recency preserves source precision without filtering device findings.

Local policy: timezone-aware ISO timestamps use the exact rolling cutoff; date-only
or timezone-unspecified values use inclusive UTC calendar days. Observation time
is a fallback only when no source date can be parsed. Source:
https://docs.python.org/3/library/datetime.html#datetime.datetime.fromisoformat .
"""

from datetime import datetime, timezone  # The standard library parses ISO offsets without another dependency.


def _date_is_recent(value: str | None, cutoff: datetime) -> bool | None:
    """Global: do not invent missing clock precision. Local: return None for absent or unparseable evidence dates."""
    if not value:  # Empty model/source fields do not establish a publication time.
        return None  # The caller can fall back to observation only when every source date is unavailable.
    try:  # Sources provide ISO dates, UTC timestamps, or explicit timezone offsets.
        parsed = datetime.fromisoformat(value)  # Python accepts YYYY-MM-DD, Z, and numeric UTC offsets.
    except ValueError:  # A malformed upstream date must not break the whole intelligence view.
        return None  # Preserve the original field in storage while treating its time as unavailable.
    if parsed.utcoffset() is None:  # A calendar date or unspecified timezone cannot locate an exact UTC instant.
        return parsed.date() >= cutoff.astimezone(timezone.utc).date()  # Include the cutoff calendar day without claiming an exact publication hour.
    return parsed.astimezone(timezone.utc) >= cutoff  # Compare actual instants so timezone offsets cannot change inclusion.


def is_recent_advisory(advisory: dict, cutoff: datetime) -> bool:
    """Global: recent corrections and KEV additions can refresh old disclosures. Local: use observation only if all source dates are absent or invalid."""
    source_dates = [_date_is_recent(advisory.get(field), cutoff) for field in ("published_at", "modified_at", "kev_added_at")]  # Evaluate each date at its supplied precision.
    established = [recent for recent in source_dates if recent is not None]  # False still means an established older source date.
    return any(established) if established else bool(_date_is_recent(advisory.get("observed_at"), cutoff))  # Reobserving an old dated advisory cannot make it new again.
