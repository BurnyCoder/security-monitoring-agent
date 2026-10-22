"""Global: shared API and agent contracts. Local: typed evidence, never inferred safety.

Sources: https://docs.pydantic.dev/latest/concepts/models/ and
https://google.github.io/osv-scanner/output/ .
"""

from datetime import datetime, timezone  # UTC timestamps remain portable across machines.
from typing import Literal  # Closed status vocabularies prevent ambiguous UI states.

from pydantic import BaseModel, ConfigDict, Field, field_validator  # Validate every boundary.


def utc_now() -> str:
    """Global: common clock format. Local: return an aware ISO timestamp."""
    return datetime.now(timezone.utc).isoformat()  # Store UTC; the browser formats locally.


class Contract(BaseModel):
    """Global: reject accidental wire-shape changes. Local: forbid unrecognized fields."""

    model_config = ConfigDict(extra="forbid")  # Failed validation cannot become a clean scan.


class ProjectRoot(Contract):
    """Global: explicitly selected project scope. Local: retain native path and distro."""

    kind: Literal["windows", "wsl"] = "windows"  # No implicit cross-filesystem translation.
    path: str  # The configured project tree is the only dependency search root.
    distribution: str = ""  # Required by the WSL collector when kind is wsl.


class Settings(Contract):
    """Global: persisted user preferences. Local: constrain operational values only."""

    provider: Literal["codex", "claude"] = "codex"  # Both adapters expose the same contract.
    model: str = Field(default="gpt-6-luna", min_length=1)  # Provider validates arbitrary IDs.
    interval_minutes: int = Field(default=60, ge=1, le=10080)  # Minutes, not cron expressions.
    auto_scan: bool = True  # Hourly polling is enabled when the local app starts.
    news_days: Literal[1, 7, 30] = 7  # News recency never filters unresolved findings.
    timeout_seconds: int = Field(default=1800, ge=30, le=14400)  # One bounded agent invocation.
    project_roots: list[ProjectRoot] = Field(default_factory=list)  # Config seeds the cwd.
    codex_path: str = "codex"  # Accept an executable name or explicit local path.
    claude_path: str = "claude"  # Existing CLI authentication is reused.
    osv_path: str = "osv-scanner"  # Installation diagnostics explain missing binaries.
    schedule_mode: Literal["app", "login", "task"] = "app"  # Background modes are opt-in.


class Source(Contract):
    """Global: auditable provenance. Local: allow clickable HTTP(S) citations only."""

    title: str  # Human-readable source label.
    url: str  # Preserve the exact supporting page, not a fabricated citation identifier.

    @field_validator("url")
    @classmethod
    def http_url(cls, value: str) -> str:
        """Global: safe rendering contract. Local: reject executable URL schemes."""
        if not value.startswith(("https://", "http://")):  # External citations must be web URLs.
            raise ValueError("Source URLs must use http or https")  # Keep invalid output visible.
        return value  # Do not rewrite the original evidence URL.


class Asset(Contract):
    """Global: observed installation identity. Local: retain raw version and provenance."""

    id: str  # Stable identity includes the machine scope and installation location.
    kind: str  # windows_os/windows_app/wsl_platform/wsl_os/wsl_package/project_dependency.
    name: str  # Product or package name from the collector.
    version: str  # Never normalize distro versions with generic semantic-version rules.
    platform: str  # Windows, a specific WSL distro, or project scope.
    location: str = ""  # Path or registry/package source identifying this occurrence.
    metadata: dict[str, str] = Field(default_factory=dict)  # Supplementary observed facts.


class Coverage(Contract):
    """Global: make incomplete inspection explicit. Local: one status per collector/source."""

    component: str  # Stable collector, project, or feed name.
    status: Literal["ok", "partial", "error", "unsupported"]  # An error is never no findings.
    detail: str  # Explain what was actually checked or unavailable.
    asset_count: int = 0  # Zero can mean unsupported; interpret alongside status.


class Inventory(Contract):
    """Global: immutable scan evidence snapshot. Local: group assets with collection gaps."""

    captured_at: str = Field(default_factory=utc_now)  # Evidence ages independently of news.
    assets: list[Asset] = Field(default_factory=list)  # Each installation retains its own ID.
    coverage: list[Coverage] = Field(default_factory=list)  # Partial scans preserve successes.


Severity = Literal["critical", "high", "medium", "low", "unknown"]  # Source-backed categories.
Exploitation = Literal["known_exploited", "public_poc", "unverified_report", "none_known"]  # Evidence type.


class Advisory(Contract):
    """Global: vulnerability intelligence. Local: separate disclosure and exploitation dates."""

    id: str  # CVE, OSV ID, or canonical advisory URL.
    aliases: list[str] = Field(default_factory=list)  # Cross-source identifiers for deduplication.
    title: str  # Concise vulnerability description.
    summary: str  # Explain what the sources establish.
    severity: Severity = "unknown"  # Missing severity is not silently assigned.
    exploitation: Exploitation = "none_known"  # Does not claim absence of exploitation.
    published_at: str = ""  # Vendor publication date when established.
    modified_at: str = ""  # Source correction date when available.
    kev_added_at: str = ""  # KEV addition is not disclosure time.
    sources: list[Source] = Field(default_factory=list)  # Supporting evidence, not search snippets.


class Remediation(Contract):
    """Global: proposals only. Local: commands carry execution context and verification."""

    summary: str  # Human-readable action with the supported fixed version if known.
    steps: list[str] = Field(default_factory=list)  # Manual vendor steps are valid fixes.
    commands: list[str] = Field(default_factory=list)  # Copied by the UI, never executed by it.
    shell: str = ""  # PowerShell or the named WSL distro's shell.
    requires_admin: bool = False  # State required elevation without automatically requesting it.
    reboot: str = "unknown"  # yes/no/conditional explanation supplied by the source.
    verification: str = ""  # A check the user can perform after remediation.


class Finding(Contract):
    """Global: installation-specific assessment. Local: evidence and uncertainty are required."""

    advisory_id: str  # Resolved against an advisory in this batch or existing intelligence.
    asset_id: str  # Must resolve to an observed installation in the scan inventory.
    status: Literal["affected", "potentially_affected", "not_affected", "unknown"]  # Applicability.
    rationale: str  # Explain the installed-version/configuration-to-advisory relationship.
    evidence: list[str] = Field(default_factory=list)  # Exact observed and advisory facts.
    uncertainty: str = ""  # Missing conditions, supersedence, or reachability details.
    sources: list[Source] = Field(default_factory=list)  # Cite applicability, not just existence.
    remediation: Remediation | None = None  # No unsupported command is better than a guess.


class Investigation(Contract):
    """Global: final agent payload. Local: progress events cannot substitute for this result."""

    summary: str  # Describe the investigation's actual coverage.
    advisories: list[Advisory]  # News may be relevant without a device finding.
    findings: list[Finding]  # Every definitive assessment must validate against inventory.
    coverage_notes: list[str]  # Disclose limits, conflicts, and searches performed.
