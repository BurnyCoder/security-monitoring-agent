"""Global: provider-independent result contract. Local: retain evidence of web activity.

Source: https://docs.python.org/3/library/dataclasses.html .
"""

from dataclasses import dataclass  # Immutable output crosses the provider boundary.


@dataclass(frozen=True)
class AgentResult:
    """Global: one output shape for both CLIs. Local: separate text from schema data."""

    text: str  # Complete final provider response.
    structured: dict | None = None  # Parsed result still requires domain-model validation.
    session_id: str | None = None  # Explicit identity for follow-up chat only.
    model: str | None = None  # Observed model, if the provider emits one.
    web_searches: int = 0  # Unique emitted search tool calls, not backend query counts.
