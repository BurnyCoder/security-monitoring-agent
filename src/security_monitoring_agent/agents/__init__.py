"""Global: public agent interface. Local: expose only the facade and its result type.

Source: https://docs.python.org/3/tutorial/modules.html#packages .
"""

from .runner import run_agent  # Callers do not depend on provider-specific implementation.
from .types import AgentResult  # Stable result type shared by scans and chat.

__all__ = ["AgentResult", "run_agent"]  # Keep the intended public surface explicit.
