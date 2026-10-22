"""Global: module entrypoint for Task Scheduler. Local: delegate to the public CLI."""

from .cli import main  # Keep command parsing in one reusable module.

main()  # python -m security_monitoring_agent follows the same path as the uv entrypoint.
