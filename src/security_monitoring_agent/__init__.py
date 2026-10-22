"""Global: installed command facade. Local: defer initialization until the user launches it."""


def main() -> None:
    """Global: uv console script entrypoint. Local: import the shared command implementation."""
    from .cli import main as run  # Avoid opening a database merely by importing the package.
    run()  # All commands share the same interface and lifecycle.
