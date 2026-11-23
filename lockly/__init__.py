"""Lockly: what changed in a lockfile, and what deserves a closer look."""

__version__ = "0.1.0"


def main() -> None:
    from .cli import main as _main

    _main()
