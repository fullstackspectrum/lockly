"""Packages read from a lockfile, the same shape whatever the format."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# OSV's names for the ecosystems, used everywhere so lookups need no mapping.
NPM, PYPI, GO, CARGO = "npm", "PyPI", "Go", "crates.io"


class LockfileError(Exception):
    pass


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    # True: the project depends on it directly. False: only through another
    # package. None: the lockfile doesn't say and no manifest was found.
    direct: bool | None = None
    dev: bool = False
    # Where it comes from: a registry host, "git", "path" or a URL. Empty
    # means the ecosystem's default registry.
    source: str = ""
    integrity: str = ""
    license: str = ""
    # True only when the lockfile records it (npm's hasInstallScript,
    # pnpm's requiresBuild); None when the format can't tell.
    install_script: bool | None = None
    # When this version was published, if the lockfile records it (uv does).
    published: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return self.ecosystem, normalise_name(self.ecosystem, self.name)


def normalise_name(ecosystem: str, name: str) -> str:
    if ecosystem == PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503
    if ecosystem == CARGO:
        return name.replace("_", "-").lower()
    return name


@dataclass
class Lockfile:
    path: str
    kind: str                      # package-lock, yarn, pnpm, uv, poetry, pipfile, go, cargo
    ecosystem: str
    packages: list[Package] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.path
