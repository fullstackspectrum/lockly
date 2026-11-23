"""Which lockfiles Lockly reads, and how to tell them apart."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Callable

from ..model import CARGO, GO, NPM, PYPI, Lockfile, LockfileError
from . import native, npm, python


@dataclass(frozen=True)
class Format:
    kind: str
    ecosystem: str
    parse: Callable[[str, str | None], list]
    # A file next to the lockfile that says which dependencies are direct,
    # for formats that don't record it (or, for go.mod, go.sum's hashes).
    manifest: str = ""


FORMATS = {
    "package-lock.json": Format("package-lock", NPM, npm.parse_package_lock),
    "npm-shrinkwrap.json": Format("package-lock", NPM, npm.parse_package_lock),
    "yarn.lock": Format("yarn", NPM, npm.parse_yarn, "package.json"),
    "pnpm-lock.yaml": Format("pnpm", NPM, npm.parse_pnpm),
    "uv.lock": Format("uv", PYPI, python.parse_uv),
    "poetry.lock": Format("poetry", PYPI, python.parse_poetry, "pyproject.toml"),
    "Pipfile.lock": Format("pipfile", PYPI, python.parse_pipfile, "Pipfile"),
    "go.mod": Format("go", GO, native.parse_go_mod, "go.sum"),
    "Cargo.lock": Format("cargo", CARGO, native.parse_cargo),
}
# go.sum on its own only when there's no go.mod to read instead.
GO_SUM = Format("go-sum", GO, native.parse_go_sum)

KINDS = sorted({f.kind for f in FORMATS.values()} | {GO_SUM.kind})


def format_for(path: str, kind: str = "") -> Format:
    if kind:
        for f in [*FORMATS.values(), GO_SUM]:
            if f.kind == kind:
                return f
        raise LockfileError(f"unknown lockfile type '{kind}' (choose from {', '.join(KINDS)})")
    base = posixpath.basename(path.replace("\\", "/"))
    if base in FORMATS:
        return FORMATS[base]
    if base == "go.sum":
        return GO_SUM
    raise LockfileError(f"{path}: not a lockfile Lockly knows (use --type: {', '.join(KINDS)})")


def is_lockfile(path: str) -> bool:
    base = posixpath.basename(path)
    return base in FORMATS or base == "go.sum"


def manifest_path(path: str, fmt: Format) -> str:
    return posixpath.join(posixpath.dirname(path), fmt.manifest) if fmt.manifest else ""


def parse(path: str, text: str, manifest: str | None = None, kind: str = "") -> Lockfile:
    fmt = format_for(path, kind)
    lock = Lockfile(path, fmt.kind, fmt.ecosystem)
    if not text.strip():
        return lock  # a lockfile that didn't exist on one side of the diff
    try:
        lock.packages = fmt.parse(text, manifest)
    except LockfileError as exc:
        raise LockfileError(f"{path}: {exc}") from None
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise LockfileError(f"{path}: doesn't look like a {fmt.kind} lockfile ({type(exc).__name__}: {exc})") from None
    return lock
