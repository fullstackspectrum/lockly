"""Read lockfiles from git: which changed since a base, and their contents on
each side. Compares against the merge base, as a pull request's diff does,
so changes that landed on the base branch afterwards don't show up."""

from __future__ import annotations

import posixpath
import subprocess
from pathlib import Path

from . import parsers
from .model import Lockfile, LockfileError


def _git(*args: str, cwd: str = ".") -> str:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise LockfileError("git isn't installed") from None
    if out.returncode != 0:
        raise LockfileError(f"git {' '.join(args[:2])} failed: {out.stderr.strip().splitlines()[-1] if out.stderr.strip() else 'unknown error'}")
    return out.stdout


def root(cwd: str = ".") -> str:
    return _git("rev-parse", "--show-toplevel", cwd=cwd).strip()


def merge_base(base: str, head: str | None, cwd: str) -> str:
    try:
        return _git("merge-base", base, head or "HEAD", cwd=cwd).strip()
    except LockfileError:
        pass
    # Shallow CI checkouts may lack the history; the base itself will do.
    try:
        return _git("rev-parse", "--verify", "--quiet", base + "^{commit}", cwd=cwd).strip()
    except LockfileError:
        raise LockfileError(f"can't find '{base}' in this repository (in CI, fetch it first: "
                            f"git fetch origin {base})") from None


def _read(ref: str | None, path: str, repo: str) -> str | None:
    """A file's contents at a ref, or in the working tree when ref is None.
    None when it doesn't exist there."""
    if ref is None:
        p = Path(repo) / path
        return p.read_text("utf-8") if p.is_file() else None
    out = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=repo, capture_output=True, text=True, timeout=60)
    return out.stdout if out.returncode == 0 else None


def changed_lockfiles(base: str, head: str | None, paths: list[str], repo: str) -> list[str]:
    args = ["diff", "--name-only", base] + ([head] if head else [])
    names = _git(*args, "--", *paths, cwd=repo).splitlines()
    if head is None:
        names += _git("ls-files", "--others", "--exclude-standard", "--", *paths, cwd=repo).splitlines()
    found = []
    for name in sorted(set(names)):
        if not parsers.is_lockfile(name):
            continue
        # go.mod is the lockfile in effect; a go.sum change is read through it.
        if posixpath.basename(name) == "go.sum":
            go_mod = posixpath.join(posixpath.dirname(name), "go.mod")
            if _read(head, go_mod, repo) is not None or _read(base, go_mod, repo) is not None:
                name = go_mod
        if name not in found:
            found.append(name)
    return found


def load_pair(path: str, base: str, head: str | None, repo: str, kind: str = "") -> tuple[Lockfile, Lockfile]:
    fmt = parsers.format_for(path, kind)
    manifest = parsers.manifest_path(path, fmt)
    sides = []
    for ref in (base, head):
        text = _read(ref, path, repo) or ""
        man = _read(ref, manifest, repo) if manifest else None
        sides.append(parsers.parse(path, text, man, kind))
    return sides[0], sides[1]


def load_file(path: str, kind: str = "") -> Lockfile:
    """A lockfile from disk, with its manifest from the same directory."""
    p = Path(path)
    try:
        text = p.read_text("utf-8")
    except FileNotFoundError:
        raise LockfileError(f"{path}: no such file") from None
    except OSError as exc:
        raise LockfileError(f"{path}: can't read ({exc.strerror})") from None
    fmt = parsers.format_for(path, kind)
    manifest = None
    if fmt.manifest:
        m = p.with_name(fmt.manifest)
        manifest = m.read_text("utf-8") if m.is_file() else None
    return parsers.parse(path, text, manifest, kind)
