"""npm, Yarn (classic and Berry) and pnpm lockfiles."""

from __future__ import annotations

import json
import re
import urllib.parse

from .. import miniyaml
from ..model import NPM, LockfileError, Package

_DEFAULT_REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"}


def _source(resolved: str) -> str:
    """'' for the public registry; 'git', 'path' or the host otherwise."""
    if not resolved:
        return ""
    if resolved.startswith(("git+", "git:", "github:", "git@")) or "#commit=" in resolved:
        return "git"
    if resolved.startswith(("file:", "link:", "portal:", "../", "./", "/")):
        return "path"
    host = urllib.parse.urlsplit(resolved).netloc.lower()
    return "" if host in _DEFAULT_REGISTRIES else host or resolved


def _manifest_deps(manifest: str | None) -> tuple[set[str], set[str]] | None:
    """(dependencies, devDependencies) names from a package.json, if given."""
    if not manifest:
        return None
    try:
        doc = json.loads(manifest)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    prod = set(doc.get("dependencies") or {}) | set(doc.get("optionalDependencies") or {}) | set(doc.get("peerDependencies") or {})
    return prod, set(doc.get("devDependencies") or {})


# ── package-lock.json / npm-shrinkwrap.json ──────────────────────────

def parse_package_lock(text: str, manifest: str | None = None) -> list[Package]:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise LockfileError(f"isn't valid JSON ({exc})") from None
    if not isinstance(doc, dict):
        raise LockfileError("isn't an npm lockfile")

    packages = doc.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        return _package_lock_v2(packages)
    if isinstance(doc.get("dependencies"), dict):  # lockfileVersion 1
        out: list[Package] = []
        _package_lock_v1(doc["dependencies"], out, top=True)
        return out
    raise LockfileError("has neither 'packages' nor 'dependencies'")


def _package_lock_v2(packages: dict) -> list[Package]:
    # Direct dependencies: the root's and every workspace's own.
    direct: set[str] = set()
    for path, meta in packages.items():
        if path == "" or (isinstance(meta, dict) and "node_modules/" not in path):
            for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                direct |= set((meta or {}).get(field) or {})
    out = []
    for path, meta in packages.items():
        if not path or "node_modules/" not in path or not isinstance(meta, dict):
            continue
        if meta.get("link"):
            continue  # a workspace symlink; the workspace itself isn't a dependency
        name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
        version = str(meta.get("version") or "")
        if not version:
            continue
        hoisted = path.count("node_modules/") == 1
        out.append(Package(
            NPM, name, version,
            direct=hoisted and name in direct,
            dev=bool(meta.get("dev")),
            source=_source(str(meta.get("resolved") or "")),
            integrity=str(meta.get("integrity") or ""),
            license=str(meta.get("license") or ""),
            install_script=bool(meta.get("hasInstallScript")),
        ))
    return out


def _package_lock_v1(deps: dict, out: list[Package], top: bool) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict) or not meta.get("version"):
            continue
        version = str(meta["version"])
        resolved = str(meta.get("resolved") or "")
        if version.startswith(("git+", "github:", "file:")):
            resolved, version = version, version.rsplit("#", 1)[-1][:12]
        # v1 hoists transitive dependencies to the top level too, so it
        # can't tell which are direct.
        out.append(Package(NPM, name, version, direct=None if top else False,
                           dev=bool(meta.get("dev")), source=_source(resolved),
                           integrity=str(meta.get("integrity") or "")))
        if isinstance(meta.get("dependencies"), dict):
            _package_lock_v1(meta["dependencies"], out, top=False)


# ── yarn.lock ────────────────────────────────────────────────────────

def _spec_name(spec: str) -> str:
    """'@babel/core@^7.0.0' → '@babel/core'; 'lodash@npm:^4' → 'lodash'."""
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def parse_yarn(text: str, manifest: str | None = None) -> list[Package]:
    if "__metadata:" in text:
        return _yarn_berry(text, manifest)
    return _yarn_classic(text, manifest)


def _yarn_classic(text: str, manifest: str | None) -> list[Package]:
    out = []
    deps = _manifest_deps(manifest)
    entry: dict[str, str] | None = None
    names: list[str] = []

    def flush():
        if entry is not None and entry.get("version"):
            name = names[0]
            out.append(Package(NPM, name, entry["version"],
                               direct=(name in deps[0] | deps[1]) if deps else None,
                               dev=bool(deps and name in deps[1] and name not in deps[0]),
                               source=_source(entry.get("resolved", "")),
                               integrity=entry.get("integrity", "")))

    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith(" "):
            flush()
            names = [_spec_name(s) for s in line.rstrip(":").split(",")]
            entry = {}
        elif entry is not None and line.startswith("  ") and not line.startswith("    "):
            m = re.match(r"^\s+(\S+)\s+\"?([^\"]*)\"?$", line)
            if m:
                entry[m.group(1)] = m.group(2)
    flush()
    return out


def _yarn_berry(text: str, manifest: str | None) -> list[Package]:
    try:
        doc = miniyaml.loads(text) or {}
    except ValueError as exc:
        raise LockfileError(f"can't be read as Yarn Berry YAML ({exc})") from None
    deps = _manifest_deps(manifest)
    out = []
    for key, meta in doc.items():
        if key == "__metadata" or not isinstance(meta, dict):
            continue
        resolution = str(meta.get("resolution") or "")
        if "@workspace:" in resolution or meta.get("linkType") == "soft":
            continue  # the project's own workspaces
        name = _spec_name(key.split(",")[0])
        protocol = resolution[len(name) + 1:] if resolution.startswith(name + "@") else ""
        if protocol.startswith("npm:"):
            source = ""
        elif protocol.startswith("patch:"):
            source = "patch"
        else:
            source = _source(protocol) if protocol else ""
        out.append(Package(NPM, name, str(meta.get("version") or ""),
                           direct=(name in deps[0] | deps[1]) if deps else None,
                           dev=bool(deps and name in deps[1] and name not in deps[0]),
                           source=source, integrity=str(meta.get("checksum") or "")))
    return [p for p in out if p.version and p.version != "0.0.0-use.local"]


# ── pnpm-lock.yaml ───────────────────────────────────────────────────

# pnpm 6+: /name@version(peers) or name@version(peers).
_PNPM_KEY = re.compile(r"^/?(@?[^@/]+(?:/[^@/]+)?)@([^(]+)")
# pnpm 5: /name/version_peers or /@scope/name/version_peers.
_PNPM5_KEY = re.compile(r"^/((?:@[^/]+/)?[^/]+)/([^_/]+)")


def parse_pnpm(text: str, manifest: str | None = None) -> list[Package]:
    try:
        docs = miniyaml.loads_all(text)
    except ValueError as exc:
        raise LockfileError(f"can't be read as pnpm YAML ({exc})") from None
    # pnpm 10 puts its own install in a first document; the project's lockfile
    # is the one with importers or packages for the project.
    doc = next((d for d in reversed(docs) if isinstance(d, dict) and (d.get("packages") or d.get("importers"))), None)
    if doc is None:
        return []

    direct: dict[str, bool] = {}  # name → only ever a dev dependency
    importers = doc.get("importers") or {".": doc}  # pre-workspace lockfiles keep deps at the top
    for importer in importers.values():
        if not isinstance(importer, dict):
            continue
        for field, dev in (("dependencies", False), ("optionalDependencies", False), ("devDependencies", True)):
            for name, spec in (importer.get(field) or {}).items():
                version = spec.get("version") if isinstance(spec, dict) else spec
                if isinstance(version, str) and version.startswith("link:"):
                    continue
                direct[name] = direct.get(name, True) and dev

    try:
        major = int(float(str(doc.get("lockfileVersion") or "9")))
    except ValueError:
        major = 9
    key_pattern = _PNPM5_KEY if major < 6 else _PNPM_KEY
    # Before lockfile 9, pnpm marked every package with an install script
    # requiresBuild, so its absence means none. 9 dropped the field.
    no_script = False if major < 9 else None
    out = []
    for key, meta in (doc.get("packages") or {}).items():
        if not isinstance(meta, dict):
            continue
        if key.startswith(("file:", "link:")):
            # A local package, keyed by its path; pnpm 6 records no version.
            name, version = str(meta.get("name") or key), str(meta.get("version") or "local")
        else:
            m = key_pattern.match(key)
            if not m:
                continue
            name, version = m.group(1), m.group(2)
        resolution = meta.get("resolution") or {}
        if not isinstance(resolution, dict):
            resolution = {}
        if resolution.get("type") == "git" or "repo" in resolution:
            source = "git"
        elif "directory" in resolution:
            source = "path"
        else:
            source = _source(str(resolution.get("tarball") or ""))
        out.append(Package(NPM, meta.get("name") or name, str(meta.get("version") or version),
                           direct=name in direct, dev=direct.get(name, bool(meta.get("dev"))),
                           source=source, integrity=str(resolution.get("integrity") or ""),
                           install_script=True if meta.get("requiresBuild") else no_script))
    return out
