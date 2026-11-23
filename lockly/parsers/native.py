"""Go modules (go.mod, go.sum) and Cargo.lock."""

from __future__ import annotations

import re
import tomllib
import urllib.parse

from ..model import CARGO, GO, LockfileError, Package, normalise_name

# ── Go ───────────────────────────────────────────────────────────────

_REQUIRE = re.compile(r"^\s*(\S+)\s+(v\S+)(\s*//\s*indirect)?")
_REPLACE = re.compile(r"^\s*(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?")


def _go_sum(text: str) -> dict[tuple[str, str], str]:
    """(module, version) → the h1: hash of its contents (not its go.mod)."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and not parts[1].endswith("/go.mod"):
            out[(parts[0], parts[1])] = parts[2]
    return out


def parse_go_mod(text: str, manifest: str | None = None) -> list[Package]:
    """go.mod is Go's lockfile in effect: since Go 1.17 it lists every module
    in the build, at the version selected, with transitive ones marked
    // indirect. go.sum, passed as the manifest, adds the content hashes."""
    hashes = _go_sum(manifest) if manifest else {}
    requires: list[tuple[str, str, bool]] = []
    replaces: dict[str, tuple[str, str]] = {}
    block = ""
    for raw in text.splitlines():
        line = raw.split("//")[0].rstrip() if "// indirect" not in raw else raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith("(") and stripped.split()[0] in ("require", "replace", "exclude", "retract", "tool", "ignore", "godebug"):
            block = stripped.split()[0]
            continue
        if stripped == ")":
            block = ""
            continue
        kind, rest = (block, stripped) if block else (stripped.split()[0], stripped[len(stripped.split()[0]):])
        if kind == "require":
            m = _REQUIRE.match(rest)
            if m:
                requires.append((m.group(1), m.group(2), bool(m.group(3))))
        elif kind == "replace":
            m = _REPLACE.match(rest)
            if m:
                replaces[m.group(1)] = (m.group(3), m.group(4) or "")
    out = []
    for module, version, indirect in requires:
        source = ""
        if module in replaces:
            target, target_version = replaces[module]
            # A replace to a local directory, or to a different module, means
            # the code no longer comes from where the name says.
            source = "path" if target.startswith((".", "/")) else f"replaced by {target}"
            version = target_version or version
        out.append(Package(GO, module, version, direct=not indirect, source=source,
                           integrity=hashes.get((module, version), "")))
    return out


def parse_go_sum(text: str, manifest: str | None = None) -> list[Package]:
    """go.sum on its own: every module version the build has verified. It can
    hold more than one version of a module, and can't say which are direct."""
    return [Package(GO, module, version, integrity=h) for (module, version), h in _go_sum(text).items()]


# ── Cargo.lock ───────────────────────────────────────────────────────

_CRATES_IO = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")


def parse_cargo(text: str, manifest: str | None = None) -> list[Package]:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise LockfileError(f"isn't valid TOML ({exc})") from None
    packages = doc.get("package") or []
    # Workspace members have no source; what they depend on is direct.
    members = [p for p in packages if "source" not in p]
    member_names = {normalise_name(CARGO, p.get("name", "")) for p in members}
    direct = {normalise_name(CARGO, d.split()[0]) for m in members for d in m.get("dependencies") or []}
    out = []
    for p in packages:
        if "source" not in p:
            continue
        name = p.get("name", "")
        source = str(p.get("source") or "")
        if source in _CRATES_IO:
            src = ""
        elif source.startswith("git+"):
            src = "git"
        else:
            src = urllib.parse.urlsplit(source.split("+", 1)[-1]).netloc or source
        key = normalise_name(CARGO, name)
        out.append(Package(CARGO, name, str(p.get("version") or ""),
                           direct=(key in direct) if members else None,
                           source=src, integrity=str(p.get("checksum") or "")))
    return [p for p in out if p.version and normalise_name(CARGO, p.name) not in member_names]
