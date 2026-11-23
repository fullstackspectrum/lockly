"""uv.lock, poetry.lock and Pipfile.lock."""

from __future__ import annotations

import json
import re
import tomllib
import urllib.parse

from ..model import PYPI, LockfileError, Package, normalise_name

_DEFAULT_INDEXES = {"pypi.org", "files.pythonhosted.org"}


def _host(url: str) -> str:
    host = urllib.parse.urlsplit(url).netloc.lower()
    return "" if host in _DEFAULT_INDEXES else host or url


def _toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise LockfileError(f"isn't valid TOML ({exc})") from None


def _requirement_names(specs) -> set[str]:
    """Names from PEP 508 strings: 'httpx[http2]>=0.27; python_version<"3.12"'."""
    out = set()
    for spec in specs or []:
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(spec))
        if m:
            out.add(normalise_name(PYPI, m.group(1)))
    return out


# ── uv.lock ──────────────────────────────────────────────────────────

def parse_uv(text: str, manifest: str | None = None) -> list[Package]:
    doc = _toml(text)
    packages = doc.get("package") or []
    roots = [p for p in packages if isinstance(p.get("source"), dict)
             and ({"editable", "virtual"} & set(p["source"]))]
    direct, dev_direct = set(), set()
    for root in roots:
        direct |= {normalise_name(PYPI, d["name"]) for d in root.get("dependencies") or [] if "name" in d}
        for extra in (root.get("optional-dependencies") or {}).values():
            direct |= {normalise_name(PYPI, d["name"]) for d in extra if "name" in d}
        for group in (root.get("dev-dependencies") or {}).values():
            dev_direct |= {normalise_name(PYPI, d["name"]) for d in group if "name" in d}
    root_names = {normalise_name(PYPI, r["name"]) for r in roots}

    out = []
    for p in packages:
        name = p.get("name")
        if not name or normalise_name(PYPI, name) in root_names:
            continue
        source = p.get("source") or {}
        if "registry" in source:
            src = _host(source["registry"])
        elif "git" in source:
            src = "git"
        elif {"path", "directory", "editable"} & set(source):
            src = "path"
        elif "url" in source:
            src = _host(source["url"])
        else:
            src = ""
        sdist = p.get("sdist") or {}
        wheels = p.get("wheels") or []
        uploaded = [w.get("upload-time") for w in [sdist, *wheels] if w.get("upload-time")]
        key = normalise_name(PYPI, name)
        out.append(Package(PYPI, name, str(p.get("version") or ""),
                           direct=(key in direct or key in dev_direct) if roots else None,
                           dev=key in dev_direct and key not in direct,
                           source=src, integrity=str(sdist.get("hash") or ""),
                           published=min(uploaded) if uploaded else ""))
    return [p for p in out if p.version]


# ── poetry.lock ──────────────────────────────────────────────────────

def _poetry_direct(manifest: str | None) -> tuple[set[str], set[str]] | None:
    """(main, dev) dependency names from a pyproject.toml, if given."""
    if not manifest:
        return None
    try:
        doc = tomllib.loads(manifest)
    except tomllib.TOMLDecodeError:
        return None
    poetry = (doc.get("tool") or {}).get("poetry") or {}
    main = {normalise_name(PYPI, n) for n in (poetry.get("dependencies") or {}) if n.lower() != "python"}
    main |= _requirement_names((doc.get("project") or {}).get("dependencies"))
    for extra in ((doc.get("project") or {}).get("optional-dependencies") or {}).values():
        main |= _requirement_names(extra)
    dev = {normalise_name(PYPI, n) for n in (poetry.get("dev-dependencies") or {})}
    for group in (poetry.get("group") or {}).values():
        dev |= {normalise_name(PYPI, n) for n in ((group or {}).get("dependencies") or {})}
    for group in (doc.get("dependency-groups") or {}).values():
        dev |= _requirement_names(g for g in group if isinstance(g, str))
    return main, dev


def parse_poetry(text: str, manifest: str | None = None) -> list[Package]:
    doc = _toml(text)
    direct = _poetry_direct(manifest)
    out = []
    for p in doc.get("package") or []:
        name = p.get("name")
        if not name:
            continue
        key = normalise_name(PYPI, name)
        source = p.get("source") or {}
        stype = source.get("type", "")
        src = "git" if stype == "git" else "path" if stype in ("directory", "file") else _host(source.get("url", "")) if source else ""
        sdist = next((f.get("hash", "") for f in p.get("files") or [] if str(f.get("file", "")).endswith((".tar.gz", ".zip"))), "")
        groups = p.get("groups") or []
        dev = (p.get("category") == "dev") or (bool(groups) and "main" not in groups)
        out.append(Package(PYPI, name, str(p.get("version") or ""),
                           direct=(key in direct[0] | direct[1]) if direct else None,
                           dev=dev, source=src, integrity=sdist))
    return [p for p in out if p.version]


# ── Pipfile.lock ─────────────────────────────────────────────────────

def _pipfile_direct(manifest: str | None) -> tuple[set[str], set[str]] | None:
    if not manifest:
        return None
    try:
        doc = tomllib.loads(manifest)
    except tomllib.TOMLDecodeError:
        return None
    return ({normalise_name(PYPI, n) for n in (doc.get("packages") or {})},
            {normalise_name(PYPI, n) for n in (doc.get("dev-packages") or {})})


def parse_pipfile(text: str, manifest: str | None = None) -> list[Package]:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise LockfileError(f"isn't valid JSON ({exc})") from None
    if not isinstance(doc, dict) or "_meta" not in doc:
        raise LockfileError("isn't a Pipfile.lock")
    indexes = {s.get("name"): s.get("url", "") for s in (doc["_meta"].get("sources") or []) if isinstance(s, dict)}
    direct = _pipfile_direct(manifest)
    out: dict[str, Package] = {}
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in (doc.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            key = normalise_name(PYPI, name)
            if key in out:  # in both: it's a runtime dependency
                out[key].dev = out[key].dev and dev
                continue
            version = str(meta.get("version") or "").lstrip("=")
            if "git" in meta:
                src, version = "git", version or str(meta.get("ref") or "")[:12]
            elif "path" in meta or "file" in meta:
                src = "path"
            else:
                src = _host(indexes.get(meta.get("index"), "")) if meta.get("index") else ""
            out[key] = Package(PYPI, name, version,
                               direct=(key in direct[0] | direct[1]) if direct else None,
                               dev=dev, source=src)
    return [p for p in out.values() if p.version]
