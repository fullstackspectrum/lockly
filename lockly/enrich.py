"""What the registries and OSV say about the versions that changed.

Only changed packages are looked up, so a lockfile with thousands of entries
and a handful of changes costs a handful of requests. Responses are cached for
a day. A lookup that fails leaves that field empty and a note on the diff; it
never stops the report.

  npm        registry.npmjs.org: publish time, publisher and whether it was
             trusted publishing, provenance, licence, install scripts,
             deprecation, when the package was created
  PyPI       pypi.org: upload time, licence, yanked, when the project was created
  crates.io  crates.io API: publish time, publisher, licence, yanked, created
             (crates.io asks crawlers for one request a second, so these run
             one at a time)
  Go         proxy.golang.org: publish time, when the module first appeared
  all        OSV: known vulnerabilities in the old and new versions
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__, cvss, versions
from .diff import Change, Diff, Meta
from .model import CARGO, GO, NPM, PYPI

_TIMEOUT = 5  # per connect and read, so a dead network costs seconds, not minutes
_DAY = 24 * 60 * 60
_MAX_BODY = 64_000_000  # the largest npm packuments run to tens of megabytes
_USER_AGENT = f"lockly/{__version__} (+https://github.com/fullstackspectrum/lockly)"


class LookupError_(Exception):
    pass


# ── HTTP and cache ───────────────────────────────────────────────────

def cache_dir() -> Path:
    if os.environ.get("LOCKLY_CACHE_DIR"):
        return Path(os.environ["LOCKLY_CACHE_DIR"])
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "lockly"


def _cache_path(url: str) -> Path:
    import hashlib

    return cache_dir() / "http" / (hashlib.sha256(url.encode()).hexdigest()[:40] + ".json")


def fetch(url: str, body: dict | None = None):
    """GET (or POST JSON) and parse JSON. Tests replace this, so no test
    reaches the network. 404 returns None."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data, {"Accept": "application/json", "User-Agent": _USER_AGENT,
                                             **({"Content-Type": "application/json"} if data else {})})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = resp.read(_MAX_BODY + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise LookupError_(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LookupError_(f"can't reach {urllib.parse.urlsplit(url).netloc} ({getattr(exc, 'reason', exc)})") from None
    if len(raw) > _MAX_BODY:
        raise LookupError_(f"response from {urllib.parse.urlsplit(url).netloc} is too large")
    return json.loads(raw)


def _get(url: str, use_cache: bool = True):
    path = _cache_path(url)
    if use_cache:
        try:
            if time.time() - path.stat().st_mtime < _DAY:
                return json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            pass
    value = fetch(url)
    if use_cache:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
            tmp.write_text(json.dumps(value), "utf-8")
            tmp.replace(path)
        except OSError:
            pass
    return value


# ── Registries ───────────────────────────────────────────────────────

def _previous(all_versions, version: str) -> str:
    """The release just before this one: the highest lower version, skipping
    pre-releases unless this is one."""
    stable = "-" not in version
    lower = [v for v in all_versions if versions.compare(v, version) == -1 and (not stable or "-" not in v)]
    return max(lower, key=versions.sort_key) if lower else ""


def _npm(name: str, version: str, want_created: bool, cache: bool) -> Meta:
    doc = _get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"), cache) or {}
    all_versions = doc.get("versions") or {}
    v = all_versions.get(version) or {}
    user = v.get("_npmUser") or {}
    prev = _previous(all_versions, version)
    pv = all_versions.get(prev) or {}
    prev_user = pv.get("_npmUser") or {}
    known = None
    if user.get("name") and prev:
        maintainers = {m.get("name") for m in pv.get("maintainers") or []}
        earlier = {(all_versions[x].get("_npmUser") or {}).get("name") for x in all_versions
                   if versions.compare(x, version) == -1}
        known = user["name"] in maintainers | earlier
    scripts = v.get("scripts") or {}
    times = doc.get("time") or {}
    lic = v.get("license")
    if isinstance(lic, dict):  # old packages: {"type": "MIT", "url": ...}
        lic = lic.get("type", "")
    return Meta(
        published=str(times.get(version) or ""),
        created=str(times.get("created") or "") if want_created else "",
        publisher=str(user.get("name") or ""),
        trusted_publisher=bool(user.get("trustedPublisher")),
        prev_version=prev,
        prev_publisher=str(prev_user.get("name") or ""),
        prev_trusted=bool(prev_user.get("trustedPublisher")),
        prev_provenance=bool(((pv.get("dist") or {}).get("attestations") or {}).get("provenance")) if pv else None,
        known_publisher=known,
        license=lic if isinstance(lic, str) else "",
        deprecated=str(v.get("deprecated") or ""),
        install_script=any(k in scripts for k in ("preinstall", "install", "postinstall")) if v else None,
        provenance=bool(((v.get("dist") or {}).get("attestations") or {}).get("provenance")) if v else None,
    )


def _pypi(name: str, version: str, want_created: bool, cache: bool) -> Meta:
    doc = _get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json", cache) or {}
    info = doc.get("info") or {}
    uploads = [u.get("upload_time_iso_8601") for u in doc.get("urls") or [] if u.get("upload_time_iso_8601")]
    lic = info.get("license_expression") or info.get("license") or ""
    if not lic or len(lic) > 80:  # some projects paste the whole licence text
        classifiers = [c.split("::")[-1].strip() for c in info.get("classifiers") or [] if c.startswith("License ::")]
        lic = " OR ".join(classifiers) if classifiers else ("" if len(lic) > 80 else lic)
    meta = Meta(published=min(uploads) if uploads else "", license=lic,
                deprecated=f"yanked: {info.get('yanked_reason') or 'no reason given'}" if info.get("yanked") else "")
    if want_created:
        project = _get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", cache) or {}
        first = [f.get("upload_time_iso_8601") for files in (project.get("releases") or {}).values()
                 for f in files if f.get("upload_time_iso_8601")]
        meta.created = min(first) if first else ""
    return meta


_crates_lock = threading.Lock()
_crates_last = [0.0]


def _crates_get(url: str, cache: bool):
    path = _cache_path(url)
    if cache and path.exists() and time.time() - path.stat().st_mtime < _DAY:
        return _get(url, cache)
    with _crates_lock:  # crates.io's crawler policy: one request a second
        wait = _crates_last[0] + 1.0 - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            return _get(url, cache)
        finally:
            _crates_last[0] = time.monotonic()


def _crates(name: str, version: str, want_created: bool, cache: bool) -> Meta:
    # One request lists every version with its publisher, so it covers this
    # version, the one before it, and when the crate first appeared.
    doc = _crates_get(f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}/versions", cache) or {}
    by_num = {str(v.get("num")): v for v in doc.get("versions") or []}
    v = by_num.get(version) or {}
    prev = _previous(by_num, version)
    pv = by_num.get(prev) or {}
    login = lambda x: str((x.get("published_by") or {}).get("login") or "")  # noqa: E731
    publisher = login(v)
    earlier = {login(x) for num, x in by_num.items() if versions.compare(num, version) == -1}
    created = [str(x.get("created_at")) for x in by_num.values() if x.get("created_at")]
    return Meta(published=str(v.get("created_at") or ""), license=str(v.get("license") or ""),
                publisher=publisher, trusted_publisher=bool(v.get("trustpub_data")),
                prev_version=prev, prev_publisher=login(pv), prev_trusted=bool(pv.get("trustpub_data")),
                known_publisher=(publisher in earlier) if publisher and prev else None,
                deprecated="yanked" if v.get("yanked") else "",
                created=min(created) if want_created and created else "")


def _go_escape(path: str) -> str:
    """The module proxy's case encoding: Azure → !azure."""
    return "".join("!" + ch.lower() if ch.isupper() else ch for ch in path)


def _go(name: str, version: str, want_created: bool, cache: bool) -> Meta:
    base = f"https://proxy.golang.org/{_go_escape(name)}/@v/"
    info = _get(base + _go_escape(version) + ".info", cache) or {}
    meta = Meta(published=str(info.get("Time") or ""))
    if want_created:
        # The proxy has no creation date; the oldest tagged version's will do.
        listing = _get_text(base + "list", cache)
        tagged = sorted((v for v in listing.split() if v), key=versions.sort_key)
        if tagged:
            first = _get(base + _go_escape(tagged[0]) + ".info", cache) or {}
            meta.created = str(first.get("Time") or "")
    return meta


def _get_text(url: str, cache: bool) -> str:
    """/@v/list is plain text; cached as a JSON string."""
    path = _cache_path(url)
    if cache:
        try:
            if time.time() - path.stat().st_mtime < _DAY:
                return json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            pass
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            text = resp.read(1_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            return ""
        raise LookupError_(f"HTTP {exc.code} from proxy.golang.org") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LookupError_(f"can't reach proxy.golang.org ({getattr(exc, 'reason', exc)})") from None
    if cache:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(text), "utf-8")
        except OSError:
            pass
    return text


_REGISTRIES = {NPM: _npm, PYPI: _pypi, CARGO: _crates, GO: _go}


# ── OSV ──────────────────────────────────────────────────────────────

def _osv(queries: list[tuple[str, str, str]]) -> dict[tuple[str, str, str], list[str]]:
    """(ecosystem, name, version) → vulnerability IDs. querybatch isn't
    cached: it's one request, and new advisories matter most."""
    out: dict[tuple[str, str, str], list[str]] = {}
    for start in range(0, len(queries), 1000):
        chunk = queries[start:start + 1000]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        doc = fetch("https://api.osv.dev/v1/querybatch", body) or {}
        for q, r in zip(chunk, doc.get("results") or []):
            out[q] = sorted({x["id"] for x in r.get("vulns") or []})
    return out


def _osv_detail(vid: str, cache: bool) -> dict:
    record = _get(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid)}", cache) or {}
    score = None
    for s in record.get("severity") or []:
        if s.get("type") in ("CVSS_V3", "CVSS_V4"):
            score = cvss.score(s.get("score", ""))
            if score is not None:
                break
    label = cvss.severity(score)
    if label == "unknown":
        ghsa = str((record.get("database_specific") or {}).get("severity", "")).lower()
        label = {"moderate": "medium"}.get(ghsa, ghsa) if ghsa in ("critical", "high", "moderate", "medium", "low") else "unknown"
    cve = next((a for a in record.get("aliases") or [] if a.startswith("CVE-")), "")
    return {"severity": label, "score": score, "summary": (record.get("summary") or "")[:160], "cve": cve}


# ── Putting it together ──────────────────────────────────────────────

def enrich(d: Diff, cache: bool = True, workers: int = 8) -> None:
    """Fill old_meta and new_meta on every change, and note what failed."""
    wanted: dict[tuple[str, str, str], bool] = {}  # (eco, name, version) → also want created
    for c in d.changes:
        if c.kind == "removed":
            continue  # nothing is flagged on a removal, so nothing to look up
        for pkg, is_new in ((c.old, False), (c.new, True)):
            if pkg and pkg.ecosystem in _REGISTRIES and pkg.source in ("",) and pkg.version:
                key = (pkg.ecosystem, pkg.name, pkg.version)
                wanted[key] = wanted.get(key, False) or (is_new and c.kind == "added")

    failures: dict[str, str] = {}
    lock = threading.Lock()
    metas: dict[tuple[str, str, str], Meta] = {}

    def look(item):
        (eco, name, version), want_created = item
        try:
            metas[(eco, name, version)] = _REGISTRIES[eco](name, version, want_created, cache)
        except (LookupError_, ValueError) as exc:
            with lock:
                failures.setdefault(eco, str(exc))

    items = list(wanted.items())
    crates = [i for i in items if i[0][0] == CARGO]
    others = [i for i in items if i[0][0] != CARGO]
    with ThreadPoolExecutor(workers) as pool:
        future = pool.submit(lambda: [look(i) for i in crates])  # one at a time, in one thread
        list(pool.map(look, others))
        future.result()

    try:
        vulns = _osv(list(wanted)) if wanted else {}
    except (LookupError_, ValueError) as exc:
        vulns = {}
        failures["OSV"] = str(exc)
    for key, ids in vulns.items():
        metas.setdefault(key, Meta()).vulns = ids

    # Severity for the vulnerabilities the change brings in.
    introduced = {vid for c in d.changes if c.new for vid in vulns.get((c.new.ecosystem, c.new.name, c.new.version), [])
                  if not c.old or vid not in vulns.get((c.old.ecosystem, c.old.name, c.old.version), [])}
    details: dict[str, dict] = {}

    def detail(vid):
        try:
            details[vid] = _osv_detail(vid, cache)
        except (LookupError_, ValueError):
            pass

    with ThreadPoolExecutor(workers) as pool:
        list(pool.map(detail, sorted(introduced)))
    for meta in metas.values():
        meta.vuln_details = {v: details[v] for v in meta.vulns if v in details}

    for c in d.changes:
        if c.old:
            c.old_meta = metas.get((c.old.ecosystem, c.old.name, c.old.version))
        if c.new:
            c.new_meta = metas.get((c.new.ecosystem, c.new.name, c.new.version))
    for where, why in sorted(failures.items()):
        d.notes.append(f"{where} lookups incomplete: {why}")
