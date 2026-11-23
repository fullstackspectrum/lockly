"""Compare two versions of a lockfile: what moved, and what deserves a look."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from . import licenses, versions
from .model import Lockfile, Package

CHANGE_KINDS = ("added", "removed", "upgraded", "downgraded", "changed")

# Finding kinds, most serious first. Each says why a change deserves a
# reviewer's attention; the network ones need registry or OSV data.
FINDING_KINDS = (
    "hash",            # same version, different contents
    "install-script",  # now runs code when installed
    "publisher",       # published by a different account than before
    "provenance",      # the previous version had a provenance attestation; this one doesn't
    "source",          # comes from somewhere other than the registry, or from somewhere new
    "new-package",     # the package itself is only days old
    "young",           # this version is only days old
    "vulnerable",      # the new version has known vulnerabilities
    "deprecated",      # deprecated or yanked
    "copyleft",        # brings in copyleft terms
    "license",         # the licence changed
)
FAIL_ON_CHOICES = FINDING_KINDS + ("any",)


@dataclass
class Meta:
    """What the registry and OSV say about one version. Every field may be
    missing: not every registry exposes everything, and lookups can fail."""
    published: str = ""
    created: str = ""          # when the package itself was first published
    publisher: str = ""
    trusted_publisher: bool = False  # published from CI through OIDC, not a person's token
    # The release just before this one in the registry, whoever installed it.
    # An account takeover shows up as a release by a different, unfamiliar
    # account from the one before it.
    prev_version: str = ""
    prev_publisher: str = ""
    prev_trusted: bool = False
    prev_provenance: bool | None = None
    # Had this publisher published or maintained the package before? None
    # when the registry can't say.
    known_publisher: bool | None = None
    license: str = ""
    deprecated: str = ""       # the deprecation or yank message
    install_script: bool | None = None
    provenance: bool | None = None
    vulns: list[str] = field(default_factory=list)
    vuln_details: dict[str, dict] = field(default_factory=dict)  # id → {severity, summary}


@dataclass
class Change:
    lockfile: str
    kind: str
    ecosystem: str
    name: str
    old: Package | None = None
    new: Package | None = None
    old_meta: Meta | None = None
    new_meta: Meta | None = None

    @property
    def old_version(self) -> str:
        return self.old.version if self.old else ""

    @property
    def new_version(self) -> str:
        return self.new.version if self.new else ""

    @property
    def current(self) -> Package:
        assert self.new or self.old
        return self.new or self.old  # type: ignore[return-value]

    @property
    def direct(self) -> bool | None:
        return self.current.direct

    @property
    def dev(self) -> bool:
        return self.current.dev


@dataclass
class Finding:
    kind: str
    lockfile: str
    ecosystem: str
    name: str
    version: str
    message: str
    # False for findings worth showing but not stopping for (a known exploit
    # gets fixed, a licence moves between two permissive ones).
    gating: bool = True


@dataclass
class FileDiff:
    path: str
    kind: str
    ecosystem: str
    changes: list[Change] = field(default_factory=list)
    unchanged: int = 0
    findings: list[Finding] = field(default_factory=list)
    fixed: dict[str, list[str]] = field(default_factory=dict)  # "name version" → advisory IDs an upgrade fixed

    def count(self, kind: str) -> int:
        return sum(1 for c in self.changes if c.kind == kind)


@dataclass
class Diff:
    files: list[FileDiff]
    notes: list[str] = field(default_factory=list)  # what couldn't be checked, and why

    @property
    def changes(self) -> list[Change]:
        return [c for f in self.files for c in f.changes]

    @property
    def findings(self) -> list[Finding]:
        return [x for f in self.files for x in f.findings]

    def count(self, kind: str) -> int:
        return sum(f.count(kind) for f in self.files)

    def triggered(self, kinds: set[str]) -> dict[str, int]:
        gating = [f for f in self.findings if f.gating]
        if "any" in kinds:
            kinds = set(FINDING_KINDS)
        hits: dict[str, int] = {}
        for f in gating:
            if f.kind in kinds:
                hits[f.kind] = hits.get(f.kind, 0) + 1
        return hits


# ── Pairing ──────────────────────────────────────────────────────────

def _index(lock: Lockfile) -> dict[tuple[str, str], dict[str, Package]]:
    out: dict[tuple[str, str], dict[str, Package]] = {}
    for p in lock.packages:
        out.setdefault(p.key, {})[p.version] = p
    return out


def compare_lockfiles(old: Lockfile, new: Lockfile) -> FileDiff:
    a, b = _index(old), _index(new)
    result = FileDiff(new.path or old.path, new.kind or old.kind, new.ecosystem or old.ecosystem)
    path = result.path
    for key in sorted(set(a) | set(b), key=lambda k: k[1].lower()):
        before, after = a.get(key, {}), b.get(key, {})
        common = set(before) & set(after)
        result.unchanged += len(common)
        for version in sorted(common, key=versions.sort_key):
            o, n = before[version], after[version]
            # Same version, nothing to classify, but its contents or origin
            # may still have changed; keep it for the findings.
            if contents_differ(o.integrity, n.integrity) or o.source != n.source \
                    or (o.install_script is False and n.install_script):
                result.changes.append(Change(path, "changed", key[0], n.name, o, n))
                result.unchanged -= 1
        gone = sorted((v for v in before if v not in common), key=versions.sort_key)
        came = sorted((v for v in after if v not in common), key=versions.sort_key)
        # Pair leftovers in version order: 1.0, 2.0 → 1.1, 2.1 is two upgrades.
        while gone and came:
            o, n = before[gone.pop(0)], after[came.pop(0)]
            order = versions.compare(o.version, n.version)
            kind = "upgraded" if order == -1 else "downgraded" if order == 1 else "changed"
            result.changes.append(Change(path, kind, key[0], n.name, o, n))
        for v in gone:
            result.changes.append(Change(path, "removed", key[0], before[v].name, old=before[v]))
        for v in came:
            result.changes.append(Change(path, "added", key[0], after[v].name, new=after[v]))
    return result


# ── Findings ─────────────────────────────────────────────────────────

def _digests(integrity: str) -> dict[str, str]:
    """'sha512-abc sha1-def' → {sha512: abc, sha1: def}. Formats without an
    algorithm prefix (Cargo's hex) count as one unnamed algorithm."""
    out = {}
    for part in integrity.split():
        if part.startswith(("sha1-", "sha256-", "sha384-", "sha512-")):  # npm SRI
            alg, _, value = part.partition("-")
        elif ":" in part[:8]:  # sha256:… (uv, Poetry), h1:… (Go)
            alg, _, value = part.partition(":")
        elif "/" in part[:4]:  # Yarn Berry's cacheKey/hash: a new cacheKey re-hashes
            alg, _, value = part.partition("/")
        else:  # Cargo's bare hex
            alg, value = "", part
        out[alg] = value
    return out


def contents_differ(a: str, b: str) -> bool:
    """Same version, different hashes, by an algorithm both sides use. A
    lockfile tool moving from sha1 to sha512 isn't a change of contents."""
    if not a or not b:
        return False
    da, db = _digests(a), _digests(b)
    common = set(da) & set(db)
    return any(da[alg] != db[alg] for alg in common)


def _age_days(timestamp: str, now: datetime.datetime) -> float | None:
    if not timestamp:
        return None
    try:
        when = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return (now - when).total_seconds() / 86400


def _ago(days: float) -> str:
    if days < 1:
        hours = max(1, round(days * 24))
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    whole = round(days)
    return f"{whole} day{'s' if whole != 1 else ''} ago"


def find(fd: FileDiff, min_age_days: float = 3, new_package_days: float = 30,
         now: datetime.datetime | None = None) -> None:
    """Fill fd.findings from its changes and whatever enrichment added."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    out: list[Finding] = []
    fixed: dict[str, list[str]] = {}

    for c in fd.changes:
        if c.kind == "removed" or c.new is None:
            continue
        new, old = c.new, c.old
        nm, om = c.new_meta or Meta(), c.old_meta or Meta()

        def add(kind: str, message: str, gating: bool = True) -> None:
            out.append(Finding(kind, c.lockfile, c.ecosystem, c.name, new.version, message, gating))

        if old and old.version == new.version and contents_differ(old.integrity, new.integrity):
            add("hash", "same version, different contents: rebuilt, republished or tampered with")

        scripts = new.install_script if new.install_script is not None else nm.install_script
        had = (old.install_script if old and old.install_script is not None else om.install_script) if old else None
        if scripts and (old is None or had is False):
            add("install-script", "runs a script when installed" + (" (new in this version)" if old else ""))

        new_version = old is None or old.version != new.version
        if new_version and nm.publisher and nm.prev_publisher and nm.publisher != nm.prev_publisher:
            prev = f"{nm.prev_version} was published by {nm.prev_publisher}"
            if nm.trusted_publisher and not nm.prev_trusted:
                # Moving to trusted publishing is an improvement, not a takeover.
                add("publisher", f"now published through trusted publishing; {prev}", gating=False)
            elif nm.prev_trusted and not nm.trusted_publisher:
                add("publisher", f"published by {nm.publisher}, no longer through trusted publishing; {prev}")
            elif nm.known_publisher is False:
                add("publisher", f"published by {nm.publisher}, new to this package; {prev}")
            # A maintainer of the previous release taking a turn is routine.
        if new_version and nm.prev_provenance and nm.provenance is False:
            add("provenance", f"{nm.prev_version}, the release before it, was published with a provenance "
                              "attestation; this version wasn't")

        def origin(src: str) -> str:
            if not src:
                return "the registry"
            if src.startswith("replaced by "):
                return f"{src[12:]} (a replace directive)"
            return {"git": "a git repository", "path": "a local path", "patch": "a local patch"}.get(src, src)

        if old and new.source != old.source:
            add("source", f"now comes from {origin(new.source)} instead of {origin(old.source)}")
        elif old is None and new.source and new.source not in ("path", "patch"):
            add("source", f"comes from {origin(new.source)}, not the registry")

        created_age = _age_days(nm.created, now)
        if old is None and created_age is not None and created_age < new_package_days:
            add("new-package", f"the package was first published {_ago(created_age)}")
        published = new.published or nm.published
        age = _age_days(published, now)
        if c.kind != "removed" and age is not None and age < min_age_days and (old is None or old.version != new.version):
            add("young", f"this version was published {_ago(age)}")

        introduced = [v for v in nm.vulns if v not in set(om.vulns)]
        if nm.vulns and (old is None or introduced or old.version == new.version):
            shown = nm.vulns if old is None else introduced or nm.vulns
            add("vulnerable", f"{len(shown)} known vulnerabilit{'y' if len(shown) == 1 else 'ies'}: "
                + ", ".join(_vuln_label(v, nm) for v in shown[:4]) + (f" and {len(shown) - 4} more" if len(shown) > 4 else ""))
        resolved = [v for v in om.vulns if v not in set(nm.vulns)]
        if old and resolved:
            fixed[f"{c.name} {new.version}"] = resolved

        if nm.deprecated and not (om.deprecated and old and old.version == new.version):
            add("deprecated", nm.deprecated[:200])

        new_lic = new.license or nm.license
        old_lic = (old.license or om.license) if old else ""
        level = licenses.copyleft_level(new_lic) if new_lic else licenses.NONE
        old_level = licenses.copyleft_level(old_lic) if old_lic else licenses.NONE
        if level > old_level:
            add("copyleft", f"{licenses.LABELS[level]}: {new_lic}" + (f" (was {old_lic})" if old_lic else ""))
        elif old and old_lic and new_lic and licenses.normalise(old_lic) != licenses.normalise(new_lic):
            add("license", f"licence changed from {old_lic} to {new_lic}",
                gating=level > licenses.NONE or old_level > licenses.NONE)
        elif old and old_lic and not new_lic and (old.license or c.new_meta is not None):
            # Only when the new version's licence was actually looked for: a
            # lockfile field that vanished, or registry data that has none.
            add("license", f"no longer declares a licence (was {old_lic})", gating=False)

    order = {k: n for n, k in enumerate(FINDING_KINDS)}
    fd.findings = sorted(out, key=lambda f: (not f.gating, order[f.kind], f.name.lower()))
    fd.fixed = fixed


def _vuln_label(vid: str, meta: Meta) -> str:
    sev = meta.vuln_details.get(vid, {}).get("severity", "")
    return f"{vid} ({sev})" if sev and sev != "unknown" else vid


def diff(pairs: list[tuple[Lockfile, Lockfile]]) -> Diff:
    return Diff([compare_lockfiles(old, new) for old, new in pairs])
