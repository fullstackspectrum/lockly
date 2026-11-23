"""Pairing, change kinds, every finding rule, and the registry lookups."""

import datetime

import pytest

from lockly import diff as D
from lockly import enrich, licenses
from lockly.diff import Change, FileDiff, Meta
from lockly.model import CARGO, NPM, PYPI, Lockfile, Package

NOW = datetime.datetime(2026, 11, 24, tzinfo=datetime.timezone.utc)


def lock(*pkgs, kind="package-lock", eco=NPM):
    return Lockfile("package-lock.json", kind, eco, list(pkgs))


def pkg(name, version, **kw):
    return Package(kw.pop("ecosystem", NPM), name, version, **kw)


# ── Pairing ──────────────────────────────────────────────────────────

def test_change_kinds():
    old = lock(pkg("a", "1.0.0"), pkg("b", "2.0.0"), pkg("c", "1.0.0"), pkg("d", "1.0.0"), pkg("e", "1.0.0"))
    new = lock(pkg("a", "1.1.0"), pkg("b", "1.9.0"), pkg("c", "1.0.0"), pkg("f", "0.1.0"), pkg("e", "deadbeef"))
    fd = D.compare_lockfiles(old, new)
    kinds = {c.name: c.kind for c in fd.changes}
    assert kinds == {"a": "upgraded", "b": "downgraded", "d": "removed", "f": "added", "e": "changed"}
    assert fd.unchanged == 1


def test_several_versions_pair_in_order():
    old = lock(pkg("x", "1.0.0"), pkg("x", "2.0.0"))
    new = lock(pkg("x", "1.1.0"), pkg("x", "2.1.0"))
    fd = D.compare_lockfiles(old, new)
    assert [(c.old_version, c.new_version, c.kind) for c in fd.changes] == [
        ("1.0.0", "1.1.0", "upgraded"), ("2.0.0", "2.1.0", "upgraded")]


def test_pypi_names_pair_after_normalising():
    old = lock(pkg("Pytest_Mock", "3.0", ecosystem=PYPI), eco=PYPI)
    new = lock(pkg("pytest-mock", "3.1", ecosystem=PYPI), eco=PYPI)
    assert [c.kind for c in D.compare_lockfiles(old, new).changes] == ["upgraded"]


def test_same_version_changes_are_kept():
    old = lock(pkg("a", "1.0.0", integrity="sha512-AAA"), pkg("b", "1.0.0", source=""),
               pkg("c", "1.0.0", integrity="sha1-old"))
    new = lock(pkg("a", "1.0.0", integrity="sha512-BBB"), pkg("b", "1.0.0", source="git"),
               pkg("c", "1.0.0", integrity="sha512-new"))
    fd = D.compare_lockfiles(old, new)
    # c only moved from sha1 to sha512: not comparable, so not a change.
    assert sorted(c.name for c in fd.changes) == ["a", "b"]


def test_contents_differ():
    assert D.contents_differ("sha512-a", "sha512-b")
    assert not D.contents_differ("sha1-a", "sha512-b")
    assert not D.contents_differ("sha512-a sha1-x", "sha512-a")
    assert not D.contents_differ("10/aa", "8/bb")  # Yarn re-hashed under a new cache key
    assert D.contents_differ("h1:a", "h1:b") and D.contents_differ("aaa", "bbb")


# ── Findings ─────────────────────────────────────────────────────────

def findings(changes):
    fd = FileDiff("package-lock.json", "package-lock", NPM, changes)
    D.find(fd, now=NOW)
    return {(f.kind, f.name): f for f in fd.findings}, fd


def test_lockfile_only_findings():
    f, _ = findings([
        Change("p", "changed", NPM, "tampered", pkg("tampered", "1.0.0", integrity="sha512-a"),
               pkg("tampered", "1.0.0", integrity="sha512-b")),
        Change("p", "upgraded", NPM, "scripted", pkg("scripted", "1.0.0", install_script=False),
               pkg("scripted", "1.1.0", install_script=True)),
        Change("p", "added", NPM, "from-git", new=pkg("from-git", "1.0.0", source="git")),
        Change("p", "upgraded", NPM, "moved", pkg("moved", "1.0.0"), pkg("moved", "1.1.0", source="npm.evil.example")),
        Change("p", "upgraded", NPM, "relicensed", pkg("relicensed", "1.0.0", license="MIT"),
               pkg("relicensed", "2.0.0", license="AGPL-3.0-only")),
        Change("p", "upgraded", NPM, "reworded", pkg("reworded", "1.0.0", license="MIT/Apache-2.0"),
               pkg("reworded", "1.1.0", license="Apache-2.0 OR MIT")),
    ])
    assert f[("hash", "tampered")].gating
    assert "new in this version" in f[("install-script", "scripted")].message
    assert f[("source", "from-git")].message == "comes from a git repository, not the registry"
    assert "npm.evil.example" in f[("source", "moved")].message
    assert "network copyleft" in f[("copyleft", "relicensed")].message
    assert ("license", "reworded") not in f  # the same licence, written differently


def test_publisher_rules():
    def change(name, meta):
        return Change("p", "upgraded", NPM, name, pkg(name, "1.0.0"), pkg(name, "1.1.0"), Meta(), meta)

    f, _ = findings([
        change("stranger", Meta(publisher="mallory", prev_version="1.0.9", prev_publisher="alice", known_publisher=False)),
        change("teammate", Meta(publisher="bob", prev_version="1.0.9", prev_publisher="alice", known_publisher=True)),
        change("to-ci", Meta(publisher="GitHub Actions", trusted_publisher=True, prev_version="1.0.9", prev_publisher="alice")),
        change("from-ci", Meta(publisher="mallory", prev_version="1.0.9", prev_publisher="GitHub Actions", prev_trusted=True)),
    ])
    assert f[("publisher", "stranger")].gating and "new to this package" in f[("publisher", "stranger")].message
    assert ("publisher", "teammate") not in f
    assert not f[("publisher", "to-ci")].gating
    assert f[("publisher", "from-ci")].gating and "no longer through trusted publishing" in f[("publisher", "from-ci")].message


def test_registry_findings():
    f, fd = findings([
        Change("p", "added", NPM, "brand-new", new=pkg("brand-new", "0.0.1"),
               new_meta=Meta(created="2026-11-20T00:00:00Z", published="2026-11-23T20:00:00Z")),
        Change("p", "upgraded", NPM, "fresh", pkg("fresh", "1.0.0"), pkg("fresh", "1.0.1"), Meta(),
               Meta(published="2026-11-22T00:00:00Z")),
        Change("p", "upgraded", NPM, "lost-prov", pkg("lost-prov", "1.0.0"), pkg("lost-prov", "1.0.1"),
               Meta(), Meta(provenance=False, prev_version="1.0.0", prev_provenance=True)),
        Change("p", "upgraded", NPM, "vuln", pkg("vuln", "1.0.0"), pkg("vuln", "1.1.0"),
               Meta(vulns=["GHSA-old"]), Meta(vulns=["GHSA-new"], vuln_details={"GHSA-new": {"severity": "high"}})),
        Change("p", "upgraded", NPM, "dep", pkg("dep", "1.0.0"), pkg("dep", "1.1.0"), Meta(), Meta(deprecated="use x")),
    ])
    assert "4 days ago" in f[("new-package", "brand-new")].message
    assert "hours ago" in f[("young", "brand-new")].message
    assert "2 days ago" in f[("young", "fresh")].message
    assert ("provenance", "lost-prov") in f
    assert f[("vulnerable", "vuln")].message == "1 known vulnerability: GHSA-new (high)"
    assert fd.fixed == {"vuln 1.1.0": ["GHSA-old"]}
    assert f[("deprecated", "dep")].message == "use x"


def test_findings_order_and_gating():
    d = D.Diff([FileDiff("a", "package-lock", NPM, findings=[
        D.Finding("license", "a", NPM, "x", "1", "m", gating=False),
        D.Finding("hash", "a", NPM, "y", "1", "m")])])
    assert d.triggered({"any"}) == {"hash": 1}
    assert d.triggered({"license"}) == {}


def test_licence_normalisation():
    assert licenses.normalise("MIT License") == licenses.normalise("MIT")
    assert licenses.normalise("MIT/Apache-2.0") == licenses.normalise("Apache-2.0 OR MIT")
    assert licenses.normalise("Apache-2.0 license") == "apache-2.0"


# ── Enrichment, against a fake registry ──────────────────────────────

NPM_DOC = {
    "time": {"created": "2015-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z",
             "1.0.1": "2021-01-01T00:00:00Z", "1.1.0": "2026-11-23T00:00:00Z"},
    "versions": {
        "1.0.0": {"_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}], "license": "MIT",
                  "dist": {"attestations": {"provenance": {}}}},
        "1.0.1": {"_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}], "license": "MIT",
                  "dist": {"attestations": {"provenance": {"predicateType": "x"}}}},
        "1.1.0": {"_npmUser": {"name": "mallory"}, "maintainers": [{"name": "mallory"}], "license": "MIT",
                  "scripts": {"postinstall": "node steal.js"}, "dist": {}},
    },
}


def test_enrich_npm_end_to_end(monkeypatch):
    calls = []

    def fake(url, body=None):
        calls.append(url)
        if "registry.npmjs.org" in url:
            return NPM_DOC
        if "querybatch" in url:
            return {"results": [{"vulns": [{"id": "GHSA-1"}]} if q["version"] == "1.1.0" else {}
                                for q in body["queries"]]}
        if "/v1/vulns/" in url:
            return {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        raise AssertionError(url)

    monkeypatch.setattr(enrich, "fetch", fake)
    d = D.diff([(lock(pkg("lib", "1.0.0")), lock(pkg("lib", "1.1.0")))])
    enrich.enrich(d)
    fd = d.files[0]
    D.find(fd, now=NOW)
    kinds = {f.kind for f in fd.findings}
    assert {"install-script", "publisher", "provenance", "young", "vulnerable"} <= kinds
    assert "GHSA-1 (critical)" in next(f.message for f in fd.findings if f.kind == "vulnerable")
    assert d.notes == []

    # Cached: a second run makes no registry requests (OSV's batch always runs).
    calls.clear()
    enrich.enrich(D.diff([(lock(pkg("lib", "1.0.0")), lock(pkg("lib", "1.1.0")))]))
    assert [c for c in calls if "registry.npmjs.org" in c] == []


def test_enrich_failure_leaves_a_note():
    d = D.diff([(lock(pkg("lib", "1.0.0")), lock(pkg("lib", "1.1.0")))])
    enrich.enrich(d)  # conftest refuses every request
    assert any(n.startswith("npm lookups incomplete") for n in d.notes)
    assert any(n.startswith("OSV lookups incomplete") for n in d.notes)


def test_enrich_skips_removed_and_non_registry(monkeypatch):
    seen = []
    monkeypatch.setattr(enrich, "fetch", lambda url, body=None: seen.append(url) or {"results": []})
    d = D.diff([(lock(pkg("gone", "1.0.0")), lock(pkg("from-git", "1.0.0", source="git")))])
    enrich.enrich(d)
    assert not [u for u in seen if "registry.npmjs.org" in u]


def test_go_proxy_escaping():
    assert enrich._go_escape("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"


@pytest.mark.parametrize("versions_, version, expected", [
    (["1.0.0", "1.0.1", "1.1.0", "2.0.0-beta.1"], "1.1.0", "1.0.1"),
    (["1.0.0", "2.0.0-beta.1", "2.0.0-beta.2"], "2.0.0-beta.2", "2.0.0-beta.1"),
    (["1.0.0"], "1.0.0", ""),
])
def test_previous_release(versions_, version, expected):
    assert enrich._previous(versions_, version) == expected


def test_crates_uses_one_request_per_crate(monkeypatch):
    monkeypatch.setattr(enrich, "_crates_last", [0.0])
    doc = {"versions": [
        {"num": "1.0.1", "created_at": "2026-01-02T00:00:00Z", "license": "MIT", "published_by": {"login": "eve"}},
        {"num": "1.0.0", "created_at": "2025-01-01T00:00:00Z", "license": "MIT", "published_by": {"login": "dtolnay"}},
    ]}
    monkeypatch.setattr(enrich, "fetch", lambda url, body=None: doc)
    meta = enrich._crates("serde", "1.0.1", True, cache=False)
    assert (meta.publisher, meta.prev_publisher, meta.known_publisher) == ("eve", "dtolnay", False)
    assert meta.created == "2025-01-01T00:00:00Z"
