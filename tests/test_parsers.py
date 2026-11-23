"""Every lockfile format, from fixtures written in each tool's exact format."""

from pathlib import Path

import pytest

from lockly import miniyaml, parsers
from lockly.model import LockfileError

FIX = Path(__file__).parent / "fixtures"


def load(name, as_name=None, manifest=None):
    text = (FIX / name).read_text()
    man = (FIX / manifest).read_text() if manifest else None
    return {p.name: p for p in parsers.parse(as_name or name, text, man).packages}


def test_package_lock():
    pk = load("package-lock.json")
    assert set(pk) == {"left-pad", "@scope/util", "tiny", "jest-lite"}  # no workspace link
    assert pk["left-pad"].direct and pk["left-pad"].license == "WTFPL"
    assert pk["@scope/util"].install_script is True and pk["left-pad"].install_script is False
    assert pk["tiny"].direct is False and pk["tiny"].source == "npm.example.com"
    assert pk["jest-lite"].dev and pk["jest-lite"].direct


def test_yarn_classic_with_manifest():
    pk = load("yarn-classic.lock", "yarn.lock", "package.json")
    assert pk["left-pad"].version == "1.3.0" and pk["left-pad"].direct
    assert pk["tiny"].source == "git" and pk["tiny"].dev
    assert load("yarn-classic.lock", "yarn.lock")["left-pad"].direct is None  # no manifest, can't tell


def test_yarn_berry():
    pk = load("yarn-berry.lock", "yarn.lock")
    assert set(pk) == {"@scope/util", "left-pad"}  # the workspace itself is skipped
    assert pk["left-pad"].integrity == "10/aaa"


def test_pnpm_9_reads_the_project_document():
    pk = load("pnpm-lock.yaml")
    assert "pnpm" not in pk  # pnpm 10's first document is pnpm's own install
    assert pk["@scope/util"].direct and not pk["@scope/util"].dev
    assert pk["left-pad"].dev and pk["tiny"].direct is False
    assert pk["tiny"].source == "npm.example.com"
    assert pk["left-pad"].install_script is None  # lockfile 9 doesn't record it


def test_pnpm_5_keys_and_install_scripts():
    pk = load("pnpm5-lock.yaml", "pnpm-lock.yaml")
    assert pk["esbuild"].version == "0.15.18" and pk["esbuild"].install_script is True
    assert pk["@esbuild/linux-x64"].install_script is False  # pre-9: absence means none
    assert pk["acorn-jsx"].version == "5.3.2"  # peer suffix _acorn@8.8.1 dropped
    assert pk["@demo/dir"].source == "path" and pk["@demo/dir"].version == "local"


def test_uv():
    pk = load("uv.lock")
    assert "app" not in pk
    assert pk["httpx"].direct and not pk["httpx"].dev and pk["idna"].direct is False
    assert pk["pytest"].dev and pk["pytest"].direct
    assert pk["httpx"].published == "2024-02-21T13:07:50.455Z"  # the earliest upload
    assert pk["private-lib"].source == "git"


def test_poetry_with_manifest():
    pk = load("poetry.lock", manifest="pyproject.toml")
    assert pk["requests"].direct and pk["requests"].integrity == "sha256:bbb"  # the sdist's hash
    assert pk["Pytest_Mock"].direct and pk["Pytest_Mock"].dev  # matched through PEP 503 names
    assert pk["internal"].source == "pypi.internal.example.com" and pk["internal"].direct is False


def test_pipfile():
    pk = load("Pipfile.lock", manifest="Pipfile")
    assert not pk["requests"].dev  # in both sections: a runtime dependency
    assert pk["corp-lib"].source == "pypi.corp.example.com"
    assert pk["edge"].source == "git" and pk["pytest"].dev and pk["pytest"].direct


def test_go_mod_with_go_sum():
    pk = load("go.mod", manifest="go.sum")
    assert pk["github.com/spf13/cobra"].direct and pk["github.com/spf13/cobra"].integrity == "h1:CCC="
    assert pk["github.com/inconshreveable/mousetrap"].direct is False
    net = pk["golang.org/x/net"]
    assert net.version == "v0.25.1" and net.source == "replaced by github.com/example/net-fork"


def test_go_sum_alone():
    pk = parsers.parse("go.sum", (FIX / "go.sum").read_text()).packages
    assert {(p.name, p.version) for p in pk} == {("github.com/inconshreveable/mousetrap", "v1.1.0"),
                                                 ("github.com/spf13/cobra", "v1.8.0")}


def test_cargo():
    pk = load("Cargo.lock")
    assert "app" not in pk
    assert pk["serde"].direct and pk["serde_derive"].direct is False
    assert pk["fork"].source == "git"


def test_errors_and_detection():
    with pytest.raises(LockfileError, match="not a lockfile Lockly knows"):
        parsers.format_for("requirements.txt")
    with pytest.raises(LockfileError, match="isn't valid JSON"):
        parsers.parse("package-lock.json", "{nope")
    with pytest.raises(LockfileError, match="isn't valid TOML"):
        parsers.parse("Cargo.lock", "[[package")
    assert parsers.parse("Cargo.lock", "").packages == []  # absent on one side of a diff
    assert parsers.format_for("lockfile.json", kind="package-lock").kind == "package-lock"


def test_miniyaml():
    doc = miniyaml.loads("a:\n  'b:c': {x: 1, y: [p, q]}\n  d:\n    - one\n    - two\n  e: 'it''s'\n  f: 1.10\n")
    assert doc == {"a": {"b:c": {"x": "1", "y": ["p", "q"]}, "d": ["one", "two"], "e": "it's", "f": "1.10"}}
    assert miniyaml.loads("file:x/y:\n  name: z\n") == {"file:x/y": {"name": "z"}}
    with pytest.raises(ValueError):
        miniyaml.loads("a: 'unterminated\n")
