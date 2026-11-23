"""Git mode, the outputs (with hostile names) and the command line."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from lockly import cli, git
from lockly import diff as D
from lockly.html import to_html
from lockly.model import NPM, Lockfile, Package
from lockly.render import COMMENT_MARKER, to_json, to_markdown, to_text

FIX = Path(__file__).parent / "fixtures"


def run_git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    if not shutil.which("git"):
        pytest.skip("git isn't installed")
    run_git(tmp_path, "init", "-q", "-b", "main")
    run_git(tmp_path, "config", "user.email", "t@example.com")
    run_git(tmp_path, "config", "user.name", "t")
    web = tmp_path / "web"
    web.mkdir()
    (web / "package-lock.json").write_text((FIX / "package-lock.json").read_text())
    (tmp_path / "Cargo.lock").write_text((FIX / "Cargo.lock").read_text())
    (tmp_path / "README.md").write_text("x")
    run_git(tmp_path, "add", "-A")
    run_git(tmp_path, "commit", "-qm", "base")
    run_git(tmp_path, "switch", "-qc", "feature")
    lock = json.loads((web / "package-lock.json").read_text())
    lock["packages"]["node_modules/left-pad"]["version"] = "1.3.1"
    lock["packages"]["node_modules/evil"] = {"version": "0.0.1", "resolved": "https://registry.npmjs.org/evil/-/evil-0.0.1.tgz",
                                             "integrity": "sha512-EEE", "hasInstallScript": True, "license": "MIT"}
    (web / "package-lock.json").write_text(json.dumps(lock))
    (tmp_path / "README.md").write_text("changed, but not a lockfile")
    run_git(tmp_path, "commit", "-qam", "change")
    return tmp_path


def test_git_finds_only_changed_lockfiles(repo):
    base = git.merge_base("main", "HEAD", str(repo))
    assert git.changed_lockfiles(base, "HEAD", [], str(repo)) == ["web/package-lock.json"]
    old, new = git.load_pair("web/package-lock.json", base, "HEAD", str(repo))
    assert len(new.packages) == len(old.packages) + 1


def test_git_working_tree_and_new_lockfiles(repo):
    (repo / "uv.lock").write_text((FIX / "uv.lock").read_text())  # untracked, not yet committed
    base = git.merge_base("main", None, str(repo))
    assert "uv.lock" in git.changed_lockfiles(base, None, [], str(repo))
    old, new = git.load_pair("uv.lock", base, None, str(repo))
    assert old.packages == [] and new.packages


def test_git_go_sum_change_reads_go_mod(repo):
    for name in ("go.mod", "go.sum"):
        (repo / name).write_text((FIX / name).read_text())
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-qm", "go")
    (repo / "go.sum").write_text((FIX / "go.sum").read_text().replace("h1:CCC=", "h1:XXX="))
    assert "go.mod" in git.changed_lockfiles("HEAD", None, [], str(repo))


def test_cli_git_mode_with_gate(repo, monkeypatch, capsys):
    monkeypatch.chdir(repo / "web")
    with pytest.raises(SystemExit) as exit_:
        cli.main(["diff", "--base", "main", "--head", "HEAD", "--offline", "--fail-on", "install-script",
                  "--markdown", str(repo / "c.md"), "--json", str(repo / "r.json"), "--html", str(repo / "r.html")])
    assert exit_.value.code == 1
    out, err = capsys.readouterr()
    assert "1 added, 1 upgraded" in out and "failing because of install-script (1)" in err
    doc = json.loads((repo / "r.json").read_text())
    assert doc["lockfiles"][0]["path"] == "web/package-lock.json"
    assert (repo / "c.md").read_text().startswith(COMMENT_MARKER)
    assert "lookups were off" in (repo / "c.md").read_text()


def test_cli_errors(repo, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    for argv, message in [
        (["diff", "--base", "no-such-ref"], "can't find 'no-such-ref'"),
        (["diff", "only-one.json"], "give two lockfiles"),
        (["diff", "Cargo.lock", "web/package-lock.json"], "is a cargo lockfile but"),
        (["diff", "--head", "HEAD"], "--head needs --base"),
    ]:
        with pytest.raises(SystemExit) as exit_:
            cli.main(argv)
        assert exit_.value.code == 2, argv
        assert message in capsys.readouterr().err
    with pytest.raises(SystemExit) as exit_:
        cli.main(["diff", "--fail-on", "everything"])
    assert exit_.value.code == 2


def test_cli_two_files(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("LOCKLY_OFFLINE", "1")
    old = tmp_path / "old" / "Cargo.lock"
    old.parent.mkdir()
    old.write_text((FIX / "Cargo.lock").read_text())
    new = tmp_path / "Cargo.lock"
    new.write_text((FIX / "Cargo.lock").read_text().replace('version = "1.0.210"', 'version = "1.0.211"', 1))
    with pytest.raises(SystemExit) as exit_:
        cli.main(["diff", str(old), str(new), "-f", "json"])
    assert exit_.value.code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["upgraded"] == 1


# ── Outputs ──────────────────────────────────────────────────────────

HOSTILE = "<img src=x onerror=alert(1)>|`{{TITLE}}`"


def hostile_diff():
    old = Lockfile("package-lock.json", "package-lock", NPM, [Package(NPM, HOSTILE, "1.0.0", integrity="sha512-a")])
    new = Lockfile("package-lock.json", "package-lock", NPM,
                   [Package(NPM, HOSTILE, "1.0.0", integrity="sha512-b"), Package(NPM, "x", "1.0.0", source="git")])
    d = D.diff([(old, new)])
    D.find(d.files[0])
    d.notes.append("<b>note</b>")
    return d


def test_outputs_escape_hostile_names():
    d = hostile_diff()
    html = to_html(d, title="{{FINDINGS}}")
    assert "<img src=x" not in html and "<b>note</b>" not in html
    assert "{{FINDINGS}}" in html  # filled once, never re-expanded
    md = to_markdown(d)
    assert not re.search(r"(?<!\\)<img", md) and "\\|" in md  # escaped, so GitHub shows it as text
    assert json.loads(to_json(d))["lockfiles"][0]["findings"][0]["name"] == HOSTILE
    assert HOSTILE in to_text(d)  # the terminal shows names as they are


def test_markdown_stays_under_githubs_limit():
    pkgs_old = [Package(NPM, f"pkg-{i}", "1.0.0") for i in range(3000)]
    pkgs_new = [Package(NPM, f"pkg-{i}", "1.0.1") for i in range(3000)]
    d = D.diff([(Lockfile("p", "package-lock", NPM, pkgs_old), Lockfile("p", "package-lock", NPM, pkgs_new))])
    md = to_markdown(d, limit=10_000)
    assert len(md) < 65_536 and "shortened" in md
