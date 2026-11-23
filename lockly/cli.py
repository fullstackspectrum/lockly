"""Command-line interface."""

from __future__ import annotations

import argparse
import inspect
import os
import re
import shutil
import sys
from pathlib import Path

from . import __version__, git, parsers
from .diff import FAIL_ON_CHOICES, Diff, compare_lockfiles, find
from .model import LockfileError
from .render import to_json, to_markdown, to_text, use_colour

# Exit codes: 0 clean (or nothing gated), 1 a --fail-on category was hit,
# 2 bad usage, or a lockfile or git ref that can't be read.
EXIT_OK, EXIT_GATED, EXIT_ERROR = 0, 1, 2
OFFLINE_ENV = "LOCKLY_OFFLINE"
REPO = "https://github.com/fullstackspectrum/lockly"


def _fail_on(value: str) -> set[str]:
    kinds = {v.strip().lower() for v in value.split(",") if v.strip()}
    unknown = kinds - set(FAIL_ON_CHOICES)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown category {', '.join(sorted(unknown))} (choose from {', '.join(FAIL_ON_CHOICES)})"
        )
    return kinds


def _days(value: str) -> float:
    try:
        n = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' isn't a number of days") from None
    if n < 0:
        raise argparse.ArgumentTypeError("days can't be negative")
    return n


# ── Help ──────────────────────────────────────────────────────────────

DIFF_EPILOG = f"""lockfiles:
  package-lock.json     npm (also npm-shrinkwrap.json)
  yarn.lock             Yarn classic and Berry (reads package.json for direct deps)
  pnpm-lock.yaml        pnpm 5.4 to 9
  uv.lock               uv
  poetry.lock           Poetry (reads pyproject.toml for direct deps)
  Pipfile.lock          Pipenv (reads Pipfile for direct deps)
  go.mod                Go modules (reads go.sum for hashes); go.sum alone also works
  Cargo.lock            Cargo

fail-on categories:
  hash                  same version, different contents: rebuilt, republished or tampered with
  install-script        a package now runs a script when it's installed
  publisher             published by an account new to the package, or no longer by trusted publishing
  provenance            the previous release had a provenance attestation; this one doesn't
  source                comes from git, a URL or another registry, or from somewhere new
  new-package           the package itself is only days old (--new-package-days)
  young                 this version is only days old (--min-age)
  vulnerable            the new version has known vulnerabilities (OSV)
  deprecated            deprecated or yanked
  copyleft              brings in copyleft licence terms
  license               the licence changed between copyleft and permissive terms
  any                   all of the above

exit codes:
  0                     passed, or nothing in --fail-on occurred
  1                     a --fail-on category occurred
  2                     bad usage, or a lockfile or git ref that can't be read

examples:
  $ lockly diff old/package-lock.json package-lock.json
  $ lockly diff --base origin/main                      # every lockfile changed on this branch
  $ lockly diff --base main --markdown comment.md --html report.html
  $ lockly diff --base main --fail-on install-script,publisher,hash
  $ lockly diff --base main --offline                   # only what the lockfiles say
"""

ROOT_EPILOG = f"""examples:
  $ lockly diff --base origin/main
  $ lockly diff old/uv.lock uv.lock
  $ lockly diff --help                                  # every option for diff

docs:
  {REPO}
"""

# Brand colours as terminal codes: flags take blue-soft (keys in code),
# placeholders yellow (strings), headings the // eyebrow.
_HELP_STYLES = {"flag": "94", "meta": "33", "dim": "2", "bold": "1", "red": "31"}


def _style(code: str, text: str) -> str:
    return f"\033[{_HELP_STYLES[code]}m{text}\033[0m"


def _colourise_help(text: str) -> str:
    out = []
    section = ""
    for line in text.splitlines():
        heading = re.fullmatch(r"([a-z][a-z -]*):", line)
        if heading:
            section = heading.group(1)
            out.append(f"{_style('dim', '//')} {_style('bold', section)}")
            continue
        if line.startswith("usage:"):
            out.append(f"{_style('dim', '//')} {_style('bold', 'usage')}")
            out.append("  " + re.sub(r"\b(lockly(?: diff)?)\b", lambda m: _style("red", m.group(1)),
                                     line[7:], count=1))
            continue
        if section == "examples" and line.lstrip().startswith("$"):
            cmd, _, comment = line.partition("#")
            cmd = cmd.replace("$", _style("dim", "$"), 1)
            out.append(cmd + (_style("dim", "#" + comment) if comment else ""))
            continue
        if section == "docs":
            out.append(_style("flag", line))
            continue
        m = re.match(r"^(  )(\S.*?)(\s{2,}\S.*)?$", line)
        if m and section not in ("", "usage"):
            term = re.sub(r"(?<![\w-])(--?[\w-]+)", lambda x: _style("flag", x.group(1)), m.group(2))
            term = re.sub(r"(?<![\w-])([A-Z]+)\b", lambda x: _style("meta", x.group(1)), term)
            if section in ("fail-on categories", "commands", "exit codes", "lockfiles"):
                term = _style("flag", m.group(2))
            out.append(m.group(1) + term + (m.group(3) or ""))
            continue
        out.append(line)
    return "\n".join(out) + "\n"


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog: str) -> None:
        width = min(shutil.get_terminal_size((100, 24)).columns, 100)
        super().__init__(prog, max_help_position=24, width=width)
        # Pin the help column at 24 in every section, so options and the
        # hand-written reference sections in the epilog line up.
        self._action_max_length = 22

    def _format_action(self, action: argparse.Action) -> str:
        # List subcommands directly under "commands:", without argparse's
        # extra "COMMAND" line above them.
        if isinstance(action, argparse._SubParsersAction):
            return "".join(self._format_action(a) for a in action._get_subactions())
        return super()._format_action(action)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        # "-p, --platform P" rather than argparse's "-p P, --platform P".
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        metavar = self._format_args(action, self._get_default_metavar_for_optional(action))
        return f"{', '.join(action.option_strings)} {metavar}"


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose help is grouped, wrapped to the terminal and, on a
    colour terminal, styled in the Full-Stack-Spectrum palette."""

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("formatter_class", _HelpFormatter)
        kwargs.setdefault("add_help", False)
        # Python 3.14 colours help itself; this parser does its own.
        if "color" in inspect.signature(argparse.ArgumentParser.__init__).parameters:
            kwargs.setdefault("color", False)
        super().__init__(*args, **kwargs)

    def format_help(self) -> str:
        text = super().format_help()
        return _colourise_help(text) if use_colour() else text


def _help_flag(group) -> None:
    group.add_argument("-h", "--help", action="help", help="show this help and exit")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="lockly",
        usage="lockly COMMAND [options]",
        description=f"lockly {__version__}: what changed in a lockfile, and what deserves a closer look.",
        epilog=ROOT_EPILOG,
    )
    sub = parser.add_subparsers(dest="command", title="commands", metavar="COMMAND", parser_class=_Parser)
    general = parser.add_argument_group("options")
    _help_flag(general)
    general.add_argument("--version", action="version", version=f"lockly {__version__}",
                         help="print the version and exit")

    d = sub.add_parser(
        "diff",
        help="compare lockfiles: two files, or every lockfile changed since a git ref",
        usage="lockly diff OLD NEW [options]\n       lockly diff --base REF [--head REF] [PATH...] [options]",
        description=(
            "Compare two versions of a lockfile: what was added, removed, upgraded or downgraded,\n"
            "and which changes deserve a reviewer's attention: new install scripts, a new publisher,\n"
            "packages days old, changed contents or sources, known vulnerabilities, licence changes.\n"
            "Registry and OSV lookups add the checks a lockfile can't answer alone; --offline skips them."
        ),
        epilog=DIFF_EPILOG,
    )
    inputs = d.add_argument_group("arguments")
    inputs.add_argument("paths", metavar="PATH", nargs="*",
                        help="two lockfiles (old, new); with --base, paths to limit the search to")
    inputs.add_argument("-b", "--base", metavar="REF",
                        help="compare every lockfile changed since REF (its merge base with --head)")
    inputs.add_argument("--head", metavar="REF",
                        help="with --base: the other side (default: the working tree)")
    inputs.add_argument("-t", "--type", metavar="TYPE", default="", choices=parsers.KINDS,
                        help=f"lockfile type, for files with other names: {', '.join(parsers.KINDS)}")

    checks = d.add_argument_group("checks")
    checks.add_argument("--offline", action="store_true",
                        help=f"no registry or OSV lookups, only what the lockfiles say (or set {OFFLINE_ENV}=1)")
    checks.add_argument("--min-age", metavar="DAYS", type=_days, default=3.0,
                        help="flag versions published less than DAYS ago (default: 3)")
    checks.add_argument("--new-package-days", metavar="DAYS", type=_days, default=30.0,
                        help="flag added packages first published less than DAYS ago (default: 30)")
    checks.add_argument("--no-cache", action="store_true",
                        help="don't read or write the lookup cache in ~/.cache/lockly")

    output = d.add_argument_group("output")
    output.add_argument("-f", "--format", choices=("text", "markdown", "json"), default="text",
                        metavar="FORMAT", help="what to print: text (default), markdown or json")
    output.add_argument("--html", metavar="FILE", type=Path,
                        help="write a self-contained HTML report that works offline")
    output.add_argument("--markdown", metavar="FILE", type=Path,
                        help="write Markdown sized for a pull request comment")
    output.add_argument("--json", metavar="FILE", type=Path, help="write everything as JSON")
    output.add_argument("-q", "--quiet", action="store_true", help="print nothing to stdout")

    gate = d.add_argument_group("ci gating")
    gate.add_argument("--fail-on", metavar="LIST", type=_fail_on, default=set(),
                      help="exit 1 if any of these comma-separated categories occur (see below)")

    display = d.add_argument_group("display")
    display.add_argument("--title", default="", metavar="TEXT", help="title for the HTML and Markdown reports")
    display.add_argument("--theme", choices=("dark", "light"), default="dark", metavar="THEME",
                         help="HTML report theme: dark (default) or light")
    display.add_argument("--limit", type=int, default=100, metavar="N",
                         help="rows per section in text and Markdown output (default: 100)")
    display.add_argument("--no-color", action="store_true",
                         help="plain terminal output; NO_COLOR and FORCE_COLOR are respected too")
    _help_flag(display)
    return parser


def _write(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise LockfileError(f"{path}: can't write ({exc.strerror})") from None


def _load(args: argparse.Namespace) -> Diff:
    if args.base:
        repo = git.root()
        base = git.merge_base(args.base, args.head, repo)
        cwd = os.path.relpath(os.getcwd(), repo)
        scope = [os.path.normpath(os.path.join(cwd, p)) for p in args.paths] or ([cwd] if cwd != "." else [])
        paths = git.changed_lockfiles(base, args.head, scope, repo)
        return Diff([compare_lockfiles(*git.load_pair(p, base, args.head, repo, args.type)) for p in paths])
    if args.head:
        raise LockfileError("--head needs --base")
    if len(args.paths) != 2:
        raise LockfileError("give two lockfiles to compare, or --base REF to compare against git")
    old, new = (git.load_file(p, args.type) for p in args.paths)
    if old.kind != new.kind:
        raise LockfileError(f"{args.paths[0]} is a {old.kind} lockfile but {args.paths[1]} is a {new.kind} one")
    new.path = args.paths[1]
    return Diff([compare_lockfiles(old, new)])


def run(args: argparse.Namespace) -> int:
    result = _load(args)
    offline = args.offline or bool(os.environ.get(OFFLINE_ENV, "").strip())
    if not offline and result.changes:
        from . import enrich  # only pay for the import when looking things up

        enrich.enrich(result, cache=not args.no_cache)
    elif offline:
        result.notes.append("Registry and OSV lookups were off (--offline): publisher, age, deprecation "
                            "and vulnerability checks didn't run.")
    for fd in result.files:
        find(fd, min_age_days=args.min_age, new_package_days=args.new_package_days)

    colour = use_colour() and not args.no_color
    if args.html:
        from .html import to_html  # only pay for loading the fonts when asked

        _write(args.html, to_html(result, theme=args.theme, title=args.title))
    if args.markdown:
        _write(args.markdown, to_markdown(result, limit=args.limit, title=args.title))
    if args.json:
        _write(args.json, to_json(result, args.fail_on))

    if not args.quiet:
        if args.format == "json":
            sys.stdout.write(to_json(result, args.fail_on))
        elif args.format == "markdown":
            sys.stdout.write(to_markdown(result, limit=args.limit, title=args.title))
        else:
            sys.stdout.write(to_text(result, colour=colour, limit=args.limit))

    hits = result.triggered(args.fail_on)
    if hits:
        summary = ", ".join(f"{kind} ({n})" for kind, n in hits.items())
        sys.stdout.flush()  # keep the report above the verdict in a terminal
        print(f"lockly: failing because of {summary}", file=sys.stderr)
        return EXIT_GATED
    return EXIT_OK


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "diff":
        parser.print_help()
        sys.exit(EXIT_ERROR)
    try:
        sys.exit(run(args))
    except LockfileError as exc:
        print(f"lockly: {exc}", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    except KeyboardInterrupt:
        sys.exit(130)
