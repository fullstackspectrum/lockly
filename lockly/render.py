"""Text, Markdown and JSON renderings of a Diff."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict

from . import __version__
from .diff import CHANGE_KINDS, Change, Diff

# The Action finds its earlier comment by this, to update it in place.
COMMENT_MARKER = "<!-- lockly -->"

CHANGE_TITLES = {
    "added": "Added", "removed": "Removed", "upgraded": "Upgraded",
    "downgraded": "Downgraded", "changed": "Changed in place",
}

FINDING_TITLES = {
    "hash": "Integrity",
    "install-script": "Install script",
    "publisher": "Publisher",
    "provenance": "Provenance",
    "source": "Source",
    "new-package": "New package",
    "young": "Fresh release",
    "vulnerable": "Vulnerable",
    "deprecated": "Deprecated",
    "copyleft": "Copyleft",
    "license": "Licence",
}


def plural(n: int, word: str, many: str = "") -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def summary(d: Diff) -> str:
    if not d.changes:
        return "No dependency changes."
    parts = [f"{d.count(k)} {k}" for k in CHANGE_KINDS if d.count(k)]
    return ", ".join(parts) + "."


def gating(d: Diff) -> list:
    return [f for f in d.findings if f.gating]


def fixed_total(d: Diff) -> int:
    return len({v for f in d.files for ids in f.fixed.values() for v in ids})


def _where(c: Change) -> str:
    if c.direct is True:
        return "direct, dev" if c.dev else "direct"
    if c.direct is False:
        return "dev" if c.dev else ""
    return "dev" if c.dev else ""


def _versions(c: Change) -> tuple[str, str]:
    return c.old_version, c.new_version


# ── JSON ──────────────────────────────────────────────────────────────

def _change_json(c: Change) -> dict:
    doc = {"kind": c.kind, "ecosystem": c.ecosystem, "name": c.name,
           "from": c.old_version or None, "to": c.new_version or None,
           "direct": c.direct, "dev": c.dev}
    for side, meta in (("fromMeta", c.old_meta), ("toMeta", c.new_meta)):
        if meta is not None:
            doc[side] = {k: v for k, v in asdict(meta).items() if v not in ("", None, [], {})}
    return doc


def to_json(d: Diff, fail_on: set[str] | None = None) -> str:
    doc: dict = {
        "tool": {"name": "lockly", "version": __version__},
        "summary": {**{k: d.count(k) for k in CHANGE_KINDS},
                    "findings": len(gating(d)), "fixedVulnerabilities": fixed_total(d)},
        "lockfiles": [{
            "path": f.path, "type": f.kind, "ecosystem": f.ecosystem, "unchanged": f.unchanged,
            "changes": [_change_json(c) for c in f.changes],
            "findings": [asdict(x) for x in f.findings],
            "fixed": f.fixed,
        } for f in d.files],
        "notes": d.notes,
    }
    if fail_on is not None:
        doc["failOn"] = {"categories": sorted(fail_on), "triggered": d.triggered(fail_on)}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


# ── Terminal ──────────────────────────────────────────────────────────

# Closest terminal colours to the Full-Stack-Spectrum palette: blue for new,
# bright blue for upgrades, 256-colour 209 for orange, red only for the
# findings that most often mean a compromise.
_COLOURS = {
    "added": "34", "removed": "2", "upgraded": "94", "downgraded": "38;5;209", "changed": "33",
    "hash": "31;1", "install-script": "31;1", "publisher": "31;1", "provenance": "38;5;209",
    "source": "38;5;209", "new-package": "38;5;209", "young": "33", "vulnerable": "38;5;209",
    "deprecated": "33", "copyleft": "38;5;209", "license": "33", "good": "34",
    "dim": "2", "bold": "1",
}


def use_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def to_text(d: Diff, colour: bool = False, limit: int = 25) -> str:
    def c(style: str, text: str) -> str:
        return f"\033[{_COLOURS[style]}m{text}\033[0m" if colour and text else text

    # One column for finding types and change kinds, wide enough for both.
    width = max([len(FINDING_TITLES[f.kind]) for f in d.findings] + [len("downgraded")])
    lines = [c("dim", "// ") + c("bold", "lockly") + c("dim", "  " + plural(len(d.files), "lockfile")),
             "", summary(d)]
    flagged = gating(d)
    if flagged:
        lines[-1] += " " + c("bold", plural(len(flagged), "finding") + " to review.")

    for fd in d.files:
        if not fd.changes:
            continue
        counts = ", ".join(f"{fd.count(k)} {k}" for k in CHANGE_KINDS if fd.count(k))
        lines += ["", c("dim", "// ") + c("bold", fd.path) + c("dim", f"  {fd.ecosystem} · {counts}")]
        for f in fd.findings[:limit]:
            tag = c(f.kind if f.gating else "dim", f"{FINDING_TITLES[f.kind].lower():<{width}}")
            note = "" if f.gating else c("dim", "  (info)")
            lines.append(f"  {tag}  {f.name} {c('dim', f.version)}  {f.message}{note}")
        if len(fd.findings) > limit:
            lines.append(c("dim", f"  … and {len(fd.findings) - limit} more findings"))
        if fd.fixed:
            n = len({v for ids in fd.fixed.values() for v in ids})
            label = c("good", "fixed".ljust(width))
            lines.append(f"  {label}  {plural(n, 'known vulnerability', 'known vulnerabilities')} fixed by "
                         + ", ".join(sorted(fd.fixed)[:4]) + (" …" if len(fd.fixed) > 4 else ""))
        direct = [ch for ch in fd.changes if ch.direct and ch.kind != "removed"]
        for ch in direct[:limit]:
            old, new = _versions(ch)
            version = new if ch.kind == "added" else f"{old} → {new}"
            lines.append(f"  {c(ch.kind, f'{ch.kind:<{width}}')}  {ch.name} {c('dim', version)}" + c("dim", "  direct"))
        rest = len(fd.changes) - len(direct)
        if rest > 0:
            lines.append(c("dim", f"  … {plural(rest, 'transitive change')} not listed (see --markdown, --json or --html)"))

    for note in d.notes:
        lines += ["", c("dim", "note: " + note)]
    return "\n".join(lines) + "\n"


# ── Markdown ──────────────────────────────────────────────────────────

MARKDOWN_BUDGET = 60_000


def _md(text: str) -> str:
    """Escape the characters that would break a table cell or inject markup."""
    for ch in ("\\", "|", "`", "*", "_", "[", "]", "<", ">"):
        text = text.replace(ch, "\\" + ch)
    return text.replace("\n", " ")


def _code(text: str) -> str:
    # GitHub splits table cells on '|' even inside a code span, so it still
    # needs escaping there; a backtick would end the span early.
    if not text:
        return "—"
    text = " ".join(text.split()).replace("`", "").replace("|", "\\|")
    return f"`{text}`"


def to_markdown(d: Diff, limit: int = 100, title: str = "") -> str:
    out: list[str] = [COMMENT_MARKER, f"### {_md(title) if title else 'Lockfile review'}", ""]
    flagged = gating(d)
    headline = f"{plural(len(d.files), 'lockfile')} changed · {_md(summary(d).rstrip('.'))}"
    if flagged:
        headline += f" · **{plural(len(flagged), 'finding')} to review**"
    elif d.changes:
        headline += " · nothing flagged"
    out += [headline, ""]

    size = sum(len(line) + 1 for line in out)
    truncated = False

    def block(lines: list[str]) -> bool:
        nonlocal size, truncated
        cost = sum(len(x) + 1 for x in lines)
        if size + cost > MARKDOWN_BUDGET:
            truncated = True
            return False
        out.extend(lines)
        size += cost
        return True

    if flagged or any(not f.gating for f in d.findings):
        rows = ["| | Package | Version | Detail |", "|---|---|---|---|"]
        for f in d.findings[:limit]:
            label = FINDING_TITLES[f.kind] + ("" if f.gating else " (info)")
            where = f" <sub>{_md(f.lockfile)}</sub>" if len(d.files) > 1 else ""
            rows.append(f"| {label} | {_md(f.name)}{where} | {_code(f.version)} | {_md(f.message)} |")
        if len(d.findings) > limit:
            rows.append(f"| | _… {len(d.findings) - limit} more in the JSON or HTML report_ | | |")
        block(rows + [""])

    fixed = fixed_total(d)
    if fixed:
        names = sorted({k for f in d.files for k in f.fixed})
        block([f"These changes fix {plural(fixed, 'known vulnerability', 'known vulnerabilities')} "
               f"({_md(', '.join(names[:6]))}{' …' if len(names) > 6 else ''}).", ""])

    for fd in d.files:
        if not fd.changes:
            continue
        counts = ", ".join(f"{fd.count(k)} {k}" for k in CHANGE_KINDS if fd.count(k))
        rows = [f"<details><summary><code>{_md(fd.path)}</code> · {fd.ecosystem} · {counts}</summary>", "",
                "| Change | Package | From | To | |", "|---|---|---|---|---|"]
        # Direct dependencies first: those are the ones someone chose.
        ordered = sorted(fd.changes, key=lambda ch: (not ch.direct, CHANGE_KINDS.index(ch.kind), ch.name.lower()))
        shown = 0
        for ch in ordered[:limit]:
            old, new = _versions(ch)
            row = f"| {CHANGE_TITLES[ch.kind]} | {_md(ch.name)} | {_code(old)} | {_code(new)} | {_where(ch)} |"
            if size + sum(len(x) + 1 for x in rows) + len(row) > MARKDOWN_BUDGET - 500:
                truncated = True
                break
            rows.append(row)
            shown += 1
        if shown < len(ordered):
            rows += ["", f"_… {len(ordered) - shown} more in the JSON or HTML report._"]
        rows += ["", "</details>", ""]
        block(rows)

    for note in d.notes:
        block([f"> {_md(note)}", ""])
    if truncated:
        out += ["_This comment was shortened to fit GitHub's size limit._", ""]
    out.append(f"<sub>Generated by [Lockly](https://github.com/fullstackspectrum/lockly) {__version__}</sub>")
    return "\n".join(out) + "\n"

