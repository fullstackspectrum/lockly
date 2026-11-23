"""Self-contained, offline HTML report for a Diff."""

from __future__ import annotations

import base64
import datetime
import re
from html import escape
from importlib import resources

from . import __version__
from .diff import CHANGE_KINDS, Diff
from .render import CHANGE_TITLES, FINDING_TITLES, fixed_total, gating, plural, summary

# docs/brand/lockly-icon.svg, inlined so the report stays self-contained.
# Keep the two in sync.
_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<rect width="64" height="64" rx="14" fill="#0a0d12"/>'
    '<rect x="25" y="11" width="28" height="28" rx="6" fill="#0a0d12" stroke="#4f8cff" stroke-width="3.5"/>'
    '<rect x="18" y="18" width="28" height="28" rx="6" fill="#0a0d12" stroke="#f5c84c" stroke-width="3.5"/>'
    '<rect x="11" y="25" width="28" height="28" rx="6" fill="#0a0d12" stroke="#eef1f6" stroke-width="3.5"/>'
    '<path d="M21.5 38.5v-3a3.5 3.5 0 0 1 7 0v3M19.5 38.5h11v8h-11z" fill="none" stroke="#ff4d5e" '
    'stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg>'
)

_STAT_SUBS = {
    "added": "New in the lockfile",
    "removed": "No longer installed",
    "upgraded": "Moved to a newer version",
    "downgraded": "Moved to an older version",
    "changed": "Same version, new contents or source",
}


def _asset(name: str) -> bytes:
    return resources.files("lockly").joinpath("assets", name).read_bytes()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _fill(template: str, values: dict[str, str]) -> str:
    # One pass, so a placeholder-shaped string inside a package name can
    # never be expanded by a later replacement.
    return re.sub(r"\{\{([A-Z0-9_]+)\}\}", lambda m: values.get(m.group(1), m.group(0)), template)


def _stat(kind: str, label: str, number: int, sub: str) -> str:
    zero = " zero" if number == 0 else ""
    return (f'<div class="stat-card k-{kind}{zero}"><div class="stat-label">{escape(label)}</div>'
            f'<div class="stat-number">{number}</div><div class="stat-sub">{escape(sub)}</div></div>')


def _lockfile_card(fd) -> str:
    counts = ", ".join(f"{fd.count(k)} {k}" for k in CHANGE_KINDS if fd.count(k)) or "no changes"
    rows = [("ecosystem", fd.ecosystem), ("format", fd.kind), ("changes", counts),
            ("unchanged", str(fd.unchanged)), ("findings", str(sum(1 for f in fd.findings if f.gating)))]
    items = "".join(f"<dt>{escape(k)}</dt><dd>{escape(v)}</dd>" for k, v in rows)
    return f'<div class="sbom-card"><h2>{escape(fd.path)}</h2><dl>{items}</dl></div>'


def _findings(d: Diff) -> str:
    if not d.findings:
        return '<div class="empty">Nothing to review: no new install scripts, publishers, sources or vulnerabilities.</div>'
    multi = len(d.files) > 1
    cards = []
    for f in d.findings:
        kind = f.kind if f.gating else "info"
        label = FINDING_TITLES[f.kind] + ("" if f.gating else " · info")
        where = f'<span class="where">{escape(f.lockfile)}</span>' if multi else ""
        cards.append(
            f'<div class="finding k-{kind}"><span class="badge">{escape(label)}</span>'
            f'<div class="finding-title">{escape(f.name)}<code>{escape(f.version)}</code>{where}</div>'
            f'<div class="finding-msg">{escape(f.message)}</div></div>'
        )
    return f'<div class="findings">{"".join(cards)}</div>'


def _fixed(d: Diff) -> str:
    n = fixed_total(d)
    if not n:
        return ""
    names = sorted({k for f in d.files for k in f.fixed})
    shown = ", ".join(names[:8]) + (" …" if len(names) > 8 else "")
    return (f'<p class="fixed-note"><strong>{escape(plural(n, "known vulnerability", "known vulnerabilities"))} '
            f"fixed</strong> by these changes: {escape(shown)}.</p>")


def _notes(d: Diff) -> str:
    fixed = _fixed(d)
    notes = "".join(f"<p>{escape(n)}</p>" for n in d.notes)
    return fixed + (f'<div class="notes">{notes}</div>' if notes else "")


def _version_cell(kind: str, old: str, new: str) -> str:
    if kind == "added":
        return escape(new)
    if kind == "removed":
        return f'<span class="old">{escape(old)}</span>'
    if old == new:
        return escape(new)
    return f'<span class="old">{escape(old)}</span><span class="sep">→</span>{escape(new)}'


def _changes(d: Diff) -> str:
    changes = d.changes
    if not changes:
        return '<div class="empty">No dependencies were added, removed or changed version.</div>'
    buttons = ['<button class="filter-btn" type="button" data-kind-filter="" aria-pressed="true">All</button>']
    for kind in CHANGE_KINDS:
        n = d.count(kind)
        if n:
            buttons.append(f'<button class="filter-btn k-{kind}" type="button" data-kind-filter="{kind}" '
                           f'aria-pressed="false">{escape(CHANGE_TITLES[kind])} {n}</button>')
    multi = len(d.files) > 1
    rows = []
    for c in sorted(changes, key=lambda c: (not c.direct, CHANGE_KINDS.index(c.kind), c.name.lower())):
        where = ("direct" if c.direct else "") + (" · dev" if c.dev else "")
        where = where.strip(" ·")
        search = " ".join((c.name, c.ecosystem, c.old_version, c.new_version, c.lockfile)).lower()
        rows.append(
            f'<tr data-kind="{c.kind}" data-search="{escape(search)}">'
            f'<td><span class="badge k-{c.kind}">{escape(c.kind)}</span></td>'
            f'<td class="pkg">{escape(c.name)}<small>{escape(c.ecosystem)}'
            f'{" · " + escape(c.lockfile) if multi else ""}</small></td>'
            f'<td class="ver">{_version_cell(c.kind, c.old_version, c.new_version)}</td>'
            f'<td class="where">{escape(where) or "—"}</td></tr>'
        )
    return (
        '<div class="controls">'
        '<input class="search-input" id="changeSearch" type="search" '
        'placeholder="search package or version…" aria-label="Search changes" />'
        f'{"".join(buttons)}<span class="result-count" id="resultCount"></span></div>'
        '<div class="table-wrap"><table id="changesTable"><thead><tr>'
        '<th>Change</th><th>Package</th><th>Version</th><th>Dependency</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
    )


def to_html(d: Diff, theme: str = "dark", title: str = "") -> str:
    template = _asset("report.html").decode("utf-8")
    flagged = len(gating(d))
    if flagged:
        badge_class, badge_text = "k-findings", f"{flagged} to review"
    elif d.changes:
        badge_class, badge_text = "k-upgraded", plural(len(d.changes), "change")
    else:
        badge_class, badge_text = "k-added", "no changes"

    paths = [f.path for f in d.files]
    hero = escape(title) if title else (escape(paths[0]) if len(paths) == 1 else escape(plural(len(paths), "lockfile")))
    headline = summary(d) + (f" {plural(flagged, 'finding')} to review." if flagged else "")

    stats = [_stat(k, CHANGE_TITLES[k], d.count(k), _STAT_SUBS[k]) for k in CHANGE_KINDS]
    stats.append(_stat("findings", "Findings", flagged, "Worth a reviewer's look"))
    stats.append(_stat("fixed", "Fixed", fixed_total(d), "Known vulnerabilities fixed"))

    return _fill(template, {
        "THEME_ATTR": ' data-theme="light"' if theme == "light" else "",
        "FAVICON_B64": _b64(_FAVICON_SVG.encode()),
        "FONT_DISPLAY_B64": _b64(_asset("space-grotesk-var.woff2")),
        "FONT_MONO_B64": _b64(_asset("jetbrains-mono-var.woff2")),
        "TITLE": escape(title or ", ".join(paths) or "lockfiles"),
        "BADGE_CLASS": badge_class,
        "BADGE_TEXT": escape(badge_text),
        "HERO_TITLE": hero,
        "HEADLINE": escape(headline),
        "LOCKFILES": "".join(_lockfile_card(f) for f in d.files),
        "STAT_CARDS": "".join(stats),
        "FINDINGS": _findings(d),
        "NOTES": _notes(d),
        "CHANGES": _changes(d),
        "VERSION": escape(__version__),
        "REPORT_DATE": datetime.date.today().strftime("%d %b %Y"),
    })
