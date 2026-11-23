"""Ordering versions across ecosystems, well enough to call a change an
upgrade or a downgrade. Adapted from Sbomly."""

from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")
_OPAQUE = re.compile(r"^[0-9a-f]{7,64}$", re.I)


def _tokens(version: str) -> tuple[int, list[int | str]]:
    version = version.strip().removeprefix("v").removeprefix("V")
    # Drop build metadata (1.2.3+build.5, Cargo's 0.1.0+wasi): it never orders.
    version = version.split("+", 1)[0]
    epoch = 0
    match = re.match(r"^(\d+)!(.+)$", version)  # PEP 440 epochs: 1!2.0 sorts after 9.9
    if match:
        epoch, version = int(match.group(1)), match.group(2)
    return epoch, [int(t) if t.isdigit() else t.lower() for t in _TOKEN.findall(version)]


def compare(a: str, b: str) -> int | None:
    """-1, 0 or 1 like cmp(); None when the versions can't be ordered (commit SHAs)."""
    if a == b:
        return 0
    if not a or not b or _OPAQUE.match(a) or _OPAQUE.match(b):
        return None
    epoch_a, ta = _tokens(a)
    epoch_b, tb = _tokens(b)
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    if not ta or not tb:
        return None
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            return -1 if x < y else 1
        # A number beats a word in the same slot: 1.0.1 > 1.0.beta.
        return 1 if isinstance(x, int) else -1
    if len(ta) == len(tb):
        return 0
    # One is a prefix of the other. A trailing word marks a pre-release
    # (1.0.0rc1 < 1.0.0); a trailing number is a later release (1.0 < 1.0.1).
    longer, sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    nxt = longer[min(len(ta), len(tb))]
    return -sign if isinstance(nxt, str) else sign


def sort_key(version: str):
    """For sorting lists of versions; unorderable ones sort as text, last."""
    import functools

    return functools.cmp_to_key(lambda a, b: compare(a, b) or (a > b) - (a < b))(version)
