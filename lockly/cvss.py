"""CVSS base scores from a vector string, per the FIRST specifications.

3.x uses the spec's formula. 4.0 is a port of FIRST's reference calculator
(https://github.com/FIRSTdotorg/cvss-v4-calculator), which scores a vector by
its MacroVector's looked-up score, adjusted by how far the vector sits below
that MacroVector's most severe vectors. The port keeps the reference's control
flow, quirks included, so scores match it exactly.
"""

from __future__ import annotations

import math

from .cvss4_data import LOOKUP, MAX_COMPOSED, MAX_SEVERITY

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    # The spec's Roundup, which avoids floating point surprises like 4.0000001.
    whole = round(value * 100000)
    return whole / 100000.0 if whole % 10000 == 0 else (math.floor(whole / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3."):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def score(vector: str) -> float | None:
    """Base score for a CVSS 3.x or 4.0 vector, or None if it can't be read."""
    if vector.startswith("CVSS:4.0/"):
        return base_score_v4(vector)
    return base_score(vector)


# ── CVSS 4.0 ─────────────────────────────────────────────────────────

_V4_REQUIRED = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
_V4_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
_DISTANCE_ORDER = ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR")


def _v4_metric(selected: dict[str, str], metric: str) -> str:
    value = selected.get(metric, "X")
    # Unset threat and requirement metrics default to the worst case.
    if metric == "E" and value == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and value == "X":
        return "H"
    # Environmental M* metrics override the base value when set.
    modified = selected.get("M" + metric, "X")
    if modified != "X":
        return modified
    return value


def _v4_macro_vector(sel: dict[str, str]) -> str:
    m = lambda k: _v4_metric(sel, k)  # noqa: E731

    if m("AV") == "N" and m("PR") == "N" and m("UI") == "N":
        eq1 = "0"
    elif (m("AV") == "N" or m("PR") == "N" or m("UI") == "N") and m("AV") != "P":
        eq1 = "1"
    else:
        eq1 = "2"

    eq2 = "0" if m("AC") == "L" and m("AT") == "N" else "1"

    if m("VC") == "H" and m("VI") == "H":
        eq3 = "0"
    elif m("VC") == "H" or m("VI") == "H" or m("VA") == "H":
        eq3 = "1"
    else:
        eq3 = "2"

    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = "0"
    elif m("SC") == "H" or m("SI") == "H" or m("SA") == "H":
        eq4 = "1"
    else:
        eq4 = "2"

    eq5 = {"A": "0", "P": "1", "U": "2"}[m("E")]

    high = ((m("CR") == "H" and m("VC") == "H") or (m("IR") == "H" and m("VI") == "H")
            or (m("AR") == "H" and m("VA") == "H"))
    eq6 = "0" if high else "1"
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _extract(metric: str, partial: str) -> str:
    rest = partial[partial.index(metric) + len(metric) + 1:]
    return rest.split("/", 1)[0]


def base_score_v4(vector: str) -> float | None:
    try:
        parts = vector.split("/")
        if parts[0] != "CVSS:4.0":
            return None
        sel = dict(p.split(":", 1) for p in parts[1:])
        if any(k not in sel for k in _V4_REQUIRED):
            return None
        macro = _v4_macro_vector(sel)
    except (ValueError, KeyError):
        return None
    if any(_v4_metric(sel, k) not in _V4_LEVELS[k] for k in _DISTANCE_ORDER):
        return None

    if all(_v4_metric(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    value = LOOKUP.get(macro)
    if value is None:
        return None
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)

    def at(*digits: int) -> float | None:
        return LOOKUP.get("".join(str(d) for d in digits))

    lower_eq1 = at(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    lower_eq2 = at(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 1 and eq6 == 1:
        lower_eq3eq6 = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 0 and eq6 == 1:
        lower_eq3eq6 = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 1 and eq6 == 0:
        lower_eq3eq6 = at(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 == 0 and eq6 == 0:
        # Two ways down; take the higher score. A missing one loses, as in JS.
        left, right = at(eq1, eq2, eq3, eq4, eq5, eq6 + 1), at(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        lower_eq3eq6 = left if (left is not None and right is not None and left > right) else right
    else:
        lower_eq3eq6 = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    lower_eq4 = at(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    lower_eq5 = at(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    maxes = [a + b + c + d + e
             for a in MAX_COMPOSED["eq1"][eq1]
             for b in MAX_COMPOSED["eq2"][eq2]
             for c in MAX_COMPOSED["eq3"][eq3][str(eq6)]
             for d in MAX_COMPOSED["eq4"][eq4]
             for e in MAX_COMPOSED["eq5"][eq5]]

    distance: dict[str, float] = {}
    for max_vector in maxes:
        distance = {k: _V4_LEVELS[k][_v4_metric(sel, k)] - _V4_LEVELS[k][_extract(k, max_vector)]
                    for k in _DISTANCE_ORDER}
        # The first max vector the scored vector doesn't exceed anywhere. If
        # none qualifies, the reference keeps the last one's distances.
        if all(d >= 0 for d in distance.values()):
            break

    current = {
        "eq1": distance["AV"] + distance["PR"] + distance["UI"],
        "eq2": distance["AC"] + distance["AT"],
        "eq3eq6": (distance["VC"] + distance["VI"] + distance["VA"]
                   + distance["CR"] + distance["IR"] + distance["AR"]),
        "eq4": distance["SC"] + distance["SI"] + distance["SA"],
    }
    step = 0.1
    depth = {
        "eq1": MAX_SEVERITY["eq1"][eq1] * step,
        "eq2": MAX_SEVERITY["eq2"][eq2] * step,
        "eq3eq6": MAX_SEVERITY["eq3eq6"][eq3][eq6] * step,
        "eq4": MAX_SEVERITY["eq4"][eq4] * step,
    }

    total, existing = 0.0, 0
    for name, lower in (("eq1", lower_eq1), ("eq2", lower_eq2), ("eq3eq6", lower_eq3eq6), ("eq4", lower_eq4)):
        if lower is not None:
            existing += 1
            total += (value - lower) * (current[name] / depth[name])
    if lower_eq5 is not None:
        existing += 1  # EQ5's proportion is always 0, but it still counts

    mean = total / existing if existing else 0.0
    value = min(max(value - mean, 0.0), 10.0)
    # JS Math.round: halves round up, unlike Python's round().
    return math.floor(value * 10 + 0.5) / 10


def severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"
