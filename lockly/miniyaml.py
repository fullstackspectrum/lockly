"""Just enough YAML to read pnpm-lock.yaml and Yarn Berry's yarn.lock.

Both are machine-written with a narrow, consistent style: block mappings
indented by two spaces, block sequences of scalars, flow mappings and
sequences one level deep ({integrity: sha512-...}, [x64]), and single- or
double-quoted scalars. This reads that and nothing more: no anchors, tags,
multi-line strings or documents. Anything else raises ValueError, so a
change in either tool's output fails loudly rather than misreading.
"""

from __future__ import annotations

import re

_COMMENT = re.compile(r"(^|\s)#.*$")


def _scalar(text: str):
    text = text.strip()
    if not text:
        return None
    if text[0] in "'\"":
        return _quoted(text)
    if text.startswith("{"):
        return _flow_map(text)
    if text.startswith("["):
        return _flow_seq(text)
    if text in ("null", "~"):
        return None
    if text == "true":
        return True
    if text == "false":
        return False
    return text  # numbers stay strings: versions like 1.10 must not become floats


def _quoted(text: str) -> str:
    quote = text[0]
    if not text.endswith(quote) or len(text) < 2:
        raise ValueError(f"unterminated string: {text[:40]}")
    body = text[1:-1]
    if quote == "'":
        return body.replace("''", "'")
    return body.encode("utf-8").decode("unicode_escape") if "\\" in body else body


def _split_flow(body: str) -> list[str]:
    """Split a flow collection's body on top-level commas."""
    parts, depth, current, quote = [], 0, [], ""
    for ch in body:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if "".join(current).strip():
        parts.append("".join(current))
    return parts


def _flow_map(text: str) -> dict:
    if not text.endswith("}"):
        raise ValueError(f"unterminated flow mapping: {text[:40]}")
    out = {}
    for part in _split_flow(text[1:-1]):
        key, value = _split_key(part.strip())
        out[key] = _scalar(value)
    return out


def _flow_seq(text: str) -> list:
    if not text.endswith("]"):
        raise ValueError(f"unterminated flow sequence: {text[:40]}")
    return [_scalar(p) for p in _split_flow(text[1:-1])]


def _split_key(line: str) -> tuple[str, str]:
    """'key: value' → (key, value), honouring quoted keys with colons in them."""
    if line[:1] in "'\"":
        quote = line[0]
        end = 1
        while True:
            end = line.index(quote, end)
            if quote == "'" and line[end + 1:end + 2] == "'":
                end += 2
                continue
            break
        key = _quoted(line[:end + 1])
        rest = line[end + 1:]
        if not rest.startswith(":"):
            raise ValueError(f"expected ':' after key: {line[:60]}")
        return key, rest[1:]
    # A plain key ends at the first ': ' or a trailing ':', so keys like
    # pnpm 5's file:playground/x: keep their inner colons.
    m = re.match(r"^(.*?):(\s|$)(.*)$", line)
    if not m:
        raise ValueError(f"not a key: {line[:60]}")
    return m.group(1).strip(), m.group(3)


def loads_all(text: str) -> list:
    """Every document in the stream. pnpm 10 writes two: its own install
    first, then the project's lockfile."""
    docs, current = [], []
    for raw in text.splitlines():
        if raw.rstrip() == "---":
            docs.append(current)
            current = []
            continue
        current.append(raw)
    docs.append(current)
    return [_load_lines(d) for d in docs if any(line.strip() and not line.lstrip().startswith("#") for line in d)]


def loads(text: str):
    docs = loads_all(text)
    return docs[-1] if docs else None


def _load_lines(raw_lines: list[str]):
    lines = []
    for raw in raw_lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        stripped = raw.rstrip()
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.lstrip(" ")))
    value, pos = _block(lines, 0, 0)
    if pos != len(lines):
        raise ValueError(f"unexpected indentation near: {lines[pos][1][:60]}")
    return value


def _block(lines, pos, indent):
    if pos >= len(lines):
        return None, pos
    if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
        return _sequence(lines, pos, lines[pos][0])
    return _mapping(lines, pos, lines[pos][0])


def _sequence(lines, pos, indent):
    out = []
    while pos < len(lines) and lines[pos][0] == indent and (lines[pos][1].startswith("- ") or lines[pos][1] == "-"):
        item = lines[pos][1][2:]
        pos += 1
        if item.strip():
            out.append(_scalar(item))
        else:
            value, pos = _block(lines, pos, indent + 1)
            out.append(value)
    return out, pos


def _mapping(lines, pos, indent):
    out: dict = {}
    while pos < len(lines) and lines[pos][0] == indent:
        text = lines[pos][1]
        if text.startswith("- "):
            break
        key, rest = _split_key(text)
        pos += 1
        rest = _COMMENT.sub("", rest) if "#" in rest and rest.strip()[:1] not in "'\"" else rest
        if rest.strip():
            out[key] = _scalar(rest)
        elif pos < len(lines) and lines[pos][0] > indent:
            out[key], pos = _block(lines, pos, lines[pos][0])
        elif pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("- "):
            # A sequence written at the same indent as its key (allowed in YAML).
            out[key], pos = _sequence(lines, pos, indent)
        else:
            out[key] = None
    return out, pos
