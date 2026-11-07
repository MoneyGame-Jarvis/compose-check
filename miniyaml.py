"""A small YAML parser for the Compose subset, used when PyYAML is absent.

The point of compose-check is that it installs nowhere and imports
nothing: an operator can paste it into a container and run it. So it
carries its own parser for the subset of YAML a Compose file uses --
nested mappings, sequences, flow collections, quoted and block scalars,
and the usual scalar types.

It is not a general YAML implementation and does not pretend to be.
Anchors, aliases, tags and multiple documents are not supported; a
Compose file that uses them is rare, and the tool says so rather than
guessing.

When PyYAML IS installed it is used instead, because it is the reference
implementation and there is no reason to prefer the fallback.
"""
from __future__ import annotations

import re

_TRUE = ("true", "yes", "on")
_FALSE = ("false", "no", "off")
_NULL = ("null", "~", "")


class YamlSubsetError(Exception):
    """The input uses YAML this parser does not implement."""


def _strip_comment(line: str) -> str:
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                i += 1
                out.append(line[i])
            elif ch == quote:
                quote = None
        else:
            if ch in "\"'":
                quote = ch
                out.append(ch)
            elif ch == "#" and (not out or out[-1] in " \t"):
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _scalar(text):
    s = (text or "").strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        try:
            return s[1:-1].encode("utf-8").decode("unicode_escape")
        except Exception:
            return s[1:-1]
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1].replace("''", "'")
    low = s.lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    if low in _NULL:
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _split_flow(body: str) -> list[str]:
    """Split a flow collection body on top-level commas."""
    parts, depth, quote, cur = [], 0, None, []
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def _flow(text: str):
    s = text.strip()
    if s.startswith("[") and s.endswith("]"):
        return [_flow(p) if p.strip().startswith(("[", "{")) else _scalar(p)
                for p in _split_flow(s[1:-1])]
    if s.startswith("{") and s.endswith("}"):
        out = {}
        for part in _split_flow(s[1:-1]):
            key, _, rest = part.partition(":")
            out[str(_scalar(key))] = _flow(rest) if rest.strip().startswith(("[", "{")) else _scalar(rest)
        return out
    return _scalar(s)


def _split_key(text: str):
    """Split `key: value` the way YAML does, or return None.

    The separator is a colon followed by a SPACE, or a colon at the end
    of the line. A colon with no space after it is part of the scalar:
    that is why `./Caddyfile:/etc/caddy/Caddyfile:ro` is a string and
    not a mapping, and why `image:nginx` is one scalar rather than a
    key.
    """
    if text.startswith(("[", "{", '"', "'")):
        return None
    head, sep, rest = text.partition(":")
    if not sep:
        return None
    if rest and not rest.startswith(" "):
        return None
    if not head.strip() or " " in head.strip():
        return None
    return head.strip(), rest.strip()


def _is_map_entry(text: str) -> bool:
    """Does this look like `key: value` rather than a plain scalar?"""
    return _split_key(text) is not None


def _block_scalar(lines, i, indent, style):
    """A `|` (literal) or `>` (folded) block scalar.

    The content is every following line indented deeper than the key,
    dedented by the shallowest such line. `|` keeps the line breaks,
    `>` folds them into spaces.
    """
    raw = []
    while i < len(lines) and lines[i][0] > indent:
        raw.append(lines[i])
        i += 1
    if not raw:
        return "", i
    base = min(l[0] for l in raw)
    body = [l[1][base:] if len(l[1]) >= base else l[1].strip() for l in raw]
    if style.startswith(">"):
        folded = " ".join(x.strip() for x in body)
        return (folded + "\n") if not style.endswith("-") else folded, i
    text = "\n".join(body)
    if style.endswith("-"):
        return text, i
    return text + "\n", i


def _parse_map(lines, i, indent):
    out = {}
    while i < len(lines):
        ind, raw_text = lines[i]
        text = raw_text.strip()
        if ind < indent or text.startswith("- "):
            break
        if ind > indent:
            i += 1
            continue
        split = _split_key(text)
        if split is None:
            i += 1
            continue
        key = str(_scalar(split[0]))
        rest = split[1]
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            value, i = _block_scalar(lines, i + 1, indent, rest)
            out[key] = value
            continue
        if rest:
            out[key] = _flow(rest) if rest.startswith(("[", "{")) else _scalar(rest)
            i += 1
            continue
        # A nested block, a nested sequence at the same indent, or null.
        if i + 1 < len(lines) and lines[i + 1][0] > indent:
            value, i = _parse_block(lines, i + 1, lines[i + 1][0])
            out[key] = value
        elif i + 1 < len(lines) and lines[i + 1][0] == indent and lines[i + 1][1].strip().startswith("- "):
            value, i = _parse_block(lines, i + 1, indent)
            out[key] = value
        else:
            out[key] = None
            i += 1
    return out, i


def _parse_block(lines, i, indent):
    if i >= len(lines):
        return None, i
    if lines[i][1].strip().startswith("- "):
        items = []
        while i < len(lines):
            ind, raw_text = lines[i]
            text = raw_text.strip()
            if ind != indent or not text.startswith("- "):
                break
            rest = text[2:].strip()
            if not rest:
                i += 1
                if i < len(lines) and lines[i][0] > indent:
                    value, i = _parse_block(lines, i, lines[i][0])
                else:
                    value = None
                items.append(value)
                continue
            if _is_map_entry(rest):
                sub = [(indent + 2, rest)]
                j = i + 1
                while j < len(lines) and lines[j][0] > indent:
                    sub.append(lines[j])
                    j += 1
                value, _ = _parse_map(sub, 0, sub[0][0])
                items.append(value)
                i = j
                continue
            items.append(_flow(rest) if rest.startswith(("[", "{")) else _scalar(rest))
            i += 1
        return items, i
    return _parse_map(lines, i, indent)


def loads(text: str):
    """Parse the Compose subset of YAML."""
    if re.search(r"(^|\n)\s*(%YAML|\.\.\.|&|\*)", text) and "---" not in text[:4]:
        raise YamlSubsetError(
            "this file uses YAML features (anchors, aliases or tags) that the "
            "built-in parser does not implement; install PyYAML for full "
            "support")
    raw = []
    for line in text.splitlines():
        if not line.strip() or line.strip() == "---":
            continue
        # The leading spaces are KEPT: a block scalar's content is
        # dedented by its own indentation, so stripping it here loses
        # the text of every `|` and `>` value.
        stripped = _strip_comment(line)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        raw.append((indent, stripped))
    if not raw:
        return {}
    value, _ = _parse_block(raw, 0, raw[0][0])
    return value
