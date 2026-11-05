"""Parse ``git diff`` unified output into file, hunk, and line records.

Malformed regions are skipped. An empty diff yields an empty list. Paths from
``diff --git a/... b/...`` headers lose the ``a/`` and ``b/`` prefixes only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_GIT = "diff --git "


@dataclass
class DiffLine:
    """One body line of a hunk.

    ``text`` excludes the leading ``+``, ``-``, or context marker. ``old_lineno``
    is set for context and removals; ``new_lineno`` is set for context and
    additions.
    """

    kind: Literal["+", "-", " "]
    text: str
    old_lineno: int | None
    new_lineno: int | None


@dataclass
class Hunk:
    """A single ``@@`` hunk. Starts are the numbers from the hunk header."""

    old_start: int
    new_start: int
    lines: list[DiffLine]


@dataclass
class FileDiff:
    """One file section of a diff.

    ``old_path`` is ``None`` for additions and ``new_path`` is ``None`` for
    deletions. ``status`` is ``binary`` when git reports a binary delta, including
    a binary add or delete.
    """

    old_path: str | None
    new_path: str | None
    status: Literal["added", "deleted", "modified", "renamed", "binary"]
    hunks: list[Hunk]


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """Parse unified diff text. Never raises on malformed input."""

    if not isinstance(diff_text, str) or not diff_text.strip():
        return []
    text = diff_text.replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith("\ufeff"):
        text = text[1:]
    lines = text.splitlines()
    files: list[FileDiff] = []
    index = 0
    total = len(lines)
    while index < total:
        if not lines[index].startswith(_DIFF_GIT):
            index += 1
            continue
        try:
            parsed, index = _parse_file(lines, index)
        except Exception:
            index += 1
            continue
        if parsed is not None:
            files.append(parsed)
    return files


def _parse_file(lines: list[str], start: int) -> tuple[FileDiff | None, int]:
    pair = _split_diff_git(lines[start])
    if pair is None:
        return None, start + 1
    old_path, new_path = pair
    index = start + 1
    total = len(lines)
    is_new = False
    is_deleted = False
    is_rename = False
    is_binary = False

    while index < total:
        line = lines[index]
        if line.startswith(_DIFF_GIT) or line.startswith("@@"):
            break
        if line.startswith("GIT binary patch"):
            is_binary = True
            index += 1
            while index < total and not lines[index].startswith(_DIFF_GIT):
                index += 1
            break
        if line.startswith("Binary files ") and line.rstrip().endswith(" differ"):
            is_binary = True
            left, right = _split_binary_paths(line.rstrip())
            if left is not None or right is not None:
                old_path, new_path = left, right
            index += 1
            break
        if line.startswith("new file mode "):
            is_new = True
        elif line.startswith("deleted file mode "):
            is_deleted = True
        elif line.startswith("rename from ") or line.startswith("copy from "):
            is_rename = True
            old_path = _plain_header_path(line.split(" ", 2)[-1])
        elif line.startswith("rename to ") or line.startswith("copy to "):
            is_rename = True
            new_path = _plain_header_path(line.split(" ", 2)[-1])
        elif line.startswith("--- "):
            old_path = _parse_minus_plus(line)
        elif line.startswith("+++ "):
            new_path = _parse_minus_plus(line)
        index += 1

    hunks: list[Hunk] = []
    if not is_binary:
        while index < total and lines[index].startswith("@@"):
            hunk, index = _parse_hunk(lines, index)
            if hunk is not None:
                hunks.append(hunk)

    if is_binary:
        status: Literal["added", "deleted", "modified", "renamed", "binary"] = "binary"
    elif is_deleted or new_path is None:
        status = "deleted"
        new_path = None
    elif is_new or old_path is None:
        status = "added"
        old_path = None
    elif is_rename or old_path != new_path:
        status = "renamed"
    else:
        status = "modified"

    if old_path is None and new_path is None:
        return None, index
    return FileDiff(old_path, new_path, status, hunks), index


def _parse_hunk(lines: list[str], start: int) -> tuple[Hunk | None, int]:
    match = _HUNK_RE.match(lines[start])
    if not match:
        return None, start + 1
    old_ln = int(match.group(1))
    new_ln = int(match.group(3))
    index = start + 1
    total = len(lines)
    body: list[DiffLine] = []
    while index < total:
        line = lines[index]
        if line.startswith(_DIFF_GIT) or line.startswith("@@"):
            break
        if line.startswith("\\"):
            index += 1
            continue
        if line.startswith("+"):
            body.append(DiffLine("+", line[1:], None, new_ln))
            new_ln += 1
        elif line.startswith("-"):
            body.append(DiffLine("-", line[1:], old_ln, None))
            old_ln += 1
        elif line.startswith(" "):
            body.append(DiffLine(" ", line[1:], old_ln, new_ln))
            old_ln += 1
            new_ln += 1
        else:
            break
        index += 1
    return Hunk(int(match.group(1)), int(match.group(3)), body), index


def _split_diff_git(line: str) -> tuple[str, str] | None:
    if not line.startswith(_DIFF_GIT):
        return None
    payload = line[len(_DIFF_GIT) :].strip()
    if not payload:
        return None
    try:
        if payload.startswith('"'):
            old_raw, rest = _take_quoted(payload)
            rest = rest.lstrip()
            if not rest:
                return None
            if rest.startswith('"'):
                new_raw, _rest = _take_quoted(rest)
            else:
                new_raw = rest
        elif payload.count(" ") == 1:
            old_raw, new_raw = payload.split(" ", 1)
        else:
            marker = " b/"
            idx = payload.find(marker)
            if idx <= 0:
                return None
            old_raw = payload[:idx]
            new_raw = payload[idx + 1 :]
    except ValueError:
        return None
    return _strip_ab(old_raw.strip()), _strip_ab(new_raw.strip())


def _parse_minus_plus(line: str) -> str | None:
    rest = line[4:].strip()
    if not rest:
        return None
    if rest.startswith('"'):
        try:
            path, _rest = _take_quoted(rest)
        except ValueError:
            path = rest.strip('"').split("\t", 1)[0]
    else:
        path = rest.split("\t", 1)[0].strip()
    if path == "/dev/null":
        return None
    return _strip_ab(path)


def _plain_header_path(raw: str) -> str:
    text = raw.strip()
    if text.startswith('"'):
        try:
            path, _rest = _take_quoted(text)
        except ValueError:
            return text.strip('"')
        return path
    return text


def _split_binary_paths(line: str) -> tuple[str | None, str | None]:
    prefix = "Binary files "
    suffix = " differ"
    if not (line.startswith(prefix) and line.endswith(suffix)):
        return None, None
    body = line[len(prefix) : -len(suffix)]
    marker = " and "
    idx = body.find(marker)
    if idx == -1:
        return None, None
    return _binary_one(body[:idx].strip()), _binary_one(body[idx + len(marker) :].strip())


def _binary_one(raw: str) -> str | None:
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1]
    if raw == "/dev/null":
        return None
    return _strip_ab(raw)


def _strip_ab(path: str) -> str:
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _take_quoted(payload: str) -> tuple[str, str]:
    """Decode a git quoted token. ``payload`` must start with a double quote."""

    if not payload.startswith('"'):
        raise ValueError(payload)
    out: list[str] = []
    index = 1
    limit = len(payload)
    while index < limit:
        char = payload[index]
        if char == '"':
            return "".join(out), payload[index + 1 :]
        if char == "\\" and index + 1 < limit:
            nxt = payload[index + 1]
            mapped = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}.get(nxt)
            if mapped is not None:
                out.append(mapped)
                index += 2
                continue
            if nxt in "01234567":
                octal = nxt
                index += 2
                for _ in range(2):
                    if index < limit and payload[index] in "01234567":
                        octal += payload[index]
                        index += 1
                    else:
                        break
                out.append(chr(int(octal, 8)))
                continue
            out.append(nxt)
            index += 2
            continue
        out.append(char)
        index += 1
    raise ValueError(payload)
