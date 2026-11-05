"""Deterministic policy auditor for unified diffs.

Reports findings against a frozen PatchPolicy. Findings describe what a diff
changed relative to agreed restrictions; they make no claim about intent.

Lockfiles (``package-lock.json``, ``yarn.lock``, ``pnpm-lock.yaml``,
``poetry.lock``, ``uv.lock``, ``Cargo.lock``, ``go.sum``) produce at most one
dependency finding each. See ``_lockfile_is_covered``.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass

from a2a_settlement_mediator.schemas import PatchPolicy, PolicyFinding, PolicyRule
from a2a_settlement_mediator.unified_diff import DiffLine, FileDiff, parse_unified_diff_report

_TEST_DIRS = frozenset({"tests", "test", "__tests__"})
# A backup or doc renamed out of a test filename is not a test file, even when
# it remains under tests/. tests/test_auth.py -> tests/test_auth.py.bak is the
# case this list exists to recognize.
_NON_TEST_SUFFIXES = (
    ".bak",
    ".orig",
    ".old",
    ".md",
    ".markdown",
    ".rst",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".pdf",
    ".webp",
)
_JS_TEST_SUFFIXES = (
    ".spec.ts",
    ".spec.tsx",
    ".spec.js",
    ".spec.jsx",
    ".test.ts",
    ".test.tsx",
    ".test.js",
    ".test.jsx",
)
_DOC_SUFFIXES = (".md", ".rst", ".txt")
_HARNESS_NAMES = frozenset(
    {
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        ".coveragerc",
        ".semgrepignore",
        ".eslintignore",
        ".bandit",
        "codecov.yml",
        ".pre-commit-config.yaml",
        "Makefile",
        "makefile",
        "GNUmakefile",
        "noxfile.py",
        "justfile",
        "Justfile",
        "Taskfile.yml",
        ".gitlab-ci.yml",
        ".travis.yml",
        "azure-pipelines.yml",
        "Jenkinsfile",
        "bitbucket-pipelines.yml",
    }
)
_HARNESS_DIRS = (".github/workflows", ".circleci", ".buildkite", ".github/actions")
_HARNESS_SECTION_PREFIXES = (
    "[tool.pytest",
    "[tool.coverage",
    "[tool.ruff",
    "[tool.bandit",
)
_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "Cargo.lock",
        "go.sum",
    }
)
_PY_EXTS = frozenset({".py", ".pyi"})
_JS_EXTS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_HASH_COMMENT_EXTS = frozenset(
    {
        ".py",
        ".pyi",
        ".pyx",
        ".toml",
        ".cfg",
        ".ini",
        ".yml",
        ".yaml",
        ".sh",
        ".bash",
        ".rb",
        ".r",
    }
)
_SLASH_COMMENT_EXTS = frozenset(
    {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".java",
        ".go",
        ".rs",
        ".c",
        ".h",
        ".cpp",
        ".cc",
        ".hpp",
        ".cs",
        ".swift",
        ".kt",
        ".scala",
        ".php",
        ".vue",
        ".mod",
        ".css",
    }
)
_DEP_JSON_KEYS = frozenset(
    {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}
)
_LOCK_STRUCTURAL = {"{", "}", "[", "]", "},", "],", "{,", "[,"}

_SECTION_RE = re.compile(r"^\[([^\]\n]+)\]\s*(?:#.*)?$")
_ASSERTION_RE = re.compile(
    r"^\s*(?:"
    r"assert\s+\S"
    r"|assert\s*\("
    r"|assert\.\w+\s*\("
    r"|self\.assert\w+\s*\("
    r"|(?:with\s+)?pytest\.raises\s*\("
    r"|expect\s*\("
    r"|assertThat\s*\("
    r")"
)
_SKIP_RE = re.compile(
    r"pytest\.mark\.skipif\b"
    r"|pytest\.mark\.skip\b"
    r"|pytest\.mark\.xfail\b"
    r"|pytest\.skip\s*\("
    r"|unittest\.skip(?:If|Unless)?\b"
    r"|(?<![\w.])@skip\b"
    r"|\bit\.skip\s*\("
    r"|\bdescribe\.skip\s*\("
    r"|\btest\.skip\s*\("
    r"|\bxit\s*\("
    r"|\bxdescribe\s*\("
    r"|\bit\.only\s*\("
    r"|\bdescribe\.only\s*\("
    r"|\btest\.only\s*\("
)
_SUPPRESSION_RE = re.compile(
    r"(?i:nosec\b)"
    r"|(?i:\bnoqa\b)"
    r"|(?i:nosemgrep\b)"
    r"|(?i:eslint-disable)"
    r"|@ts-ignore\b"
    r"|@ts-nocheck\b"
    r"|@ts-expect-error\b"
    r"|(?i:codeql\[)"
    r"|(?i:lgtm\[)"
    r"|(?i:pragma:\s*no\s*cover)"
    r"|(?i:pylint:\s*disable)"
    r"|(?i:NOLINT)"
)
_TYPE_IGNORE_RE = re.compile(r"type:\s*ignore\b")
_JAVA_SUPPRESS_RE = re.compile(r"(?<![\w])@SuppressWarnings\b")
_PY_LIT = r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|-?\d+|True|False|None)"
_PY_IDENT = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
_PY_ONE_RE = re.compile(
    rf"^\s*if\s+\(?\s*{_PY_IDENT}\s*==\s*{_PY_LIT}\s*\)?\s*:\s*return\s+{_PY_LIT}\s*(?:#.*)?$"
)
_PY_IF_RE = re.compile(
    rf"^\s*if\s+\(?\s*{_PY_IDENT}\s*==\s*{_PY_LIT}\s*\)?\s*:\s*(?:#.*)?$"
)
_PY_RET_RE = re.compile(rf"^\s*return\s+{_PY_LIT}\s*(?:#.*)?$")
_JS_LIT = r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|-?\d+|true|false|null)"
_JS_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
_JS_ONE_RE = re.compile(
    rf"^\s*if\s*\(\s*{_JS_IDENT}\s*===?\s*{_JS_LIT}\s*\)\s*return\s+{_JS_LIT}\s*;?\s*$"
)
_PKG_SECTION_RE = re.compile(
    r'"(dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{'
)
_PKG_ENTRY_RE = re.compile(r'"([^"]+)"\s*:')
_GO_SUM_RE = re.compile(r"^(\S+)\s+v\S+")
_GO_REQUIRE_RE = re.compile(r"^(?:require\s+)?(\S+)\s+(v\d\S*)")
_LOCK_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_NODE_MODULES_RE = re.compile(r'"node_modules/((?:@[^"/]+/)?[^"]+)"')
_LOCK_META_RE = re.compile(
    r'^"(?:version|resolved|integrity|license|dev|optional|devOptional|'
    r"requires|dependencies|peer|bundled|engines|funding|bin|inBundle|"
    r'hasInstallScript|link|extraneous)"\s*:'
)
_POETRY_GROUP_RE = re.compile(r"\[tool\.poetry\.group\.[^\]]+\.dependencies\]")
_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_KEY_VALUE_RE = re.compile(r"""^["']?([A-Za-z0-9._-]+)["']?\s*=""")


@dataclass
class _PkgChange:
    added_line: int | None = None
    added_text: str | None = None
    removed_line: int | None = None
    removed_text: str | None = None


def audit_diff(diff_text: str, policy: PatchPolicy) -> list[PolicyFinding]:
    """Return deterministic findings for ``diff_text`` under ``policy``.

    Order is path, then line (file-level findings with no line first), then
    rule name. Severity is always ``policy.severity_for(rule)``.
    """

    text = diff_text if isinstance(diff_text, str) else ""
    report = parse_unified_diff_report(text)
    files = report.files
    findings: list[PolicyFinding] = []
    manifest_names: set[str] = set()
    disallowed: set[str] = set()
    lockfiles: list[FileDiff] = []
    allowed = _allowset(policy)

    # Content the parser could not attribute to a file was not audited.
    unparsed = None
    if report.problems:
        unparsed = "malformed diff: " + "; ".join(report.problems[:5])
        if len(report.problems) > 5:
            unparsed += f"; and {len(report.problems) - 5} more"
    elif text.strip() and not files:
        unparsed = "diff contains no file changes"
    if unparsed is not None:
        findings.append(_finding(policy, PolicyRule.UNINSPECTABLE_CHANGE, "", None, unparsed))

    for fd in files:
        findings.extend(_uninspectable_findings(fd, policy, allowed))
        findings.extend(_structural_findings(fd, policy))
        findings.extend(_content_findings(fd, policy))
        if _basename(_primary_path(fd)) in _LOCKFILES:
            if _has_delta(fd):
                lockfiles.append(fd)
            continue
        changes = _manifest_changes(fd)
        findings.extend(
            _emit_packages(fd, changes, policy, allowed, manifest_names, disallowed)
        )
        if not changes:
            findings.extend(_unclassified_manifest_findings(fd, policy, allowed))

    for fd in lockfiles:
        if _lockfile_is_covered(fd, allowed, manifest_names, disallowed):
            continue
        findings.append(
            _finding(
                policy,
                PolicyRule.DEPENDENCY_CHANGED,
                _primary_path(fd),
                None,
                "lockfile changed",
            )
        )

    findings.sort(key=_sort_key)
    return findings


def _sort_key(finding: PolicyFinding) -> tuple[str, int, str]:
    line = finding.line if finding.line is not None else -1
    return (finding.path, line, finding.rule.value)


def _finding(
    policy: PatchPolicy,
    rule: PolicyRule,
    path: str,
    line: int | None,
    evidence: str,
) -> PolicyFinding:
    return PolicyFinding(
        rule=rule,
        severity=policy.severity_for(rule),
        path=path,
        line=line,
        evidence=evidence.strip(),
        source="deterministic",
    )


def _primary_path(fd: FileDiff) -> str:
    if fd.status == "deleted":
        return fd.old_path or fd.new_path or ""
    return fd.new_path or fd.old_path or ""


def _norm_path(path: str) -> str:
    text = path.replace("\\", "/").strip()
    if text.startswith("./"):
        text = text[2:]
    return text


def _basename(path: str) -> str:
    return posixpath.basename(_norm_path(path))


def _ext(path: str) -> str:
    base = _basename(path).lower()
    dot = base.rfind(".")
    if dot <= 0:
        return ""
    return base[dot:]


def _is_doc(path: str) -> bool:
    return _norm_path(path).lower().endswith(_DOC_SUFFIXES)


def _is_test_path(path: str | None) -> bool:
    if not path:
        return False
    norm = _norm_path(path)
    name = posixpath.basename(norm)
    if name == "conftest.py":
        return True
    if name.startswith("test_") and name.endswith(".py"):
        return True
    if name.endswith("_test.py"):
        return True
    if name.endswith(_JS_TEST_SUFFIXES):
        return True
    parents = norm.split("/")[:-1]
    if any(part in _TEST_DIRS for part in parents):
        if name.lower().endswith(_NON_TEST_SUFFIXES):
            return False
        return True
    return False


def _is_plain_harness(path: str) -> bool:
    norm = _norm_path(path)
    base = posixpath.basename(norm)
    if norm == "conftest.py":
        return True
    if any(norm == root or norm.startswith(root + "/") for root in _HARNESS_DIRS):
        return True
    if base in _HARNESS_NAMES:
        return True
    if base.startswith(("jest.config.", "vitest.config.", "karma.conf.", ".eslintrc")):
        return True
    return False


def _section_header(text: str) -> str | None:
    match = _SECTION_RE.match(text.strip())
    if not match:
        return None
    return "[" + match.group(1).strip() + "]"


def _is_harness_section(header: str) -> bool:
    return header.startswith(_HARNESS_SECTION_PREFIXES)


def _pyproject_touches_harness(fd: FileDiff) -> bool:
    for hunk in fd.hunks:
        section: str | None = None
        for line in hunk.lines:
            header = _section_header(line.text)
            if header is not None:
                section = header
                if line.kind in "+-" and _is_harness_section(header):
                    return True
                continue
            if line.kind in "+-" and section is not None and _is_harness_section(section):
                return True
    return False


def _is_canonical_path(path: str) -> bool:
    """A repository-relative POSIX path with no empty, ``.``, or ``..`` parts."""
    if not path or path.startswith("/") or "\\" in path:
        return False
    if any(ord(char) < 0x20 for char in path):
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def _uninspectable_findings(
    fd: FileDiff, policy: PatchPolicy, allowed: set[str]
) -> list[PolicyFinding]:
    """Changes whose effect the line rules cannot see."""
    findings: list[PolicyFinding] = []
    path = _primary_path(fd)
    for candidate in (fd.old_path, fd.new_path):
        if candidate is not None and not _is_canonical_path(candidate):
            findings.append(
                _finding(
                    policy,
                    PolicyRule.PATH_NOT_ALLOWED,
                    candidate,
                    None,
                    "non-canonical path",
                )
            )
    if fd.status == "binary":
        findings.append(
            _finding(policy, PolicyRule.UNINSPECTABLE_CHANGE, path, None, "binary change")
        )
    if fd.submodule and _normalize_pkg(_basename(path)) not in allowed:
        findings.append(
            _finding(policy, PolicyRule.DEPENDENCY_CHANGED, path, None, "submodule changed")
        )
    return findings


def _structural_findings(fd: FileDiff, policy: PatchPolicy) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    deleted = _deleted_test_finding(fd, policy)
    if deleted is not None:
        findings.append(deleted)
    harness = _harness_finding(fd, policy)
    if harness is not None:
        findings.append(harness)
    blocked = _path_finding(fd, policy)
    if blocked is not None:
        findings.append(blocked)
    return findings


def _deleted_test_finding(fd: FileDiff, policy: PatchPolicy) -> PolicyFinding | None:
    old = fd.old_path or ""
    new = fd.new_path or ""
    if fd.status == "deleted" and _is_test_path(old):
        return _finding(policy, PolicyRule.TEST_FILE_DELETED, old, None, f"deleted {old}")
    if fd.status == "renamed" and _is_test_path(old) and not _is_test_path(new):
        return _finding(
            policy,
            PolicyRule.TEST_FILE_DELETED,
            old,
            None,
            f"renamed to {new}",
        )
    return None


def _harness_finding(fd: FileDiff, policy: PatchPolicy) -> PolicyFinding | None:
    paths: list[str] = []
    for candidate in (fd.old_path, fd.new_path):
        if candidate and candidate not in paths:
            paths.append(candidate)
    plain = [path for path in paths if _is_plain_harness(path)]
    if plain:
        primary = _primary_path(fd)
        path = primary if primary and _is_plain_harness(primary) else plain[0]
        return _finding(policy, PolicyRule.HARNESS_CHANGED, path, None, "changed")
    toml = any(_basename(path) == "pyproject.toml" for path in paths)
    if toml and _pyproject_touches_harness(fd):
        return _finding(
            policy,
            PolicyRule.HARNESS_CHANGED,
            _primary_path(fd),
            None,
            "changed",
        )
    return None


def _path_finding(fd: FileDiff, policy: PatchPolicy) -> PolicyFinding | None:
    if not policy.allowed_paths:
        return None
    path = _primary_path(fd)
    if not path:
        return None
    norm = _norm_path(path)
    if any(fnmatch.fnmatch(norm, pattern) for pattern in policy.allowed_paths):
        return None
    return _finding(policy, PolicyRule.PATH_NOT_ALLOWED, path, None, path)


def _content_findings(fd: FileDiff, policy: PatchPolicy) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    findings.extend(_assertion_findings(fd, policy))
    path = _primary_path(fd)
    if not path or _is_doc(path):
        return findings
    for hunk in fd.hunks:
        for line in hunk.lines:
            if line.kind != "+":
                continue
            if _is_weak_assertion(line.text):
                findings.append(
                    _finding(
                        policy,
                        PolicyRule.WEAK_ASSERTION_ADDED,
                        path,
                        line.new_lineno,
                        line.text,
                    )
                )
            if _SKIP_RE.search(line.text):
                findings.append(
                    _finding(
                        policy,
                        PolicyRule.TEST_SKIP_ADDED,
                        path,
                        line.new_lineno,
                        line.text,
                    )
                )
            if _line_has_suppression(line.text, path, policy.type_ignore_is_suppression):
                findings.append(
                    _finding(
                        policy,
                        PolicyRule.SUPPRESSION_ADDED,
                        path,
                        line.new_lineno,
                        line.text,
                    )
                )
    findings.extend(_literal_findings(fd, policy))
    return findings


def _assertion_findings(fd: FileDiff, policy: PatchPolicy) -> list[PolicyFinding]:
    if fd.status not in {"modified", "renamed"}:
        return []
    old = fd.old_path or ""
    new = fd.new_path or ""
    if _is_test_path(old):
        path = old
    elif _is_test_path(new):
        path = new
    else:
        return []
    findings: list[PolicyFinding] = []
    for hunk in fd.hunks:
        for line in hunk.lines:
            if line.kind != "-" or not _ASSERTION_RE.match(line.text):
                continue
            findings.append(
                _finding(
                    policy,
                    PolicyRule.ASSERTION_CHANGED,
                    path,
                    line.old_lineno,
                    line.text,
                )
            )
    return findings


def _is_weak_assertion(text: str) -> bool:
    stripped = text.strip()
    if re.fullmatch(r"assert\s+True", stripped):
        return True
    if re.fullmatch(r"assert\s+1", stripped):
        return True
    if re.fullmatch(r"assert\s+not\s+False", stripped):
        return True
    if re.fullmatch(r"assert\s+([A-Za-z_]\w*)\s*==\s*\1", stripped):
        return True
    if re.fullmatch(r"assert\s+(-?\d+)\s*==\s*\1", stripped):
        return True
    if re.fullmatch(r"expect\(\s*true\s*\)\.toBe\(\s*true\s*\)\s*;?", stripped):
        return True
    if re.fullmatch(r"expect\(\s*1\s*\)\.toBe\(\s*1\s*\)\s*;?", stripped):
        return True
    if re.fullmatch(r"self\.assertTrue\(\s*True\s*\)", stripped):
        return True
    return False


def _comment_styles(path: str) -> tuple[bool, bool]:
    """Return ``(hash_comments, line_comments)`` for ``path``.

    Python-style sources use ``#``. JS/TS and Java-style sources use ``//``
    and block comments. Other paths accept both.
    """

    ext = _ext(path)
    if ext in _SLASH_COMMENT_EXTS:
        return False, True
    if ext in _HASH_COMMENT_EXTS:
        return True, False
    return True, True


def _line_has_suppression(text: str, path: str, type_ignore: bool) -> bool:
    comments = "\n".join(_comment_texts(text, path))
    if _SUPPRESSION_RE.search(comments):
        return True
    if type_ignore and _TYPE_IGNORE_RE.search(comments):
        return True
    if _JAVA_SUPPRESS_RE.search(_mask_strings(text)):
        return True
    return False


def _comment_texts(line: str, path: str) -> list[str]:
    """Comment bodies on one line, ignoring quoted strings."""

    hash_comments, line_comments = _comment_styles(path)
    comments: list[str] = []
    index = 0
    limit = len(line)
    while index < limit:
        char = line[index]
        if char in {"'", '"', "`"}:
            index = _skip_string(line, index, char)
            continue
        if hash_comments and char == "#":
            comments.append(line[index:])
            break
        if line_comments and char == "/" and index + 1 < limit and line[index + 1] == "/":
            comments.append(line[index:])
            break
        if line_comments and char == "/" and index + 1 < limit and line[index + 1] == "*":
            end = line.find("*/", index + 2)
            if end == -1:
                comments.append(line[index:])
                break
            comments.append(line[index : end + 2])
            index = end + 2
            continue
        index += 1
    return comments


def _skip_string(line: str, start: int, quote: str) -> int:
    limit = len(line)
    if quote != "`" and line.startswith(quote * 3, start):
        end = line.find(quote * 3, start + 3)
        if end == -1:
            return limit
        return end + 3
    index = start + 1
    while index < limit:
        if line[index] == "\\":
            index += 2
            continue
        if line[index] == quote:
            return index + 1
        index += 1
    return limit


def _mask_strings(line: str) -> str:
    parts: list[str] = []
    index = 0
    limit = len(line)
    while index < limit:
        char = line[index]
        if char in {"'", '"', "`"}:
            nxt = _skip_string(line, index, char)
            parts.append('""')
            index = nxt
            continue
        parts.append(char)
        index += 1
    return "".join(parts)


def _literal_findings(fd: FileDiff, policy: PatchPolicy) -> list[PolicyFinding]:
    path = _primary_path(fd)
    if not path or _is_test_path(path):
        return []
    ext = _ext(path)
    if ext in _PY_EXTS:
        return _python_literal_findings(fd, policy, path)
    if ext in _JS_EXTS:
        return _js_literal_findings(fd, policy, path)
    return []


def _python_literal_findings(
    fd: FileDiff, policy: PatchPolicy, path: str
) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    for hunk in fd.hunks:
        lines = hunk.lines
        index = 0
        while index < len(lines):
            line = lines[index]
            if line.kind == "+" and _PY_ONE_RE.match(line.text):
                findings.append(
                    _finding(
                        policy,
                        PolicyRule.LITERAL_RETURN_SUSPECT,
                        path,
                        line.new_lineno,
                        line.text,
                    )
                )
                index += 1
                continue
            if (
                line.kind == "+"
                and index + 1 < len(lines)
                and lines[index + 1].kind == "+"
                and _PY_IF_RE.match(line.text)
                and _PY_RET_RE.match(lines[index + 1].text)
            ):
                evidence = f"{line.text.strip()} / {lines[index + 1].text.strip()}"
                findings.append(
                    _finding(
                        policy,
                        PolicyRule.LITERAL_RETURN_SUSPECT,
                        path,
                        line.new_lineno,
                        evidence,
                    )
                )
                index += 2
                continue
            index += 1
    return findings


def _js_literal_findings(fd: FileDiff, policy: PatchPolicy, path: str) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    for hunk in fd.hunks:
        for line in hunk.lines:
            if line.kind == "+" and _JS_ONE_RE.match(line.text):
                findings.append(
                    _finding(
                        policy,
                        PolicyRule.LITERAL_RETURN_SUSPECT,
                        path,
                        line.new_lineno,
                        line.text,
                    )
                )
    return findings


def _allowset(policy: PatchPolicy) -> set[str]:
    return {name for item in policy.allowed_dependency_changes if (name := _normalize_pkg(item))}


def _normalize_pkg(name: str) -> str:
    text = name.strip().strip("\"'").lower().replace("_", "-")
    if not text:
        return ""
    if text.startswith("@"):
        match = re.match(r"^(@[^/\[<>=!~;\s]+/[^\[<>=!~;\s]+)", text)
        return match.group(1) if match else text.split()[0]
    text = text.split("[", 1)[0]
    return re.split(r"[<>=!~;\s]", text, maxsplit=1)[0]


def _lineno(line: DiffLine) -> int | None:
    if line.kind == "+":
        return line.new_lineno
    if line.kind == "-":
        return line.old_lineno
    return None


def _changed_lines(fd: FileDiff) -> list[DiffLine]:
    return [line for hunk in fd.hunks for line in hunk.lines if line.kind in "+-"]


def _has_delta(fd: FileDiff) -> bool:
    if fd.status in {"added", "deleted"}:
        return True
    return any(line.kind in "+-" for hunk in fd.hunks for line in hunk.lines)


def _note(
    changes: dict[str, _PkgChange],
    raw_name: str,
    kind: str,
    line_no: int | None,
    evidence_text: str,
) -> None:
    key = _normalize_pkg(raw_name)
    if not key:
        return
    slot = changes.setdefault(key, _PkgChange())
    if kind == "+" and slot.added_text is None:
        slot.added_line = line_no
        slot.added_text = evidence_text.strip()
    elif kind == "-" and slot.removed_text is None:
        slot.removed_line = line_no
        slot.removed_text = evidence_text.strip()


def _emit_packages(
    fd: FileDiff,
    changes: dict[str, _PkgChange],
    policy: PatchPolicy,
    allowed: set[str],
    manifest_names: set[str],
    disallowed: set[str],
) -> list[PolicyFinding]:
    path = _primary_path(fd)
    findings: list[PolicyFinding] = []
    for pkg, slot in changes.items():
        manifest_names.add(pkg)
        if pkg in allowed:
            continue
        disallowed.add(pkg)
        if slot.added_text is not None:
            findings.append(
                _finding(
                    policy,
                    PolicyRule.DEPENDENCY_CHANGED,
                    path,
                    slot.added_line,
                    f"added {slot.added_text}",
                )
            )
        elif slot.removed_text is not None:
            findings.append(
                _finding(
                    policy,
                    PolicyRule.DEPENDENCY_CHANGED,
                    path,
                    slot.removed_line,
                    f"removed {slot.removed_text}",
                )
            )
    return findings


_SECTIONED_MANIFESTS = frozenset({"pyproject.toml", "package.json", "Pipfile", "Cargo.toml"})
_NON_DEP_KEYS = frozenset({"version", "name", "python", "requires-python", "edition"})
_DEP_LIKE_PATTERNS = (
    re.compile(
        r"""^\s*["'](?P<key>[A-Za-z0-9][A-Za-z0-9_.\-]*)(\[[^\]]*\])?\s*"""
        r"""(==|>=|<=|~=|!=|>|<|@)"""
    ),
    re.compile(r"""^\s*"(?P<key>@?[A-Za-z0-9][\w.\-/]*)"\s*:\s*"[\^~>=<*]?\s*\d"""),
    re.compile(r"""^\s*(?P<key>[A-Za-z0-9][\w\-]*)\s*=\s*("[\^~>=<*]?\s*\d|\{[^}]*version)"""),
)
# Entries whose value is not a numeric version: a tag, URL, path, or workspace
# reference may still be a dependency.
_ENTRY_PATTERNS = (
    re.compile(r"""^\s*"(?P<key>@?[A-Za-z0-9][\w.\-/]*)"\s*:\s*\S"""),
    re.compile(r"""^\s*(?P<key>[A-Za-z0-9][\w.\-]*)\s*=\s*\S"""),
    re.compile(r"""^\s*["'](?P<key>[A-Za-z0-9][A-Za-z0-9_.\-]*)"""),
)
_JSON_OPEN_RE = re.compile(r'^\s*"[^"]+"\s*:\s*[\[{]')


def _dependency_like_name(
    text: str, patterns: tuple[re.Pattern[str], ...] = _DEP_LIKE_PATTERNS
) -> str | None:
    for pattern in patterns:
        match = pattern.match(text)
        if match is None:
            continue
        key = match.group("key")
        if key.lower() in _NON_DEP_KEYS:
            continue
        return key
    return None


def _unclassified_manifest_findings(
    fd: FileDiff, policy: PatchPolicy, allowed: set[str]
) -> list[PolicyFinding]:
    """Flag dependency-like lines whose section header is outside every hunk.

    Without the header the change cannot be attributed to a dependency table,
    so it is reported instead of silently passed.
    """
    path = _primary_path(fd)
    if _basename(path) not in _SECTIONED_MANIFESTS:
        return []
    for line in _changed_lines(fd):
        name = _dependency_like_name(line.text)
        if name is None or _normalize_pkg(name) in allowed:
            continue
        return [
            _finding(
                policy,
                PolicyRule.DEPENDENCY_CHANGED,
                path,
                _lineno(line),
                f"unclassified manifest change: {line.text.strip()[:200]}",
            )
        ]
    # A changed entry with no section or object header above it in its hunk
    # cannot be shown to be outside a dependency table.
    for hunk in fd.hunks:
        attributed = False
        for line in hunk.lines:
            if _section_header(line.text) is not None or _JSON_OPEN_RE.match(line.text):
                attributed = True
                continue
            if attributed or line.kind not in "+-":
                continue
            name = _dependency_like_name(line.text, _ENTRY_PATTERNS)
            if name is None or _normalize_pkg(name) in allowed:
                continue
            return [
                _finding(
                    policy,
                    PolicyRule.UNINSPECTABLE_CHANGE,
                    path,
                    _lineno(line),
                    f"manifest entry outside a visible section: {line.text.strip()[:200]}",
                )
            ]
    return []


def _manifest_changes(fd: FileDiff) -> dict[str, _PkgChange]:
    base = _basename(_primary_path(fd))
    if re.fullmatch(r"requirements.*\.txt", base) or re.fullmatch(r"constraints.*\.txt", base):
        return _req_file_changes(fd)
    if base == "Pipfile":
        return _pipfile_changes(fd)
    if base == "pyproject.toml":
        return _pyproject_dep_changes(fd)
    if base == "package.json":
        return _package_json_changes(fd)
    if base == "go.mod":
        return _go_mod_changes(fd)
    if base == "Cargo.toml":
        return _cargo_changes(fd)
    return {}


def _python_req_name(text: str) -> str | None:
    stripped = text.strip().strip("\"'")
    if not stripped or stripped.startswith("#") or stripped.startswith("-"):
        return None
    if "://" in stripped or stripped.startswith(("git+", "svn+", "hg+", "bzr+")):
        egg = re.search(r"(?:#|&|\?)egg=([A-Za-z0-9._-]+)", stripped)
        return egg.group(1) if egg else None
    match = _REQ_NAME_RE.match(stripped)
    if not match:
        return None
    return match.group(1)


def _req_file_changes(fd: FileDiff) -> dict[str, _PkgChange]:
    changes: dict[str, _PkgChange] = {}
    for line in _changed_lines(fd):
        raw = line.text.strip()
        name = _python_req_name(raw)
        if name:
            _note(changes, name, line.kind, _lineno(line), raw)
    return changes


def _pipfile_changes(fd: FileDiff) -> dict[str, _PkgChange]:
    changes: dict[str, _PkgChange] = {}
    for hunk in fd.hunks:
        section: str | None = None
        for line in hunk.lines:
            header = _section_header(line.text)
            if header is not None:
                section = header
                continue
            if section not in {"[packages]", "[dev-packages]"} or line.kind not in "+-":
                continue
            match = _KEY_VALUE_RE.match(line.text.strip())
            if match:
                _note(changes, match.group(1), line.kind, _lineno(line), line.text.strip())
    return changes


def _is_poetry_dep_section(header: str | None) -> bool:
    if header is None:
        return False
    if header in {"[tool.poetry.dependencies]", "[tool.poetry.dev-dependencies]"}:
        return True
    return _POETRY_GROUP_RE.fullmatch(header) is not None


def _opens_dep_array(section: str | None, stripped: str) -> bool:
    if section in {None, "[project]"} and re.match(r"^dependencies\s*=\s*\[", stripped):
        return True
    optional = section == "[project.optional-dependencies]" or (
        section is not None and section.startswith("[project.optional-dependencies.")
    )
    if optional and re.match(r"^[A-Za-z0-9_-]+\s*=\s*\[", stripped):
        return True
    return False


def _quoted_strings(text: str) -> list[str]:
    return re.findall(r'"([^"]*)"', text) + re.findall(r"'([^']*)'", text)


def _closes_array(text: str) -> bool:
    return "]" in _mask_strings(text)


def _note_req_strings(
    changes: dict[str, _PkgChange], line: DiffLine, stripped: str
) -> None:
    for req in _quoted_strings(stripped):
        name = _python_req_name(req)
        if name:
            _note(changes, name, line.kind, _lineno(line), req)


def _pyproject_dep_changes(fd: FileDiff) -> dict[str, _PkgChange]:
    changes: dict[str, _PkgChange] = {}
    for hunk in fd.hunks:
        section: str | None = None
        in_array = False
        for line in hunk.lines:
            stripped = line.text.strip()
            header = _section_header(stripped)
            if header is not None:
                section = header
                in_array = False
                continue
            if _is_poetry_dep_section(section):
                if line.kind in "+-":
                    match = _KEY_VALUE_RE.match(stripped)
                    if match and match.group(1) != "python":
                        _note(changes, match.group(1), line.kind, _lineno(line), stripped)
                continue
            if _opens_dep_array(section, stripped):
                if line.kind in "+-":
                    _note_req_strings(changes, line, stripped)
                in_array = not _closes_array(stripped)
                continue
            if in_array:
                if line.kind in "+-":
                    _note_req_strings(changes, line, stripped)
                if _closes_array(stripped):
                    in_array = False
    return changes


def _brace_delta(text: str) -> int:
    masked = _mask_strings(text)
    return masked.count("{") - masked.count("}")


def _package_json_changes(fd: FileDiff) -> dict[str, _PkgChange]:
    changes: dict[str, _PkgChange] = {}
    for hunk in fd.hunks:
        section: str | None = None
        depth = 0
        section_depth: int | None = None
        for line in hunk.lines:
            stripped = line.text.strip()
            opened = _PKG_SECTION_RE.search(stripped)
            if opened:
                section = opened.group(1)
                section_depth = depth + 1
            elif (
                section is not None
                and section_depth is not None
                and depth == section_depth
                and line.kind in "+-"
            ):
                match = _PKG_ENTRY_RE.match(stripped)
                if match and match.group(1) not in _DEP_JSON_KEYS:
                    _note(
                        changes,
                        match.group(1),
                        line.kind,
                        _lineno(line),
                        stripped.rstrip(",").strip(),
                    )
            depth += _brace_delta(line.text)
            if section_depth is not None and depth < section_depth:
                section = None
                section_depth = None
    return changes


def _go_mod_changes(fd: FileDiff) -> dict[str, _PkgChange]:
    changes: dict[str, _PkgChange] = {}
    for hunk in fd.hunks:
        in_require = False
        for line in hunk.lines:
            stripped = line.text.strip()
            if stripped == "require (" or stripped.startswith("require ("):
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue
            if line.kind not in "+-":
                continue
            if stripped.startswith(("replace ", "exclude ", "module ", "go ", "retract ")):
                continue
            if stripped.startswith("require ") or in_require:
                match = _GO_REQUIRE_RE.match(stripped)
                if match:
                    _note(changes, match.group(1), line.kind, _lineno(line), stripped)
    return changes


def _cargo_section_package(header: str) -> str | None:
    inner = header[1:-1].strip()
    for prefix in ("dependencies.", "dev-dependencies.", "build-dependencies."):
        if inner.startswith(prefix):
            return inner[len(prefix) :].strip().strip("\"'")
    return None


def _is_cargo_dep_table(header: str) -> bool:
    inner = header[1:-1].strip()
    if inner in {"dependencies", "dev-dependencies", "build-dependencies"}:
        return True
    return inner.endswith((".dependencies", ".dev-dependencies", ".build-dependencies"))


def _cargo_changes(fd: FileDiff) -> dict[str, _PkgChange]:
    changes: dict[str, _PkgChange] = {}
    for hunk in fd.hunks:
        section: str | None = None
        named: str | None = None
        for line in hunk.lines:
            header = _section_header(line.text)
            if header is not None:
                section = header
                named = _cargo_section_package(header)
                continue
            if section is None:
                continue
            if named:
                if line.kind in "+-":
                    _note(changes, named, line.kind, _lineno(line), line.text.strip())
                continue
            if not _is_cargo_dep_table(section) or line.kind not in "+-":
                continue
            match = _KEY_VALUE_RE.match(line.text.strip())
            if match:
                _note(changes, match.group(1), line.kind, _lineno(line), line.text.strip())
    return changes


def _lockfile_is_covered(
    fd: FileDiff,
    allowed: set[str],
    manifest_names: set[str],
    disallowed: set[str],
) -> bool:
    """Return True when a lockfile change should not be reported.

    A lockfile contributes at most one dependency finding. That finding is
    omitted when either:

    * the same diff changes one or more manifest dependencies and every one
      of those packages is allowlisted (an opaque lockfile hunk is treated
      as the lockstep result of that manifest edit); or
    * every substantive changed line is attributed to a package and every
      one of those packages is allowlisted. ``go.sum`` and
      ``package-lock.json`` are parsed line by line. Other lockfiles count
      as fully attributed only when every changed line is a ``name = "..."``
      entry (or empty / structural).

    A lockfile-only rewrite that cannot be fully attributed is reported
    once, including when the allowlist is non-empty.
    """

    if manifest_names and not disallowed:
        return True
    names, unattributed = _scan_lock(fd)
    if not names and not unattributed:
        return True
    return bool(names) and not unattributed and names <= allowed


def _scan_lock(fd: FileDiff) -> tuple[set[str], bool]:
    lines = _changed_lines(fd)
    base = _basename(_primary_path(fd))
    if base == "go.sum":
        return _scan_go_sum(lines)
    if base == "package-lock.json":
        return _scan_package_lock(lines)
    names: set[str] = set()
    unattributed = False
    for line in lines:
        text = line.text.strip()
        if not text or text in _LOCK_STRUCTURAL:
            continue
        match = _LOCK_NAME_RE.match(text)
        if match:
            names.add(_normalize_pkg(match.group(1)))
            continue
        unattributed = True
    return names, unattributed


def _scan_go_sum(lines: list[DiffLine]) -> tuple[set[str], bool]:
    names: set[str] = set()
    unattributed = False
    for line in lines:
        text = line.text.strip()
        if not text:
            continue
        match = _GO_SUM_RE.match(text)
        if match:
            names.add(_normalize_pkg(match.group(1)))
        else:
            unattributed = True
    return names, unattributed


def _scan_package_lock(lines: list[DiffLine]) -> tuple[set[str], bool]:
    names: set[str] = set()
    unattributed = False
    for line in lines:
        text = line.text.strip().rstrip(",")
        if not text or text in _LOCK_STRUCTURAL:
            continue
        modules = _NODE_MODULES_RE.search(text)
        if modules:
            names.add(_normalize_pkg(modules.group(1)))
            continue
        if _LOCK_META_RE.match(text):
            continue
        unattributed = True
    return names, unattributed
