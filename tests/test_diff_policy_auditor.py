"""Adversarial tests for the deterministic diff policy auditor."""

from __future__ import annotations

from pathlib import Path

import pytest

from a2a_settlement_mediator.diff_policy_auditor import audit_diff
from a2a_settlement_mediator.schemas import FindingSeverity, PatchPolicy, PolicyRule

FIXTURES = Path(__file__).parent / "fixtures" / "diffs"


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _check(findings: list, policy: PatchPolicy) -> None:
    previous = None
    for finding in findings:
        assert finding.source == "deterministic"
        assert finding.rule != PolicyRule.REVIEWER_CONCERN
        assert finding.severity == policy.severity_for(finding.rule)
        key = (
            finding.path,
            -1 if finding.line is None else finding.line,
            finding.rule.value,
        )
        if previous is not None:
            assert previous <= key
        previous = key


def run(diff: str, policy: PatchPolicy | None = None) -> list:
    chosen = policy if policy is not None else PatchPolicy()
    findings = audit_diff(diff, chosen)
    _check(findings, chosen)
    return findings


def _hunk(path: str, lines: list[str], header: str = "@@ -1,1 +1,2 @@") -> str:
    body = "\n".join(lines) + "\n"
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"{header}\n"
        f"{body}"
    )


def _addition(path: str, code: str) -> str:
    return _hunk(path, [" start", f"+{code}", " end"], "@@ -1,2 +1,3 @@")


def _removal(path: str, code: str) -> str:
    return _hunk(
        path,
        [" def test_case():", f"-{code}", "     cleanup()"],
        "@@ -10,3 +10,2 @@",
    )


def test_valid_fix_has_no_findings():
    assert run(load("valid_fix.diff")) == []


def test_deleted_assertion_defaults_to_review_and_can_be_violation():
    findings = run(load("deleted_assertion.diff"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == PolicyRule.ASSERTION_CHANGED
    assert finding.severity == FindingSeverity.REVIEW
    assert finding.path == "tests/test_auth.py"
    assert finding.line == 16
    assert finding.evidence == "assert resp.status_code == 401"

    policy = PatchPolicy(
        rule_severity={PolicyRule.ASSERTION_CHANGED: FindingSeverity.VIOLATION}
    )
    overridden = run(load("deleted_assertion.diff"), policy)
    assert overridden[0].rule == PolicyRule.ASSERTION_CHANGED
    assert overridden[0].severity == FindingSeverity.VIOLATION
    assert overridden[0].evidence == "assert resp.status_code == 401"


def test_injected_nosec():
    findings = run(load("injected_nosec.diff"))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.SUPPRESSION_ADDED
    assert findings[0].path == "src/app/run.py"
    assert findings[0].line == 6
    assert "nosec" in findings[0].evidence


def test_semantic_weaken_with_equal_counts():
    findings = run(load("semantic_weaken.diff"))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.ASSERTION_CHANGED
    assert findings[0].path == "tests/test_auth.py"
    assert findings[0].line == 16
    assert findings[0].evidence == "assert status == 401"


def test_workflow_edit_is_harness_violation():
    findings = run(load("workflow_ci.diff"))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.HARNESS_CHANGED
    assert findings[0].severity == FindingSeverity.VIOLATION
    assert findings[0].path == ".github/workflows/ci.yml"


def test_evasion_variants_are_detected():
    findings = run(load("evasions.diff"))
    expected = {
        (PolicyRule.SUPPRESSION_ADDED, "src/evasion/nosec_tight.py"),
        (PolicyRule.SUPPRESSION_ADDED, "src/evasion/nosec_upper.py"),
        (PolicyRule.SUPPRESSION_ADDED, "src/evasion/noqa_glued.py"),
        (PolicyRule.SUPPRESSION_ADDED, "src/evasion/noqa_spaced.py"),
        (PolicyRule.WEAK_ASSERTION_ADDED, "tests/test_weak_assert.py"),
        (PolicyRule.SUPPRESSION_ADDED, "src/web/handler.ts"),
        (PolicyRule.TEST_SKIP_ADDED, "front/widget.test.js"),
        (PolicyRule.TEST_SKIP_ADDED, "tests/test_skip_mark.py"),
        (PolicyRule.TEST_FILE_DELETED, "tests/test_removed.py"),
        (PolicyRule.TEST_FILE_DELETED, "tests/test_auth.py"),
    }
    got = {(finding.rule, finding.path) for finding in findings}
    assert got == expected
    assert len(findings) == len(expected)
    by_path = {finding.path: finding for finding in findings}
    assert "nosec" in by_path["src/evasion/nosec_tight.py"].evidence
    assert "NOSEC" in by_path["src/evasion/nosec_upper.py"].evidence
    assert "noqa:E501" in by_path["src/evasion/noqa_glued.py"].evidence
    assert "noqa:E501" in by_path["src/evasion/noqa_spaced.py"].evidence
    assert by_path["tests/test_weak_assert.py"].evidence == "assert   True"
    assert "eslint-disable-next-line" in by_path["src/web/handler.ts"].evidence
    assert "it.skip(" in by_path["front/widget.test.js"].evidence
    assert "skipif" in by_path["tests/test_skip_mark.py"].evidence


@pytest.mark.parametrize(
    "name",
    [
        "fp_context_comment.diff",
        "fp_rename_tests.diff",
        "fp_readme_nosec.diff",
        "fp_no_newline.diff",
        "fp_string_literal.diff",
    ],
)
def test_no_false_positives(name: str):
    assert run(load(name)) == []


def test_requirements_dependency_and_allowlist():
    findings = run(load("requirements_requests.diff"))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.DEPENDENCY_CHANGED
    assert findings[0].severity == FindingSeverity.VIOLATION
    assert findings[0].path == "requirements.txt"
    assert findings[0].line == 2
    assert findings[0].evidence == "added requests==2.31.0"

    allowed = PatchPolicy(allowed_dependency_changes=["requests"])
    assert run(load("requirements_requests.diff"), allowed) == []
    capitalized = PatchPolicy(allowed_dependency_changes=["Requests"])
    assert run(load("requirements_requests.diff"), capitalized) == []


def test_package_json_dev_dependency():
    findings = run(load("package_json_devdep.diff"))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.DEPENDENCY_CHANGED
    assert findings[0].severity == FindingSeverity.VIOLATION
    assert findings[0].path == "package.json"
    assert findings[0].evidence.startswith("added")
    assert "left-pad" in findings[0].evidence


def test_path_outside_allowed_globs():
    policy = PatchPolicy(allowed_paths=["src/**"])
    findings = run(load("path_not_allowed.diff"), policy)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.PATH_NOT_ALLOWED
    assert findings[0].severity == FindingSeverity.VIOLATION
    assert findings[0].path == "scripts/x.sh"
    assert run(load("path_not_allowed.diff")) == []

    allowed = _addition("src/app/auth.py", "    token = issue(user)")
    assert run(allowed, policy) == []


def test_literal_return_in_src_not_in_tests():
    findings = run(load("literal_return.diff"))
    assert [(item.rule, item.path, item.line) for item in findings] == [
        (PolicyRule.LITERAL_RETURN_SUSPECT, "src/app/auth.py", 22),
        (PolicyRule.LITERAL_RETURN_SUSPECT, "src/app/gate.py", 6),
    ]
    assert "1234" in findings[0].evidence
    assert "abc" in findings[1].evidence
    assert findings[0].severity == FindingSeverity.REVIEW


def test_findings_are_deterministic_and_ordered():
    policy = PatchPolicy()
    first = run(load("ordering.diff"), policy)
    second = audit_diff(load("ordering.diff"), policy)
    assert first == second
    assert [(item.path, item.line, item.rule, item.severity) for item in first] == [
        (
            ".github/workflows/ci.yml",
            None,
            PolicyRule.HARNESS_CHANGED,
            FindingSeverity.VIOLATION,
        ),
        (
            "src/a_suppress.py",
            2,
            PolicyRule.LITERAL_RETURN_SUSPECT,
            FindingSeverity.REVIEW,
        ),
        (
            "src/a_suppress.py",
            2,
            PolicyRule.SUPPRESSION_ADDED,
            FindingSeverity.REVIEW,
        ),
        (
            "tests/test_z.py",
            9,
            PolicyRule.ASSERTION_CHANGED,
            FindingSeverity.REVIEW,
        ),
    ]


def test_empty_and_malformed_diffs():
    assert run("") == []
    assert run("   \n") == []
    assert run("this is not a diff\n@@ -1 +1 @@\n+hello\n") == []


def test_crlf_diff_still_detects_nosec():
    text = load("injected_nosec.diff").replace("\n", "\r\n")
    findings = run(text)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.SUPPRESSION_ADDED
    assert findings[0].line == 6


@pytest.mark.parametrize(
    ("path", "code"),
    [
        ("tests/test_auth.py", "    assert left == right"),
        ("tests/test_auth.py", "    assert(left == right)"),
        ("tests/test_auth.py", "    self.assertEqual(a, b)"),
        ("tests/test_auth.py", "    with pytest.raises(ValueError):"),
        ("web/app.test.tsx", "    expect(screen.getByText('ok'))"),
        ("web/app.test.js", "    assert.strictEqual(a, b)"),
        ("tests/ExampleTest.java", "    assertThat(x, equalTo(y))"),
    ],
)
def test_removed_assertion_forms(path: str, code: str):
    findings = run(_removal(path, code))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.ASSERTION_CHANGED
    assert findings[0].path == path
    assert findings[0].line == 11
    assert findings[0].evidence == code.strip()


def test_removed_non_assertion_is_clean():
    assert run(_removal("tests/test_auth.py", "    value = 1")) == []


def test_added_real_assertion_is_clean():
    diff = _addition("tests/test_auth.py", "    assert status == 401")
    assert run(diff) == []


def test_deleted_source_file_is_clean():
    diff = """diff --git a/src/app/auth.py b/src/app/auth.py
deleted file mode 100644
--- a/src/app/auth.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def login():
-    return True
"""
    assert run(diff) == []


def test_rename_between_test_paths_keeps_assertion_finding():
    diff = (
        "diff --git a/tests/test_auth.py b/tests/test_login.py\n"
        "similarity index 80%\n"
        "rename from tests/test_auth.py\n"
        "rename to tests/test_login.py\n"
        "--- a/tests/test_auth.py\n"
        "+++ b/tests/test_login.py\n"
        "@@ -2,3 +2,3 @@\n"
        " def test_auth():\n"
        "-    assert status == 401\n"
        "+    assert status == 200\n"
        " keep\n"
    )
    findings = run(diff)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.ASSERTION_CHANGED
    assert findings[0].path == "tests/test_auth.py"
    assert findings[0].line == 3
    assert findings[0].evidence == "assert status == 401"


@pytest.mark.parametrize(
    "code",
    [
        "    assert   True",
        "    assert 1",
        "    assert not False",
        "    assert x == x",
        "    assert 1 == 1",
        "    self.assertTrue(True)",
        "expect(true).toBe(true)",
        "expect(1).toBe(1);",
    ],
)
def test_weak_assertion_forms(code: str):
    path = "web/app.test.ts" if code.startswith("expect") else "tests/test_auth.py"
    findings = run(_addition(path, code))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.WEAK_ASSERTION_ADDED
    assert findings[0].evidence == code.strip()


def test_unequal_assertion_is_not_weak():
    assert run(_addition("tests/test_auth.py", "    assert 1 == 2")) == []
    assert run(_addition("tests/test_auth.py", "    assert x == y")) == []


@pytest.mark.parametrize(
    "code",
    [
        "@pytest.mark.xfail",
        'pytest.skip("nope")',
        '@unittest.skip("x")',
        '@unittest.skipIf(True, "x")',
        'describe.skip("suite", () => {});',
        'test.only("one", () => {});',
        'xit("hidden", () => {});',
        'it.only("focus", () => {});',
        "describe.only('x', () => {});",
        "test.skip('x', () => {});",
        "xdescribe('hidden', () => {});",
    ],
)
def test_skip_markers(code: str):
    findings = run(_addition("tests/test_marks.py", code))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.TEST_SKIP_ADDED


@pytest.mark.parametrize(
    ("path", "code"),
    [
        ("src/app/a.py", "call()  # nosec B602"),
        ("src/app/a.py", "call()  # noqa"),
        ("src/app/a.py", "call()  # nosemgrep"),
        ("src/app/a.py", "call()  # pragma: no cover"),
        ("src/app/a.py", "call()  # pylint: disable=all"),
        ("src/app/a.py", "call()  # codeql[py/sql]"),
        ("src/app/a.py", "call()  # lgtm[py/path]"),
        ("src/web/a.ts", "// eslint-disable-next-line no-eval"),
        ("src/web/a.ts", "/* eslint-disable no-console */"),
        ("src/web/a.ts", "// @ts-ignore"),
        ("src/web/a.ts", "// @ts-nocheck"),
        ("src/web/a.ts", "// @ts-expect-error reason"),
        ("src/web/a.ts", "// codeql[js/xss]"),
        ("src/lib/a.go", "// NOLINT"),
        ("src/App.java", '@SuppressWarnings("unchecked")'),
    ],
)
def test_suppression_forms(path: str, code: str):
    findings = run(_addition(path, code))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.SUPPRESSION_ADDED
    assert findings[0].path == path


def test_string_and_private_field_are_not_suppressions():
    url = _addition("src/app/a.py", 'url = "http://nosec.example/a"')
    field = _addition("src/web/field.ts", "this.#nosec = 1;")
    assert run(url) == []
    assert run(field) == []


def test_nosec_after_a_string_is_detected():
    diff = _addition("src/app/a.py", 'message = "ok"  # nosec')
    findings = run(diff)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.SUPPRESSION_ADDED


def test_suppress_annotation_inside_string_is_ignored():
    diff = _addition("src/App.java", 'log("@SuppressWarnings")')
    assert run(diff) == []


def test_type_ignore_respects_policy_flag():
    diff = _addition("src/app/typed.py", "x = 1  # type: ignore[arg-type]")
    assert run(diff) == []
    policy = PatchPolicy(type_ignore_is_suppression=True)
    findings = run(diff, policy)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.SUPPRESSION_ADDED
    quoted = _addition("src/app/typed.py", 'note = "# type: ignore"')
    assert run(quoted, policy) == []


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "docs/guide.rst",
        "notes.txt",
    ],
)
def test_docs_do_not_report_suppression(path: str):
    assert run(_addition(path, "call()  # nosec")) == []


@pytest.mark.parametrize(
    "path",
    [
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        ".coveragerc",
        "jest.config.js",
        "vitest.config.ts",
        "karma.conf.js",
        ".semgrepignore",
        ".eslintignore",
        ".eslintrc.js",
        ".eslintrc",
        ".bandit",
        "codecov.yml",
        ".github/workflows/build.yml",
        "pkg/pytest.ini",
    ],
)
def test_harness_files(path: str):
    diff = _hunk(path, [" keep", "+changed = 1"], "@@ -1,1 +1,2 @@")
    findings = run(diff)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.HARNESS_CHANGED
    assert findings[0].severity == FindingSeverity.VIOLATION
    assert findings[0].path == path


def test_harness_mode_only_change():
    diff = """diff --git a/pytest.ini b/pytest.ini
old mode 100644
new mode 100755
"""
    findings = run(diff)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.HARNESS_CHANGED
    assert findings[0].path == "pytest.ini"


def test_root_conftest_is_harness_nested_is_not():
    root = _hunk("conftest.py", [" import pytest", "+x = 1"], "@@ -1,1 +1,2 @@")
    nested = _hunk(
        "tests/conftest.py",
        [" import pytest", "+x = 1"],
        "@@ -1,1 +1,2 @@",
    )
    package = _hunk(
        "pkg/conftest.py",
        [" import pytest", "+x = 1"],
        "@@ -1,1 +1,2 @@",
    )
    root_findings = run(root)
    assert [item.rule for item in root_findings] == [PolicyRule.HARNESS_CHANGED]
    assert run(nested) == []
    assert run(package) == []


def test_nested_conftest_assertion_is_not_harness():
    diff = _hunk(
        "tests/conftest.py",
        [" def test_plugin():", "-    assert ready", "     return"],
        "@@ -1,3 +1,2 @@",
    )
    findings = run(diff)
    assert [item.rule for item in findings] == [PolicyRule.ASSERTION_CHANGED]


def test_pyproject_ruff_section_is_harness():
    diff = _hunk(
        "pyproject.toml",
        [" [tool.ruff]", " line-length = 100", '+target-version = "py310"'],
        "@@ -12,2 +12,3 @@",
    )
    findings = run(diff)
    assert [item.rule for item in findings] == [PolicyRule.HARNESS_CHANGED]


def test_pyproject_unknown_section_is_clean():
    diff = _hunk(
        "pyproject.toml",
        [" timeout = 30", "+retries = 5", " workers = 2"],
        "@@ -40,2 +40,3 @@",
    )
    assert run(diff) == []


def test_pyproject_project_metadata_is_not_harness():
    diff = _hunk(
        "pyproject.toml",
        [" [project]", '-name = "old"', '+name = "new"'],
        "@@ -1,2 +1,2 @@",
    )
    assert run(diff) == []


def test_pyproject_dependency_array_without_visible_section():
    diff = _hunk(
        "pyproject.toml",
        [
            " dependencies = [",
            '   "flask==2.0.0",',
            '+  "requests==2.31.0",',
            " ]",
        ],
        "@@ -4,3 +4,4 @@",
    )
    findings = run(diff)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.DEPENDENCY_CHANGED
    assert "requests==2.31.0" in findings[0].evidence


def test_pyproject_optional_and_poetry_dependencies():
    optional = _hunk(
        "pyproject.toml",
        [
            " [project.optional-dependencies]",
            " dev = [",
            '+  "pytest>=7",',
            " ]",
        ],
        "@@ -8,2 +8,3 @@",
    )
    poetry = _hunk(
        "pyproject.toml",
        [
            " [tool.poetry.dependencies]",
            ' python = "^3.10"',
            '+requests = "^2.0"',
        ],
        "@@ -3,2 +3,3 @@",
    )
    optional_findings = run(optional)
    assert len(optional_findings) == 1
    assert optional_findings[0].rule == PolicyRule.DEPENDENCY_CHANGED
    assert "pytest>=7" in optional_findings[0].evidence
    poetry_findings = run(poetry)
    assert len(poetry_findings) == 1
    assert "requests" in poetry_findings[0].evidence
    python_only = _hunk(
        "pyproject.toml",
        [" [tool.poetry.dependencies]", '+python = "^3.11"'],
        "@@ -1,1 +1,2 @@",
    )
    assert run(python_only) == []


def test_pyproject_harness_and_dependency_together():
    diff = _hunk(
        "pyproject.toml",
        [
            " [project]",
            " dependencies = [",
            '+  "requests==2.0",',
            " ]",
            "+[tool.pytest.ini_options]",
            '+addopts = "-q"',
        ],
        "@@ -1,3 +1,6 @@",
    )
    findings = run(diff)
    assert [item.rule for item in findings] == [
        PolicyRule.HARNESS_CHANGED,
        PolicyRule.DEPENDENCY_CHANGED,
    ]


def test_package_name_normalization_and_extras():
    foo = _addition("requirements.txt", "foo_bar==1")
    assert run(foo, PatchPolicy(allowed_dependency_changes=["Foo_Bar"])) == []
    plain = run(foo)
    assert len(plain) == 1
    assert plain[0].evidence == "added foo_bar==1"
    extras = _addition("requirements.txt", "requests[security]==2.0")
    assert run(extras, PatchPolicy(allowed_dependency_changes=["requests"])) == []


def test_removed_requirement_and_repin():
    removed = _hunk(
        "requirements.txt",
        [" flask==1", "-requests==1.0", " pydantic==1"],
        "@@ -1,3 +1,2 @@",
    )
    removed_findings = run(removed)
    assert len(removed_findings) == 1
    assert removed_findings[0].evidence == "removed requests==1.0"
    repin = _hunk(
        "requirements.txt",
        ["-requests==1.0", "+requests==2.0"],
        "@@ -1,1 +1,1 @@",
    )
    repin_findings = run(repin)
    assert len(repin_findings) == 1
    assert repin_findings[0].evidence == "added requests==2.0"
    assert run(repin, PatchPolicy(allowed_dependency_changes=["requests"])) == []


def test_pipfile_gomod_and_cargo():
    pipfile = _hunk(
        "Pipfile",
        [" [packages]", '+requests = "==2.31.0"'],
        "@@ -1,1 +1,2 @@",
    )
    gomod = _hunk(
        "go.mod",
        [" require (", "+    github.com/gin-gonic/gin v1.9.0", " )"],
        "@@ -2,1 +2,2 @@",
    )
    cargo = _hunk(
        "Cargo.toml",
        [" [dependencies]", '+serde = "1.0"'],
        "@@ -4,1 +4,2 @@",
    )
    pip_findings = run(pipfile)
    assert len(pip_findings) == 1
    assert pip_findings[0].rule == PolicyRule.DEPENDENCY_CHANGED
    assert "requests" in pip_findings[0].evidence
    go_findings = run(gomod)
    assert len(go_findings) == 1
    assert "github.com/gin-gonic/gin" in go_findings[0].evidence
    cargo_findings = run(cargo)
    assert len(cargo_findings) == 1
    assert "serde" in cargo_findings[0].evidence


def test_constraints_file():
    diff = _addition("constraints.txt", "flask==2.0")
    findings = run(diff)
    assert len(findings) == 1
    assert findings[0].path == "constraints.txt"
    assert findings[0].evidence == "added flask==2.0"


def test_lockfile_reporting():
    lock = """diff --git a/package-lock.json b/package-lock.json
index 1111111..2222222 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -10,3 +10,6 @@
     "node_modules/vitest": {
       "version": "1.0.0"
     },
+    "node_modules/left-pad": {
+      "version": "1.3.0"
+    }
"""
    findings = run(lock)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.DEPENDENCY_CHANGED
    assert findings[0].path == "package-lock.json"
    assert findings[0].evidence == "lockfile changed"
    assert run(lock, PatchPolicy(allowed_dependency_changes=["left-pad"])) == []
    unrelated = PatchPolicy(allowed_dependency_changes=["requests"])
    assert len(run(lock, unrelated)) == 1

    summed = """diff --git a/go.sum b/go.sum
index 1111111..2222222 100644
--- a/go.sum
+++ b/go.sum
@@ -1,2 +1,4 @@
 example.com/a v1.0.0 h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
 example.com/a v1.0.0/go.mod h1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
+example.com/b v1.2.3 h1:ccccccccccccccccccccccccccccccccccccccccccc=
+example.com/b v1.2.3/go.mod h1:ddddddddddddddddddddddddddddddddddddddddddd=
"""
    summed_findings = run(summed)
    assert len(summed_findings) == 1
    assert summed_findings[0].path == "go.sum"
    assert run(summed, PatchPolicy(allowed_dependency_changes=["example.com/b"])) == []

    yarn = _hunk(
        "yarn.lock",
        [" left-pad@^1.0.0:", '+  version "1.3.0"'],
        "@@ -1,1 +1,2 @@",
    )
    assert len(run(yarn, PatchPolicy(allowed_dependency_changes=["left-pad"]))) == 1

    named = _hunk("poetry.lock", ['+name = "requests"'], "@@ -0,0 +1,1 @@")
    assert run(named, PatchPolicy(allowed_dependency_changes=["requests"])) == []
    assert len(run(named)) == 1


def test_allowlisted_manifest_suppresses_lockfile():
    manifest = load("requirements_requests.diff")
    lock = """diff --git a/package-lock.json b/package-lock.json
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,1 +1,2 @@
 {}
+    "node_modules/left-pad": {
"""
    combined = manifest + lock
    assert run(combined, PatchPolicy(allowed_dependency_changes=["requests"])) == []
    both = run(combined)
    paths = {item.path for item in both}
    assert paths == {"requirements.txt", "package-lock.json"}


def test_disallowed_manifest_still_reports_lockfile():
    diff = """diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 flask==1
+evilpkg==1
 pydantic==1
diff --git a/package-lock.json b/package-lock.json
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,1 +1,2 @@
 {}
+    "node_modules/left-pad": {
"""
    findings = run(diff)
    got = {(item.rule, item.path) for item in findings}
    assert (PolicyRule.DEPENDENCY_CHANGED, "requirements.txt") in got
    assert (PolicyRule.DEPENDENCY_CHANGED, "package-lock.json") in got


def test_js_literal_return_and_non_matches():
    hit = _addition("src/web/gate.ts", "if (userId === 'abc') return 42;")
    findings = run(hit)
    assert [item.rule for item in findings] == [PolicyRule.LITERAL_RETURN_SUSPECT]
    assert findings[0].path == "src/web/gate.ts"
    assert run(_addition("src/web/gate.ts", "if (userId === name) return 42;")) == []
    assert run(_addition("src/app/auth.py", "    if user_id == 1234: return name")) == []
    two = _hunk(
        "src/app/gate.py",
        [
            " def allow(token):",
            '+    if token == "abc":',
            "+        return name",
        ],
        "@@ -1,1 +1,3 @@",
    )
    assert run(two) == []
    in_test = _addition("web/app.test.ts", "if (userId === 'abc') return 42;")
    assert run(in_test) == []


def test_binary_outside_allowed_paths():
    diff = """diff --git a/assets/logo.bin b/assets/logo.bin
index 1111111..2222222 100644
Binary files a/assets/logo.bin and b/assets/logo.bin differ
"""
    findings = run(diff, PatchPolicy(allowed_paths=["src/**"]))
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.PATH_NOT_ALLOWED
    assert findings[0].path == "assets/logo.bin"
    assert run(diff) == []


def test_new_test_file_with_real_assertion_is_clean():
    diff = """diff --git a/tests/test_new.py b/tests/test_new.py
new file mode 100644
--- /dev/null
+++ b/tests/test_new.py
@@ -0,0 +1,3 @@
+def test_new():
+    resp = client.get("/login")
+    assert resp.status_code == 401
"""
    assert run(diff) == []


def test_new_test_file_with_weak_assertion():
    diff = """diff --git a/tests/test_new.py b/tests/test_new.py
new file mode 100644
--- /dev/null
+++ b/tests/test_new.py
@@ -0,0 +1,2 @@
+def test_new():
+    assert True
"""
    findings = run(diff)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.WEAK_ASSERTION_ADDED


def test_pyproject_dependency_without_visible_header_is_flagged():
    diff = """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -20,6 +20,7 @@
     "httpx>=0.27",
     "pydantic>=2.0",
     "litellm>=1.40",
+    "requests==2.31.0",
     "fastapi>=0.110",
     "uvicorn>=0.23",
 ]
"""
    findings = run(diff)
    assert len(findings) == 1
    assert findings[0].rule == PolicyRule.DEPENDENCY_CHANGED
    assert findings[0].severity == FindingSeverity.VIOLATION
    assert "requests==2.31.0" in findings[0].evidence


def test_package_json_dependency_without_visible_section_is_flagged():
    diff = """diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -40,6 +40,7 @@
     "react": "^18.2.0",
     "react-dom": "^18.2.0",
+    "left-pad": "^1.3.0",
     "zod": "^3.22.0"
   }
 }
"""
    findings = run(diff)
    assert [f.rule for f in findings] == [PolicyRule.DEPENDENCY_CHANGED]
    assert findings[0].severity == FindingSeverity.VIOLATION


def test_pyproject_version_bump_without_header_is_not_flagged():
    diff = """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -5,3 +5,3 @@
 name = "pkg"
-version = "0.6.0"
+version = "0.6.1"
 description = "x"
"""
    assert run(diff) == []


def test_unclassified_manifest_change_respects_allowlist():
    diff = """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -20,3 +20,4 @@
     "httpx>=0.27",
+    "requests==2.31.0",
     "fastapi>=0.110",
 ]
"""
    assert run(diff, PatchPolicy(allowed_dependency_changes=["requests"])) == []
