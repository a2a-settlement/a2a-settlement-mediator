"""Parser tests for git unified diffs."""

from __future__ import annotations

from a2a_settlement_mediator.unified_diff import parse_unified_diff


def _rows(lines):
    return [(line.kind, line.text, line.old_lineno, line.new_lineno) for line in lines]


def test_empty_input():
    assert parse_unified_diff("") == []
    assert parse_unified_diff("   \n\n\t") == []
    assert parse_unified_diff("\n") == []


def test_added_file_strips_prefixes_and_numbers_lines():
    diff = """diff --git a/src/new.py b/src/new.py
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/src/new.py
@@ -0,0 +1,3 @@
+one
+two
+three
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    added = files[0]
    assert added.status == "added"
    assert added.old_path is None
    assert added.new_path == "src/new.py"
    assert added.hunks[0].old_start == 0
    assert added.hunks[0].new_start == 1
    assert _rows(added.hunks[0].lines) == [
        ("+", "one", None, 1),
        ("+", "two", None, 2),
        ("+", "three", None, 3),
    ]


def test_deleted_file():
    diff = """diff --git a/src/old.py b/src/old.py
deleted file mode 100644
index abc1234..0000000
--- a/src/old.py
+++ /dev/null
@@ -1,2 +0,0 @@
-one
-two
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    deleted = files[0]
    assert deleted.status == "deleted"
    assert deleted.old_path == "src/old.py"
    assert deleted.new_path is None
    assert _rows(deleted.hunks[0].lines) == [
        ("-", "one", 1, None),
        ("-", "two", 2, None),
    ]


def test_modified_hunk_line_numbers():
    diff = """diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,4 +10,4 @@ def value():
 context
-removed
+added
 tail
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    modified = files[0]
    assert modified.status == "modified"
    assert modified.old_path == "src/app.py"
    assert modified.new_path == "src/app.py"
    assert _rows(modified.hunks[0].lines) == [
        (" ", "context", 10, 10),
        ("-", "removed", 11, None),
        ("+", "added", None, 11),
        (" ", "tail", 12, 12),
    ]


def test_rename_with_hunk():
    diff = """diff --git a/src/old_name.py b/src/new_name.py
similarity index 90%
rename from src/old_name.py
rename to src/new_name.py
index 1111111..2222222 100644
--- a/src/old_name.py
+++ b/src/new_name.py
@@ -1,3 +1,3 @@
 def value():
-    return 1
+    return 2
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    renamed = files[0]
    assert renamed.status == "renamed"
    assert renamed.old_path == "src/old_name.py"
    assert renamed.new_path == "src/new_name.py"
    kinds = [line.kind for line in renamed.hunks[0].lines]
    assert kinds == [" ", "-", "+"]


def test_rename_identical_has_no_hunks():
    diff = """diff --git a/tests/test_auth.py b/tests/test_login.py
similarity index 100%
rename from tests/test_auth.py
rename to tests/test_login.py
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    renamed = files[0]
    assert renamed.status == "renamed"
    assert renamed.old_path == "tests/test_auth.py"
    assert renamed.new_path == "tests/test_login.py"
    assert renamed.hunks == []


def test_binary_files():
    diff = """diff --git a/assets/logo.bin b/assets/logo.bin
index 1111111..2222222 100644
Binary files a/assets/logo.bin and b/assets/logo.bin differ
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    binary = files[0]
    assert binary.status == "binary"
    assert binary.old_path == "assets/logo.bin"
    assert binary.new_path == "assets/logo.bin"
    assert binary.hunks == []


def test_git_binary_patch_does_not_swallow_next_file():
    diff = """diff --git a/assets/logo.bin b/assets/logo.bin
index 1111111..2222222 100644
GIT binary patch
literal 8
zc${000000

diff --git a/src/app.py b/src/app.py
index 3333333..4444444 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1 +1 @@
-a
+b
"""
    files = parse_unified_diff(diff)
    assert [item.status for item in files] == ["binary", "modified"]
    assert files[0].new_path == "assets/logo.bin"
    assert files[0].hunks == []
    assert files[1].new_path == "src/app.py"
    assert [line.text for line in files[1].hunks[0].lines] == ["a", "b"]


def test_crlf_line_endings():
    diff = "\r\n".join(
        [
            "diff --git a/src/new.py b/src/new.py",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/src/new.py",
            "@@ -0,0 +1,2 @@",
            "+alpha",
            "+beta",
            "",
        ]
    )
    files = parse_unified_diff(diff)
    assert len(files) == 1
    assert files[0].status == "added"
    assert files[0].new_path == "src/new.py"
    assert [line.text for line in files[0].hunks[0].lines] == ["alpha", "beta"]


def test_no_newline_marker_is_ignored():
    diff = """diff --git a/src/eof.py b/src/eof.py
index 1111111..2222222 100644
--- a/src/eof.py
+++ b/src/eof.py
@@ -1 +1 @@
-old
+new
\\ No newline at end of file
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    lines = files[0].hunks[0].lines
    assert [(line.kind, line.text) for line in lines] == [("-", "old"), ("+", "new")]
    assert all("newline" not in line.text for line in lines)


def test_directory_named_a_keeps_inner_prefix():
    diff = """diff --git a/a/foo.py b/a/foo.py
index 1111111..2222222 100644
--- a/a/foo.py
+++ b/a/foo.py
@@ -1 +1 @@
-a
+b
"""
    files = parse_unified_diff(diff)
    assert files[0].old_path == "a/foo.py"
    assert files[0].new_path == "a/foo.py"
    assert files[0].status == "modified"


def test_quoted_paths_with_spaces():
    diff = """diff --git "a/foo bar.py" "b/foo bar.py"
index 1111111..2222222 100644
--- "a/foo bar.py"
+++ "b/foo bar.py"
@@ -1 +1 @@
-a
+b
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    assert files[0].old_path == "foo bar.py"
    assert files[0].new_path == "foo bar.py"
    assert files[0].hunks[0].lines[1].text == "b"


def test_malformed_input_does_not_raise_and_keeps_later_file():
    garbage = parse_unified_diff("this is not a diff\n@@ -1 +1 @@\n+hello\n")
    assert garbage == []
    assert parse_unified_diff("diff --git\n") == []
    assert parse_unified_diff("@@ not a hunk\n+orphan\n") == []

    valid = """diff --git a/ok.py b/ok.py
--- a/ok.py
+++ b/ok.py
@@ -1 +1 @@
-a
+b
"""
    files = parse_unified_diff("noise before\n" + valid + "@@ garbage\n")
    assert len(files) == 1
    assert files[0].new_path == "ok.py"
    assert [line.text for line in files[0].hunks[0].lines] == ["a", "b"]


def test_multiple_files_preserve_order():
    diff = """diff --git a/src/a.py b/src/a.py
--- a/src/a.py
+++ b/src/a.py
@@ -1 +1 @@
-a
+b
diff --git a/src/b.py b/src/b.py
--- a/src/b.py
+++ b/src/b.py
@@ -1 +1 @@
-c
+d
"""
    files = parse_unified_diff(diff)
    assert [item.new_path for item in files] == ["src/a.py", "src/b.py"]
