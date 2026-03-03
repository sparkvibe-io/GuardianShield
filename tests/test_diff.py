"""Tests for unified diff parsing and scanning."""

import os

from guardianshield.core import GuardianShield
from guardianshield.diff import DiffHunk, parse_unified_diff, scan_diff
from guardianshield.findings import FindingType

# -- Sample diffs -------------------------------------------------------------

SAMPLE_DIFF = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,5 @@
 import os
+import subprocess

 def run():
+    subprocess.call(user_input, shell=True)
"""

MULTI_FILE_DIFF = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 import os
+import subprocess

 def run():
diff --git a/db.py b/db.py
--- a/db.py
+++ b/db.py
@@ -1,2 +1,3 @@
 import sqlite3
+cursor.execute("SELECT * FROM users WHERE id=" + user_id)

"""

REMOVAL_ONLY_DIFF = """\
diff --git a/old.py b/old.py
--- a/old.py
+++ b/old.py
@@ -1,4 +1,2 @@
 import os
-import subprocess
-subprocess.call("rm -rf /", shell=True)
 print("done")
"""

MIXED_DIFF = """\
diff --git a/handler.py b/handler.py
--- a/handler.py
+++ b/handler.py
@@ -1,5 +1,6 @@
 import os
-import sys
+import subprocess

 def handle():
-    sys.exit(1)
+    subprocess.call(cmd, shell=True)
+    print("handled")
"""

MULTI_HUNK_DIFF = """\
diff --git a/server.py b/server.py
--- a/server.py
+++ b/server.py
@@ -1,3 +1,4 @@
 import os
+import subprocess

 def start():
@@ -10,3 +11,4 @@

 def stop():
+    subprocess.call(cmd, shell=True)
     pass
"""

JS_DIFF = """\
diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -1,2 +1,3 @@
 const express = require('express');
+const result = eval(userInput);
 module.exports = {};
"""

CONTEXT_ONLY_DIFF = """\
diff --git a/utils.py b/utils.py
--- a/utils.py
+++ b/utils.py
@@ -1,3 +1,3 @@
 import os
 print("hello")
 print("world")
"""

BINARY_DIFF = """\
diff --git a/image.png b/image.png
Binary files a/image.png and b/image.png differ
"""

RENAME_DIFF = """\
diff --git a/old_name.py b/new_name.py
--- a/old_name.py
+++ b/new_name.py
@@ -1,2 +1,3 @@
 import os
+import subprocess
 print("hello")
"""

NO_VULN_DIFF = """\
diff --git a/safe.py b/safe.py
--- a/safe.py
+++ b/safe.py
@@ -1,2 +1,3 @@
 import os
+x = 42
 print("hello")
"""


# -- TestParseUnifiedDiff ------------------------------------------------------


class TestParseUnifiedDiff:
    def test_single_file_added_lines(self):
        hunks = parse_unified_diff(SAMPLE_DIFF)
        assert len(hunks) == 1
        hunk = hunks[0]
        assert hunk.file_path == "app.py"
        assert len(hunk.added_lines) == 2

    def test_added_line_content(self):
        hunks = parse_unified_diff(SAMPLE_DIFF)
        hunk = hunks[0]
        # Line 2: "import subprocess"
        assert 2 in hunk.added_lines
        assert hunk.added_lines[2] == "import subprocess"

    def test_added_line_numbers(self):
        hunks = parse_unified_diff(SAMPLE_DIFF)
        hunk = hunks[0]
        # Line 2: import subprocess, Line 5: subprocess.call(...)
        assert sorted(hunk.added_lines.keys()) == [2, 5]

    def test_multiple_files(self):
        hunks = parse_unified_diff(MULTI_FILE_DIFF)
        assert len(hunks) == 2
        assert hunks[0].file_path == "app.py"
        assert hunks[1].file_path == "db.py"

    def test_multiple_files_separate_added_lines(self):
        hunks = parse_unified_diff(MULTI_FILE_DIFF)
        assert len(hunks[0].added_lines) == 1
        assert len(hunks[1].added_lines) == 1

    def test_empty_diff(self):
        assert parse_unified_diff("") == []

    def test_none_diff(self):
        assert parse_unified_diff(None) == []

    def test_whitespace_only_diff(self):
        assert parse_unified_diff("   \n  \n") == []

    def test_removal_only_no_added_lines(self):
        hunks = parse_unified_diff(REMOVAL_ONLY_DIFF)
        assert len(hunks) == 1
        assert len(hunks[0].added_lines) == 0

    def test_mixed_add_remove(self):
        hunks = parse_unified_diff(MIXED_DIFF)
        assert len(hunks) == 1
        hunk = hunks[0]
        # Added: import subprocess (line 2), subprocess.call (line 5), print (line 6)
        assert len(hunk.added_lines) == 3

    def test_mixed_line_numbers(self):
        hunks = parse_unified_diff(MIXED_DIFF)
        hunk = hunks[0]
        added_nums = sorted(hunk.added_lines.keys())
        assert added_nums == [2, 5, 6]

    def test_mixed_content(self):
        hunks = parse_unified_diff(MIXED_DIFF)
        hunk = hunks[0]
        assert hunk.added_lines[2] == "import subprocess"
        assert "subprocess.call" in hunk.added_lines[5]
        assert hunk.added_lines[6] == '    print("handled")'

    def test_multi_hunk_same_file(self):
        hunks = parse_unified_diff(MULTI_HUNK_DIFF)
        assert len(hunks) == 1
        hunk = hunks[0]
        # Two hunks: line 2 in first, line 13 in second
        assert 2 in hunk.added_lines
        assert 13 in hunk.added_lines

    def test_multi_hunk_line_numbers(self):
        hunks = parse_unified_diff(MULTI_HUNK_DIFF)
        hunk = hunks[0]
        assert sorted(hunk.added_lines.keys()) == [2, 13]

    def test_binary_diff_skipped(self):
        hunks = parse_unified_diff(BINARY_DIFF)
        # Binary diffs have no +++ b/ header, so no hunks created
        assert len(hunks) == 0

    def test_context_only_no_added_lines(self):
        hunks = parse_unified_diff(CONTEXT_ONLY_DIFF)
        assert len(hunks) == 1
        assert len(hunks[0].added_lines) == 0

    def test_language_python(self):
        hunks = parse_unified_diff(SAMPLE_DIFF)
        assert hunks[0].language == "python"

    def test_language_javascript(self):
        hunks = parse_unified_diff(JS_DIFF)
        assert hunks[0].language == "javascript"

    def test_rename_uses_new_path(self):
        hunks = parse_unified_diff(RENAME_DIFF)
        assert len(hunks) == 1
        assert hunks[0].file_path == "new_name.py"

    def test_malformed_no_header(self):
        malformed = "@@ -1,2 +1,3 @@\n+some line\n"
        hunks = parse_unified_diff(malformed)
        # No +++ header means no hunk created
        assert len(hunks) == 0


# -- TestDiffHunk --------------------------------------------------------------


class TestDiffHunk:
    def test_default_creation(self):
        hunk = DiffHunk()
        assert hunk.file_path == ""
        assert hunk.added_lines == {}
        assert hunk.language is None

    def test_creation_with_values(self):
        hunk = DiffHunk(
            file_path="app.py",
            added_lines={1: "import os", 3: "x = 1"},
            language="python",
        )
        assert hunk.file_path == "app.py"
        assert hunk.added_lines == {1: "import os", 3: "x = 1"}
        assert hunk.language == "python"

    def test_added_lines_mapping(self):
        hunk = DiffHunk(added_lines={10: "foo", 15: "bar", 20: "baz"})
        assert len(hunk.added_lines) == 3
        assert hunk.added_lines[10] == "foo"
        assert hunk.added_lines[15] == "bar"
        assert hunk.added_lines[20] == "baz"

    def test_language_py_extension(self):
        hunks = parse_unified_diff(SAMPLE_DIFF)
        assert hunks[0].language == "python"

    def test_language_js_extension(self):
        hunks = parse_unified_diff(JS_DIFF)
        assert hunks[0].language == "javascript"

    def test_language_unknown_extension(self):
        diff = """\
diff --git a/data.xyz b/data.xyz
--- a/data.xyz
+++ b/data.xyz
@@ -1,1 +1,2 @@
 existing
+new line
"""
        hunks = parse_unified_diff(diff)
        assert len(hunks) == 1
        assert hunks[0].language is None


# -- TestScanDiff --------------------------------------------------------------


class TestScanDiff:
    def _make_shield(self, tmp_path):
        audit_db = os.path.join(str(tmp_path), "audit.db")
        return GuardianShield(audit_path=audit_db)

    def test_findings_on_added_lines(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, SAMPLE_DIFF)
        # subprocess.call with shell=True should be detected
        assert len(findings) > 0

    def test_finding_type_command_injection(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, SAMPLE_DIFF)
        types = [f.finding_type for f in findings]
        assert FindingType.COMMAND_INJECTION in types or FindingType.INSECURE_FUNCTION in types

    def test_correct_line_number(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, SAMPLE_DIFF)
        # The subprocess.call line should map to line 5 in the new file
        vuln_findings = [
            f
            for f in findings
            if f.finding_type
            in (FindingType.COMMAND_INJECTION, FindingType.INSECURE_FUNCTION)
        ]
        if vuln_findings:
            assert vuln_findings[0].line_number == 5

    def test_correct_file_path(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, SAMPLE_DIFF)
        for f in findings:
            assert f.file_path == "app.py"

    def test_multi_file_findings(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, MULTI_FILE_DIFF)
        file_paths = {f.file_path for f in findings}
        # db.py should have a SQL injection finding
        assert "db.py" in file_paths

    def test_no_vulnerabilities(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, NO_VULN_DIFF)
        assert findings == []

    def test_empty_diff(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, "")
        assert findings == []

    def test_none_diff(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, None)
        assert findings == []

    def test_removal_only_no_findings(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, REMOVAL_ONLY_DIFF)
        # No added lines means nothing to scan
        assert findings == []

    def test_js_diff_findings(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, JS_DIFF)
        # eval(userInput) should be detected
        assert len(findings) > 0
        assert findings[0].file_path == "app.js"

    def test_context_only_no_findings(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, CONTEXT_ONLY_DIFF)
        assert findings == []

    def test_mixed_diff_findings(self, tmp_path):
        shield = self._make_shield(tmp_path)
        findings = scan_diff(shield, MIXED_DIFF)
        # subprocess.call in added line should be detected
        assert len(findings) > 0
        for f in findings:
            assert f.file_path == "handler.py"


# -- TestEdgeCases -------------------------------------------------------------


class TestEdgeCases:
    def test_empty_string(self):
        assert parse_unified_diff("") == []

    def test_none_input(self):
        assert parse_unified_diff(None) == []

    def test_whitespace_only(self):
        assert parse_unified_diff("   \n\t\n  ") == []

    def test_malformed_no_plus_header(self):
        diff = "@@ -1,2 +1,3 @@\n+added line\n context\n"
        hunks = parse_unified_diff(diff)
        assert len(hunks) == 0

    def test_only_context_lines(self):
        diff = """\
diff --git a/f.py b/f.py
--- a/f.py
+++ b/f.py
@@ -1,3 +1,3 @@
 line1
 line2
 line3
"""
        hunks = parse_unified_diff(diff)
        assert len(hunks) == 1
        assert hunks[0].added_lines == {}

    def test_file_rename_detection(self):
        hunks = parse_unified_diff(RENAME_DIFF)
        assert len(hunks) == 1
        # +++ b/new_name.py is what we capture
        assert hunks[0].file_path == "new_name.py"
        assert hunks[0].language == "python"

    def test_diff_with_no_newline_at_end(self):
        diff = """\
diff --git a/f.py b/f.py
--- a/f.py
+++ b/f.py
@@ -1,2 +1,3 @@
 import os
+x = 1
 print("done")
\\ No newline at end of file"""
        hunks = parse_unified_diff(diff)
        assert len(hunks) == 1
        assert 2 in hunks[0].added_lines
        assert hunks[0].added_lines[2] == "x = 1"

    def test_large_line_numbers(self):
        diff = """\
diff --git a/big.py b/big.py
--- a/big.py
+++ b/big.py
@@ -999,2 +1000,3 @@
 existing_line
+new_line_at_1001
 another_existing
"""
        hunks = parse_unified_diff(diff)
        assert len(hunks) == 1
        assert 1001 in hunks[0].added_lines
        assert hunks[0].added_lines[1001] == "new_line_at_1001"

    def test_multiple_additions_consecutive(self):
        diff = """\
diff --git a/f.py b/f.py
--- a/f.py
+++ b/f.py
@@ -1,1 +1,4 @@
 existing
+line_a
+line_b
+line_c
"""
        hunks = parse_unified_diff(diff)
        hunk = hunks[0]
        assert sorted(hunk.added_lines.keys()) == [2, 3, 4]
        assert hunk.added_lines[2] == "line_a"
        assert hunk.added_lines[3] == "line_b"
        assert hunk.added_lines[4] == "line_c"
