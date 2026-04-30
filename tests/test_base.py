# security-guard: ignore-file
"""Tests for ``scanners.base`` — skip helpers, ignore marker, file iteration."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.base import (
    Severity,
    IGNORE_FILE_MARKER,
    has_ignore_marker,
    should_skip_dir,
    should_skip_file,
    iter_source_files,
)


class TestSeverity(unittest.TestCase):
    def test_score_ordering(self):
        # Severity scores must rank CRITICAL > HIGH > MEDIUM > LOW > INFO.
        scores = [s.score for s in (
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
            Severity.LOW, Severity.INFO,
        )]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestSkipHelpers(unittest.TestCase):
    def test_skip_common_noise_dirs(self):
        for d in ("node_modules", ".git", "__pycache__", "venv", "dist"):
            self.assertTrue(should_skip_dir(d), f"{d} should be skipped")

    def test_keeps_normal_dirs(self):
        for d in ("src", "lib", "app", "scanners"):
            self.assertFalse(should_skip_dir(d))

    def test_skip_minified_and_lockfiles(self):
        for f in ("app.min.js", "vendor.bundle.js", "package-lock.lock",
                  "image.png", "lib.so"):
            self.assertTrue(should_skip_file(f), f"{f} should be skipped")

    def test_keeps_source_files(self):
        for f in ("app.py", "main.js", "index.html", "Dockerfile"):
            self.assertFalse(should_skip_file(f), f"{f} should NOT be skipped")


class TestIgnoreMarker(unittest.TestCase):
    """The ``# security-guard: ignore-file`` opt-out is the mechanism that
    lets the tool audit itself without flagging its own pattern definitions."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name: str, content: str) -> str:
        p = os.path.join(self.tmp.name, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        return p

    def test_marker_in_first_2kb_is_detected(self):
        path = self._write("a.py", f"# {IGNORE_FILE_MARKER}\nprint('hi')\n")
        self.assertTrue(has_ignore_marker(path))

    def test_no_marker(self):
        path = self._write("b.py", "print('plain')\n")
        self.assertFalse(has_ignore_marker(path))

    def test_marker_after_2kb_is_ignored(self):
        # Marker placed *after* the 2 KB read window must not count, otherwise
        # an attacker could hide a "skip me" line at byte 50 000.
        padding = "x = 0\n" * 1000  # ~6 KB
        path = self._write("c.py", padding + f"# {IGNORE_FILE_MARKER}\n")
        self.assertFalse(has_ignore_marker(path))

    def test_unreadable_file_returns_false(self):
        self.assertFalse(has_ignore_marker(
            os.path.join(self.tmp.name, "does-not-exist.py")
        ))

    def test_iter_source_files_skips_marked(self):
        keep = self._write("real.py", "print('keep me')\n")
        skip = self._write("pattern.py",
                           f"# {IGNORE_FILE_MARKER}\nprint('skip me')\n")
        files = set(iter_source_files(self.tmp.name, extensions={".py"}))
        self.assertIn(keep, files)
        self.assertNotIn(skip, files)


if __name__ == "__main__":
    unittest.main()
