# security-guard: ignore-file
"""Tests for ``core.github_fetcher`` — URL parsing + visibility classification.

Network-touching tests stub :func:`urllib.request.urlopen` with
:mod:`unittest.mock` so the suite stays hermetic and offline.
"""

import io
import json
import os
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.github_fetcher import (
    parse_github_url,
    check_repo_visibility,
    is_github_url,
    is_web_url,
)


# ── parse_github_url ──────────────────────────────────────────────────────────

class TestParseGithubUrl(unittest.TestCase):
    def test_canonical_form(self):
        info = parse_github_url("https://github.com/foo/bar")
        self.assertEqual(info["owner"], "foo")
        self.assertEqual(info["repo"], "bar")
        self.assertIsNone(info["branch"])
        self.assertEqual(info["clone_url"], "https://github.com/foo/bar.git")
        self.assertEqual(info["display"], "foo/bar")

    def test_dot_git_suffix_stripped(self):
        info = parse_github_url("https://github.com/foo/bar.git")
        self.assertEqual(info["repo"], "bar")

    def test_branch_extracted_from_tree_url(self):
        info = parse_github_url("https://github.com/foo/bar/tree/develop")
        self.assertEqual(info["branch"], "develop")
        self.assertEqual(info["display"], "foo/bar@develop")

    def test_protocol_optional(self):
        info = parse_github_url("github.com/foo/bar")
        self.assertEqual(info["clone_url"], "https://github.com/foo/bar.git")

    def test_trailing_slash(self):
        info = parse_github_url("https://github.com/foo/bar/")
        self.assertEqual(info["repo"], "bar")

    def test_invalid_url_raises(self):
        with self.assertRaises(ValueError):
            parse_github_url("https://gitlab.com/foo/bar")


# ── is_github_url / is_web_url helpers ────────────────────────────────────────

class TestUrlClassifiers(unittest.TestCase):
    def test_github_detected(self):
        self.assertTrue(is_github_url("https://github.com/x/y"))
        self.assertTrue(is_github_url("github.com/x/y"))

    def test_web_excludes_github(self):
        self.assertTrue(is_web_url("https://example.com"))
        self.assertFalse(is_web_url("https://github.com/x/y"))

    def test_local_path_is_neither(self):
        self.assertFalse(is_github_url("/home/user/project"))
        self.assertFalse(is_web_url("/home/user/project"))


# ── check_repo_visibility ─────────────────────────────────────────────────────

def _fake_response(payload: dict):
    """Build a minimal context-manager mock for urlopen."""
    body = json.dumps(payload).encode("utf-8")

    class _Resp:
        def __enter__(self_inner): return self_inner
        def __exit__(self_inner, *a): return False
        def read(self_inner): return body
    return _Resp()


class TestCheckRepoVisibility(unittest.TestCase):
    @patch("core.github_fetcher.urllib.request.urlopen")
    def test_public_repo(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response({"private": False})
        result = check_repo_visibility("octocat", "Hello-World")
        self.assertEqual(result["status"], "public")
        self.assertFalse(result["private"])

    @patch("core.github_fetcher.urllib.request.urlopen")
    def test_private_repo(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response({"private": True})
        result = check_repo_visibility("acme", "internal")
        self.assertEqual(result["status"], "private")
        self.assertTrue(result["private"])

    @patch("core.github_fetcher.urllib.request.urlopen")
    def test_404_classified_as_not_found(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            url="http://x", code=404, msg="Not Found", hdrs=None, fp=io.BytesIO(b"")
        )
        result = check_repo_visibility("acme", "missing")
        self.assertEqual(result["status"], "not_found")
        self.assertIn("PRIVATE or does not exist", result["message"])

    @patch("core.github_fetcher.urllib.request.urlopen")
    def test_network_error_falls_back_to_unknown(self, mock_urlopen):
        from urllib.error import URLError
        mock_urlopen.side_effect = URLError("dns down")
        result = check_repo_visibility("any", "thing")
        self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
