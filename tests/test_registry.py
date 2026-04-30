# security-guard: ignore-file
"""Tests for ``scanners.registry`` — the single source of truth shared by
the web dashboard and the CLI."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.base import BaseScanner
from scanners.registry import (
    SCANNERS, ScannerEntry,
    code_scanners, web_scanners, by_key, keys,
)


class TestRegistryShape(unittest.TestCase):
    def test_at_least_one_entry(self):
        self.assertTrue(len(SCANNERS) > 0)

    def test_keys_unique(self):
        ks = [s.key for s in SCANNERS]
        self.assertEqual(len(ks), len(set(ks)), f"duplicate keys: {ks}")

    def test_keys_are_short_lowercase_ids(self):
        for s in SCANNERS:
            self.assertRegex(s.key, r"^[a-z][a-z0-9_]*$",
                             f"bad key: {s.key!r}")

    def test_classes_extend_basescanner(self):
        for s in SCANNERS:
            self.assertTrue(issubclass(s.cls, BaseScanner),
                            f"{s.cls.__name__} is not a BaseScanner")

    def test_kinds_are_valid(self):
        for s in SCANNERS:
            self.assertIn(s.kind, ("code", "web"))

    def test_descriptions_nonempty(self):
        for s in SCANNERS:
            self.assertTrue(s.description.strip(),
                            f"{s.key} has empty description")


class TestRegistryHelpers(unittest.TestCase):
    def test_partitions_cover_all(self):
        # code + web should equal the full registry, no overlap, no loss.
        all_keys = {s.key for s in SCANNERS}
        partition = {s.key for s in code_scanners()} | {s.key for s in web_scanners()}
        self.assertEqual(all_keys, partition)

    def test_by_key_lookup(self):
        lookup = by_key()
        for s in SCANNERS:
            self.assertIs(lookup[s.key], s)

    def test_keys_helper_returns_strings(self):
        ks = keys()
        self.assertEqual(set(ks), {s.key for s in SCANNERS})


class TestRegistryCoreScanners(unittest.TestCase):
    """Sanity check: the scanners we *expect* to ship are still registered."""

    def test_essential_scanners_present(self):
        for k in ("static", "secrets", "deps", "config",
                  "defaults", "attacks", "web"):
            self.assertIn(k, by_key(),
                          f"essential scanner '{k}' missing from registry")


if __name__ == "__main__":
    unittest.main()
