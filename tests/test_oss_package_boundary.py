"""Free-package metadata boundary. Archive contents are checked outside unittest."""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


class OssPackageBoundaryTests(unittest.TestCase):
    def test_pyproject_ships_only_the_free_package(self):
        text = _read("pyproject.toml")
        self.assertIn('packages = ["afk_guard"]', text)
        self.assertNotIn("afk_guard.platform", text)
        self.assertNotIn("project.urls", text)
        self.assertNotIn("authors", text)
        self.assertIn('name = "afk-guard"', text)
        self.assertIn('version = "0.1.0"', text)
        self.assertIn('readme = "README.md"', text)
        self.assertNotIn("optional-dependencies", text)
        self.assertIn("Apache-2.0", text)

    def test_manifest_prunes_private_trees(self):
        text = _read("MANIFEST.in")
        for needle in (
            "prune afk_guard/platform",
            "prune plan",
            "prune tests",
            "prune docs",
            "prune trial-audits",
            "prune scripts",
            "prune test-fixtures",
            "exclude updates.jsonl",
            "exclude CONTRIBUTING.md",
        ):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
