"""DEF-007: registry directory must be owner-only. Fake files only.

These tests cover this Linux interpreter's directory descriptors. They do not
claim a concurrent rename race was closed, and they do not walk ancestors.
"""
import io
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from afk_guard import canary, cli

MARKER = "AFKGUARDTEST"


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


class CanaryRegistryDirectoryTests(unittest.TestCase):
    def test_private_directory_still_plants_0600_without_value_hash(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(_mode(d), 0o700)
            planted = canary.plant(d, ["github"])
            reg = os.path.join(d, canary.REGISTRY_NAME)
            self.assertEqual(_mode(reg), 0o600)
            with open(reg) as fh:
                text = fh.read()
            self.assertNotIn("value_sha256", text)
            self.assertIn(planted[0]["marker"], text)
            self.assertEqual(_mode(os.path.join(d, planted[0]["file"])), 0o600)
            self.assertEqual(canary.check(d), [])

    def test_shared_and_sticky_directories_are_refused_and_not_chmodded(self):
        parent = tempfile.mkdtemp()

        def _cleanup():
            os.chmod(parent, 0o700)
            shutil.rmtree(parent, ignore_errors=True)

        self.addCleanup(_cleanup)
        for mode in (0o777, 0o1777, 0o755, 0o1700):
            os.chmod(parent, mode)
            with self.assertRaises(canary.CanaryRegistryError):
                canary.plant(parent, ["github"])
            self.assertEqual(_mode(parent), mode)
            self.assertFalse(os.path.exists(os.path.join(parent, canary.REGISTRY_NAME)))
            code, out, err = _run(["canary", "plant", parent, "--kinds", "github"])
            self.assertEqual(code, 1)
            self.assertNotIn(MARKER, err)
            self.assertNotIn("ghp_", err)
            self.assertNotIn("AFKGUARD", out)
            self.assertIn("0700", err)
            self.assertEqual(_mode(parent), mode)

    def test_symlink_directory_is_refused_and_target_is_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real")
            os.mkdir(real, 0o700)
            link = os.path.join(d, "link")
            os.symlink(real, link)
            with self.assertRaises(canary.CanaryRegistryError):
                canary.plant(link, ["github"])
            self.assertEqual(os.listdir(real), [])
            self.assertTrue(os.path.islink(link))
            code, _out, err = _run(["canary", "plant", link, "--kinds", "github"])
            self.assertEqual(code, 1)
            self.assertNotIn("ghp_", err)
            self.assertEqual(os.listdir(real), [])

    def test_symlink_registry_is_refused_and_target_bytes_stay(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o700)
            target = os.path.join(d, "elsewhere.json")
            payload = '{"canaries":[],"note":"' + MARKER + '"}\n'
            with open(target, "w") as fh:
                fh.write(payload)
            os.symlink(target, os.path.join(d, canary.REGISTRY_NAME))
            with self.assertRaises(canary.CanaryRegistryError):
                canary.plant(d, ["github"])
            with open(target) as fh:
                self.assertEqual(fh.read(), payload)
            self.assertTrue(os.path.islink(os.path.join(d, canary.REGISTRY_NAME)))
            code, out, err = _run(["canary", "check", d])
            self.assertEqual(code, 1)
            self.assertNotIn(MARKER, out)
            self.assertNotIn(MARKER, err)
            with open(target) as fh:
                self.assertEqual(fh.read(), payload)

    def test_loose_registry_is_refused_not_repaired(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o700)
            path = os.path.join(d, canary.REGISTRY_NAME)
            body = '{"version":1,"canaries":[{"id":"abcd","marker":"' + MARKER + '"}]}\n'
            with open(path, "w") as fh:
                fh.write(body)
            os.chmod(path, 0o644)
            with self.assertRaises(canary.CanaryRegistryError):
                canary.check(d)
            self.assertEqual(_mode(path), 0o644)
            with open(path) as fh:
                self.assertEqual(fh.read(), body)
            code, out, err = _run(["canary", "check", d, "--format", "json"])
            self.assertEqual(code, 1)
            self.assertNotIn(MARKER, out)
            self.assertNotIn(MARKER, err)
            with open(path) as fh:
                self.assertEqual(fh.read(), body)
            self.assertEqual(_mode(path), 0o644)

    def test_missing_leaf_is_created_0700_without_touching_parent_mode(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o755)
            parent_mode = _mode(d)
            leaf = os.path.join(d, "sandbox")
            planted = canary.plant(leaf, ["env"])
            self.assertTrue(planted)
            self.assertEqual(_mode(leaf), 0o700)
            self.assertEqual(_mode(d), parent_mode)
            self.assertEqual(_mode(os.path.join(leaf, canary.REGISTRY_NAME)), 0o600)


if __name__ == "__main__":
    unittest.main()
