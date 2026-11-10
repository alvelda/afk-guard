"""Free-package metadata boundary. Archive contents are checked outside unittest."""
import hashlib
import os
import re
import unittest

# SHA-256 of lowercased denied name tokens. The words are not stored as text.
_DENIED_NAME_SHA256 = frozenset({
    "5d19115b2691291d373573fb347c57d65882836bcda5e3d8d6768e59a6311904",
    "82210325181958a3f884408e6a503e1a63668a5e35c2863d95230cb2d9bb09c8",
})

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
        self.assertIn('version = "0.1.1"', text)
        self.assertIn('readme = "README.md"', text)
        self.assertNotIn("optional-dependencies", text)
        self.assertIn("Apache-2.0", text)
        self.assertIn("tomli>=1.2.3; python_version < '3.11'", text)

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

    def test_readme_links_and_ids_stay_in_the_free_export(self):
        text = _read("README.md")
        license_at = text.index("## License\n")
        license_section = text[license_at:]
        body = text[:license_at]
        self.assertNotIn("docs/", body)
        self.assertEqual(
            license_section,
            "## License\n"
            "Apache-2.0, see `LICENSE`. Commercial terms for paid features will be "
            "published separately.\n",
        )
        self.assertNotIn("docs/legal", text)
        for pattern in (r"DEF-\d+", r"\bR\d+\b", r"\bG\d+\b", r"Architect"):
            self.assertIsNone(re.search(pattern, text), pattern)
        shipped = _free_export_files()
        for banned in (
            "docs/platform-overview.md",
            "updates.jsonl",
            "tests/support_paid_access.py",
            "test-fixtures/MANIFEST.md",
        ):
            self.assertNotIn(banned, shipped)
        missing = []
        for link in _relative_links(body):
            if not _link_ships(link, shipped):
                missing.append(link)
        self.assertEqual(missing, [])

    def test_readme_denylist(self):
        self.assertEqual(_denylist_hits(_read("README.md")), [])

    def test_inventory_preview_example_matches_help(self):
        text = _read("README.md")
        self.assertIn("inventory-preview ./inventory.json", text)
        self.assertNotIn("inventory-preview ./my-project", text)
        self.assertNotIn("test-fixtures/preview", text)
        import io
        from contextlib import redirect_stdout
        from afk_guard.cli import main
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as caught:
                main(["inventory-preview", "--help"])
        self.assertEqual(caught.exception.code, 0)
        help_text = buf.getvalue()
        self.assertRegex(help_text, r"inventory-preview.*\bfile\b")
        parent = io.StringIO()
        with redirect_stdout(parent):
            with self.assertRaises(SystemExit) as top:
                main(["--help"])
        self.assertEqual(top.exception.code, 0)
        collapsed = re.sub(r"\s+", " ", parent.getvalue())
        self.assertIn("offline analysis of an agent-access inventory JSON", collapsed)

    def test_denylist_catches_names_prices_and_bare_brainworks(self):
        samples = (
            "see stripe billing",
            "the pricing page",
            "costs $29",
            "costs 29 USD",
            "costs USD 29",
            "an internal note",
            "Brainworks builds this",
            "stripe checkout",
        )
        for sample in samples:
            self.assertNotEqual(_denylist_hits(sample), [], sample)

    def test_denylist_allows_shell_git_and_the_operator_name(self):
        samples = (
            "git checkout main",
            "echo $1",
            "Brainworks Ventures Foundry, Inc. publishes the commercial terms.",
            "Commercial terms for paid features will be published separately.",
        )
        for sample in samples:
            self.assertEqual(_denylist_hits(sample), [], sample)

    def test_name_hash_matcher_flags_a_token_and_masks_the_repo_url(self):
        fake = "qxname"
        digest = hashlib.sha256(fake.encode("utf-8")).hexdigest()
        names = frozenset({digest})
        self.assertEqual(_denylist_hits("hello " + fake, names=names), ["name"])
        self.assertEqual(_denylist_hits(fake.upper(), names=names), ["name"])
        url = "https://github.com/" + fake + "/afk-guard"
        self.assertEqual(_denylist_hits("see " + url, names=names), [])


def _denylist_hits(text, names=None):
    """Case-insensitive public-README denylist. Returns the labels that matched."""
    hits = []
    denied = _DENIED_NAME_SHA256 if names is None else names
    masked = re.sub(r"Brainworks Ventures Foundry, Inc\.", " ", text, flags=re.I)
    masked = re.sub(r"https://github\.com/[^/\s]+/afk-guard\b", " ", masked, flags=re.I)
    masked = re.sub(r"\bgit\s+checkout\b", " ", masked, flags=re.I)
    masked = re.sub(r"\$\d\b", " ", masked)
    for token in re.findall(r"[A-Za-z]+", masked):
        digest = hashlib.sha256(token.lower().encode("utf-8")).hexdigest()
        if digest in denied:
            hits.append("name")
            break
    checks = (
        ("Stripe", r"\bstripe\b"),
        ("pricing", r"\bpricing\b"),
        ("checkout", r"\bcheckout\b"),
        ("internal", r"\binternal\b"),
        ("Brainworks", r"\bbrainworks\b"),
        ("dollar amount", r"\$\s*\d+"),
        ("USD amount", r"\b\d+\s+usd\b|\busd\s+\d+\b"),
    )
    for label, pattern in checks:
        if re.search(pattern, masked, re.I):
            hits.append(label)
    emails = re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)
    if emails:
        hits.append("email")
    return hits


def _free_export_files():
    """Source files that the free export keeps. docs/, plan/, scripts/, and platform tests do not."""
    skip_dirs = {
        ".git", "__pycache__", "docs", "plan", "scripts", "trial-audits", "critique", "platform",
    }
    shipped = set()
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [name for name in dirnames if name not in skip_dirs]
        for name in filenames:
            if name.endswith(".pyc"):
                continue
            path = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
            if path in {"CONTRIBUTING.md", "updates.jsonl", ".gitignore", "test-fixtures/MANIFEST.md"}:
                continue
            if path.startswith("tests/test_platform") or path == "tests/support_paid_access.py":
                continue
            shipped.add(path)
    return shipped


def _relative_links(text):
    found = []
    for match in re.finditer(r"\[[^\]]*\]\(([^)\s]+)\)", text):
        target = match.group(1)
        if not re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):
            found.append(target.split("#", 1)[0])
    for match in re.finditer(
        r"`((?:docs|plan|scripts|afk_guard|test-fixtures|tests)/[^`]+)`",
        text,
    ):
        found.append(match.group(1).strip())
    for match in re.finditer(r"`(LICENSE|CHANGELOG\.md|README\.md|pyproject\.toml|MANIFEST\.in)`", text):
        found.append(match.group(1))
    return found


def _link_ships(link, shipped):
    path = link.strip().lstrip("./").rstrip("/")
    if not path:
        return False
    if path in shipped:
        return True
    prefix = path + "/"
    return any(item.startswith(prefix) for item in shipped)


if __name__ == "__main__":
    unittest.main()
