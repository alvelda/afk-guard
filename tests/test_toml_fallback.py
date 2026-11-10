"""Codex TOML parsing, missing and broken parsers, and the unparseable-config exit."""
import importlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from afk_guard import cli, mcpcheck

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(os.path.dirname(HERE), "test-fixtures", "mcp", "codex-config.toml")
_HAS_TOML = mcpcheck._toml is not None


class CodexTomlTests(unittest.TestCase):
    def setUp(self):
        self._saved = (mcpcheck._toml, mcpcheck._toml_status, mcpcheck._toml_exc_name)

    def tearDown(self):
        mcpcheck._toml, mcpcheck._toml_status, mcpcheck._toml_exc_name = self._saved

    @unittest.skipUnless(_HAS_TOML, "no TOML parser installed")
    def test_codex_fixture_parses_as_toml(self):
        self.assertTrue(FIX.endswith(".toml"))
        servers, notes = mcpcheck.parse_config(FIX)
        self.assertEqual(notes, [])
        self.assertIn("fastmcp-thing", {s.name for s in servers})
        hit = next(s for s in servers if s.name == "fastmcp-thing")
        self.assertEqual(hit.command, "uvx")
        self.assertEqual(hit.args, ["fastmcp==3.4.9"])

    @unittest.skipUnless(_HAS_TOML, "no TOML parser installed")
    def test_inline_toml_server_parses(self):
        body = "\n".join([
            "[mcp_servers.demo]",
            'command = "npx"',
            'args = ["-y", "example-pin-fixture@1.0.0"]',
            "",
        ])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            servers, notes = mcpcheck.parse_config(path)
        self.assertEqual(notes, [])
        self.assertEqual([s.name for s in servers], ["demo"])
        self.assertEqual(servers[0].command, "npx")
        self.assertEqual(servers[0].args, ["-y", "example-pin-fixture@1.0.0"])

    @unittest.skipUnless(_HAS_TOML, "no TOML parser installed")
    def test_malformed_toml_is_a_parse_failure_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[\n")
            servers, notes = mcpcheck.parse_config(path)
        self.assertEqual(servers, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("could not parse", notes[0])
        self.assertNotIn("crashed", notes[0])
        self.assertTrue(mcpcheck.notes_indicate_parse_failure(notes))

    def test_missing_parser_is_a_parse_failure_note(self):
        mcpcheck._toml = None
        mcpcheck._toml_status = "missing"
        body = "[mcp_servers.demo]\ncommand = \"npx\"\nargs = [\"-y\", \"example-pin-fixture@1.0.0\"]\n"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            servers, notes = mcpcheck.parse_config(path)
        self.assertEqual(servers, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("TOML parsing unavailable", notes[0])
        self.assertNotIn("failed to load", notes[0])
        self.assertNotIn("npx", notes[0])
        self.assertNotIn("example-pin-fixture", notes[0])
        self.assertTrue(mcpcheck.notes_indicate_parse_failure(notes))

    def test_broken_import_is_not_a_missing_module(self):
        orig = importlib.import_module

        def fake(name, package=None):
            if name == "tomllib":
                raise ModuleNotFoundError("No module named tomllib")
            if name == "tomli":
                raise ImportError("tomli init failed SECRETTOKEN")
            return orig(name, package)

        importlib.import_module = fake
        try:
            mod, status, exc_name = mcpcheck._load_toml_parser()
        finally:
            importlib.import_module = orig
        self.assertIsNone(mod)
        self.assertEqual(status, "broken-import")
        self.assertEqual(exc_name, "ImportError")

    def test_broken_import_note_uses_the_real_exception_class(self):
        class TomlInitError(Exception):
            pass

        orig = importlib.import_module

        def fake(name, package=None):
            if name == "tomllib":
                raise ModuleNotFoundError("No module named tomllib")
            if name == "tomli":
                raise TomlInitError("init failed SECRETTOKEN")
            return orig(name, package)

        importlib.import_module = fake
        try:
            mod, status, exc_name = mcpcheck._load_toml_parser()
        finally:
            importlib.import_module = orig
        self.assertIsNone(mod)
        self.assertEqual(status, "broken-import")
        self.assertEqual(exc_name, "TomlInitError")
        mcpcheck._toml = None
        mcpcheck._toml_status = status
        mcpcheck._toml_exc_name = exc_name
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[mcp_servers.demo]\ncommand = \"npx\"\n")
            servers, notes = mcpcheck.parse_config(path)
        self.assertEqual(servers, [])
        self.assertIn("TOML parser failed to load (TomlInitError)", notes[0])
        self.assertNotIn("ImportError", notes[0])
        self.assertNotIn("SECRETTOKEN", notes[0])
        self.assertNotIn("npx", notes[0])

    def test_broken_install_note_is_distinct_and_redacted(self):
        mcpcheck._toml = None
        mcpcheck._toml_status = "broken-import"
        mcpcheck._toml_exc_name = "ImportError"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[mcp_servers.demo]\ncommand = \"npx\"\n")
            servers, notes = mcpcheck.parse_config(path)
        self.assertEqual(servers, [])
        self.assertIn("TOML parser failed to load (ImportError)", notes[0])
        self.assertNotIn("TOML parsing unavailable", notes[0])
        self.assertNotIn("npx", notes[0])
        self.assertNotIn("SECRETTOKEN", notes[0])
        self.assertTrue(mcpcheck.notes_indicate_parse_failure(notes))

    def test_parser_crash_note_is_distinct_and_redacted(self):
        class _Boom:
            def loads(self, raw):
                raise RuntimeError("parser blew up SECRETTOKEN")

        mcpcheck._toml = _Boom()
        mcpcheck._toml_status = "ok"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[mcp_servers.demo]\ncommand = \"npx\"\n")
            servers, notes = mcpcheck.parse_config(path)
        self.assertEqual(servers, [])
        self.assertIn("TOML parser crashed (RuntimeError)", notes[0])
        self.assertNotIn("could not parse", notes[0])
        self.assertNotIn("unavailable", notes[0])
        self.assertNotIn("SECRETTOKEN", notes[0])
        self.assertNotIn("npx", notes[0])
        self.assertTrue(mcpcheck.notes_indicate_parse_failure(notes))

    def test_skipped_toml_exits_nonzero_without_pin_state(self):
        mcpcheck._toml = None
        mcpcheck._toml_status = "missing"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[mcp_servers.demo]\ncommand = \"npx\"\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.main(["mcp-check", path, "--no-discover", "--home", d, "--format", "json"])
            zero = io.StringIO()
            with redirect_stdout(zero):
                forced = cli.main([
                    "mcp-check", path, "--no-discover", "--home", d, "--format", "json", "--exit-zero",
                ])
        text = buf.getvalue()
        self.assertEqual(code, 1)
        self.assertEqual(forced, 0)
        self.assertNotIn("npx", text)
        doc = json.loads(text)
        self.assertTrue(any(
            f["check"] == "config-unparseable" and f["severity"] == "high" for f in doc["findings"]
        ))
        self.assertTrue(any("TOML parsing unavailable" in n for n in doc["notes"]))
        self.assertIn("config-unparseable", doc["gate"]["process_exit"])

    def test_unparseable_text_summary_is_safety_not_pin_drift(self):
        mcpcheck._toml = None
        mcpcheck._toml_status = "missing"
        mcpcheck._toml_exc_name = ""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[mcp_servers.demo]\ncommand = \"npx\"\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.main(["mcp-check", path, "--no-discover", "--home", d])
        text = buf.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("CONFIG-UNPARSEABLE", text)
        self.assertIn("0 pin-drift, 1 safety", text)
        self.assertNotIn("1 pin-drift", text)
        self.assertNotIn("npx", text)


if __name__ == "__main__":
    unittest.main()
