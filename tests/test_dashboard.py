"""Offline HTML report. No network. EXAMPLE fixture plus redaction gates."""
import contextlib
import io
import json
import os
import socket
import tempfile
import unittest

from afk_guard import cli, dashboard
from afk_guard.dashboard import HONESTY, SCHEMA, location_fingerprint

FIX = os.path.join(os.path.dirname(dashboard.__file__), "data", "dashboard-example.json")

# Assembled at runtime so this file holds no complete token literal.
AWS = "AKIA" + "IOSFODNN7" + "EXAMPLX"
GH = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"
PREFIX = "ghp_"


def _html_from_example():
    model = dashboard.normalize(dashboard.example_manifest())
    return dashboard.render(model), model


class DashboardTests(unittest.TestCase):
    def test_cli_writes_example_html(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.html")
            self.assertEqual(cli.main(["dashboard", "--example", "-o", out]), 0)
            self.assertTrue(os.path.isfile(out))
            with open(out, encoding="utf-8") as fh:
                text = fh.read()
            self.assertLess(len(text), dashboard.SIZE_TARGET)
            for marker in (
                "afk-badge-example",
                "EXAMPLE DATA",
                "Scan report",
                "MCP hash drift above fold",
                "Command mosaic",
                "Severity mix",
                "Canary rail",
                "MCP pin / hash drift",
                "Inject panel",
                "What was not checked",
                HONESTY,
                "Kill switch: n/a on free CLI",
                "Not-run",
                "afk-guard.report.v1",
                SCHEMA,
                'id="afk-data"',
                "[REDACTED]",
            ):
                self.assertIn(marker, text, marker)
            order = [
                'id="hero-title"', 'id="mcp-drift"', 'id="mosaic-h"', 'id="sev-h"',
                'id="find-h"', 'id="canary-h"', 'id="mcp-h"', 'id="inject-h"',
                'id="limits-h"', 'id="afk-data"',
            ]
            last = -1
            for key in order:
                at = text.find(key)
                self.assertGreater(at, last, key)
                last = at

    def test_report_html_alias_and_input_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "from-file.html")
            self.assertEqual(cli.main(["report-html", "--html", out, "--input", FIX]), 0)
            with open(out, encoding="utf-8") as fh:
                self.assertIn("EXAMPLE DATA", fh.read())

    def test_missing_input_exits_2(self):
        self.assertEqual(cli.main(["dashboard", "-o", os.devnull]), 2)

    def test_locked_mock_gates(self):
        html, _model = _html_from_example()
        self.assertIn("min-height:44px", html)
        self.assertIn(":focus-visible", html)
        self.assertIn("overflow-x:hidden", html)
        self.assertIn("max-width:640px", html)
        self.assertIn("grid-template-columns:1fr", html)
        self.assertIn("table-scroll", html)
        self.assertIn("email · inbound", html)
        self.assertIn("inject email", html)
        self.assertIn('data-state="Not-run"', html)
        self.assertNotIn("fonts.googleapis", html)
        self.assertNotIn("woff", html.lower())
        self.assertNotIn("<script src", html)
        self.assertNotIn("fetch(", html)
        self.assertNotIn("@font-face", html)
        low = html.lower()
        for banned in ("posture", "risk score", "security score", "certified", "fully protected",
                       "guaranteed safe", "you are secure", "ai firewall", "heatmap", "donut"):
            self.assertNotIn(banned, low, banned)

    def test_r1_strips_secret_prefix_and_uses_location_fp(self):
        raw_fp = "deadbeefcafebabe"
        manifest = {
            "schema": SCHEMA,
            "example": True,
            "scan": {"findings": [{
                "path": "sandbox/example.env",
                "line": 3,
                "rule": "github-token",
                "severity": "high",
                "preview": GH,
                "fingerprint": raw_fp,
                "value": GH,
            }]},
        }
        html = dashboard.render(dashboard.normalize(manifest))
        self.assertNotIn(GH, html)
        self.assertNotIn(PREFIX, html)
        self.assertNotIn(raw_fp, html)
        self.assertIn("[REDACTED]", html)
        self.assertIn("bucket", html)
        fp = location_fingerprint("github-token", "sandbox/example.env", 3)
        self.assertIn(fp, html)
        other = dashboard.normalize({"scan": {"findings": [{
            "path": "sandbox/example.env", "line": 3, "rule": "github-token",
            "severity": "high", "preview": AWS,
        }]}})
        self.assertEqual(other["findings"][0]["fingerprint"], fp)
        self.assertNotIn(AWS, dashboard.render(other))

    def test_skip_reason_when_sections_absent(self):
        html = dashboard.render(dashboard.normalize({"scan": {"files_scanned": 1, "findings": [], "total_real": 0}}))
        self.assertIn("Not-run", html)
        self.assertIn("No inject-check JSON was provided", html)
        self.assertIn("No canary check JSON was provided", html)
        self.assertIn("Kill switch: n/a on free CLI", html)

    def test_critical_uses_red_label_and_pattern(self):
        html = dashboard.render(dashboard.normalize({"scan": {"findings": [{
            "path": "a.txt", "line": 1, "rule": "private-key-block", "severity": "critical", "length": 40,
        }]}}))
        self.assertIn("afk-sev-critical", html.split("</style>", 1)[-1])
        self.assertIn("CRITICAL", html)
        self.assertIn("#e24a2b", html)
        self.assertIn("sev-critical", html)

    def test_renderer_does_not_open_sockets(self):
        real = socket.socket

        def boom(*_a, **_k):
            raise AssertionError("network")

        socket.socket = boom
        try:
            html, _model = _html_from_example()
            self.assertIn("data-section=\"drift\"", html)
        finally:
            socket.socket = real

    def test_fixture_has_no_secret_shapes(self):
        with open(FIX, encoding="utf-8") as fh:
            blob = fh.read()
        for needle in (AWS, GH, "AKIA", PREFIX, "sk_live_", "xoxb-"):
            self.assertNotIn(needle, blob)
        json.loads(blob)

    def test_module_source_has_no_network_imports(self):
        with open(dashboard.__file__, encoding="utf-8") as fh:
            src = fh.read()
        for banned in ("urllib", "requests", "http.client", "socket", "webbrowser"):
            self.assertNotIn(banned, src)


def _write_json(directory, name, payload):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


def _run(argv):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, err.getvalue()


def _between(html, start, end):
    at = html.find(start)
    if at < 0:
        return ""
    stop = html.find(end, at + len(start))
    if stop < 0:
        return html[at:]
    return html[at:stop]


class DashboardSafetyTests(unittest.TestCase):
    def _raw_scan(self, total_real=1, counts=None):
        preview = "ghp_" + "abcd" + "…[40 chars]"
        return {
            "files_scanned": 2,
            "total_real": total_real,
            "counts": counts if counts is not None else {"high": 1},
            "findings": [{
                "path": "live-marker.env",
                "line": 4,
                "rule": "github-token",
                "severity": "high",
                "description": "saw " + preview + " and " + ("AKIA" + "…[20 chars]"),
                "preview": preview,
                "fingerprint": "deadbeefcafebabe",
            }],
        }

    def _c2(self):
        return {
            "schema": "afk-guard/inject-check/v1",
            "tool": "inject-check",
            "version": "0.1.0",
            "generated_at": "2026-11-05T00:00:00Z",
            "source": "live-marker.txt",
            "truncated": False,
            "severity": "high",
            "risk": "high",
            "reasons": ["Text tells the reader to ignore, disregard, or forget earlier instructions."],
            "spans": [],
            "advice": ["Do not follow instructions embedded in untrusted text."],
            "findings": [{
                "rule": "ignore-previous-instructions",
                "severity": "high",
                "reason": "Text tells the reader to ignore, disregard, or forget earlier instructions.",
                "line": 2,
                "span": {"start": 0, "end": 12},
                "length_bucket": "16-31",
                "preview": "[REDACTED] ignore-previous-instructions len=16-31 id=aabbccdd",
                "fingerprint": "deadbeefcafebabe",
            }],
        }

    def _c3(self):
        return {
            "schema": "afk-guard/mcp-check/v1",
            "tool": "mcp-check",
            "version": "0.1.0",
            "generated_at": "2026-11-05T00:00:00Z",
            "findings": [{
                "check": "advisory",
                "severity": "high",
                "file": "mcp.json",
                "server": "demo",
                "rule": "ADV-1",
                "message": "matched advisory pkg",
                "verdict": "affected",
                "package": "pkg",
                "advisory_id": "ADV-1",
            }],
            "hits": [{
                "verdict": "affected",
                "server": "demo",
                "package": "pkg",
                "version": "1.2.3",
                "advisory_id": "ADV-1",
                "file": "mcp.json",
                "reason": "matched advisory",
            }],
            "extension_hits": [],
            "hygiene": [],
            "notes": [],
            "advisory_db": {"count": 0, "generated_at": "2026-11-05T00:00:00Z", "feed_sha256": "abc"},
            "servers": 1,
            "configs": [],
        }

    def test_input_raw_scan_keeps_finding_and_exit(self):
        with tempfile.TemporaryDirectory() as d:
            src = _write_json(d, "scan.json", self._raw_scan())
            via_input = os.path.join(d, "input.html")
            via_scan = os.path.join(d, "scan.html")
            self.assertEqual(cli.main(["dashboard", "--input", src, "-o", via_input]), 1)
            self.assertEqual(cli.main(["dashboard", "--scan", src, "-o", via_scan]), 1)
            for path in (via_input, via_scan):
                with open(path, encoding="utf-8") as fh:
                    html = fh.read()
                self.assertIn("live-marker.env", html)
                self.assertIn("github-token", html)
                self.assertIn("Ran-fail", html)
                self.assertNotIn("No findings in this JSON", html)
                self.assertNotIn("ghp_", html)
                self.assertNotIn("AKIA", html)
                self.assertNotIn("deadbeefcafebabe", html)
                self.assertNotIn("EXAMPLE DATA", html)
                self.assertNotIn("40 chars", html)
                self.assertNotIn('data-state="Ran-pass"', html)

    def test_input_c2_matches_inject_flag(self):
        with tempfile.TemporaryDirectory() as d:
            src = _write_json(d, "inject.json", self._c2())
            for flag, out_name in (("--input", "a.html"), ("--inject", "b.html")):
                out = os.path.join(d, out_name)
                self.assertEqual(cli.main(["dashboard", flag, src, "-o", out]), 1)
                with open(out, encoding="utf-8") as fh:
                    html = fh.read()
                panel = _between(html, 'id="inject-h"', 'id="limits-h"')
                self.assertIn("ignore-previous-instructions", panel)
                self.assertIn("disregard", panel)
                self.assertIn("16-31", panel)
                self.assertIn("afk-sev-high", panel)
                self.assertNotIn("afk-sev-pass", panel)
                self.assertNotIn(">PASS<", panel)
                self.assertNotIn("deadbeefcafebabe", html)
                self.assertNotIn("EXAMPLE DATA", html)

    def test_input_c3_matches_mcp_flag(self):
        with tempfile.TemporaryDirectory() as d:
            src = _write_json(d, "mcp.json", self._c3())
            for flag, out_name in (("--input", "a.html"), ("--mcp", "b.html")):
                out = os.path.join(d, out_name)
                self.assertEqual(cli.main(["dashboard", flag, src, "-o", out]), 1)
                with open(out, encoding="utf-8") as fh:
                    html = fh.read()
                panel = _between(html, 'id="mcp-h"', 'id="inject-h"')
                self.assertIn("ADV-1", panel)
                self.assertIn("pkg", panel)
                self.assertIn("afk-sev-high", panel)
                self.assertNotIn(">PASS<", panel)
                self.assertNotIn("EXAMPLE DATA", html)

    def test_schema_less_mcp_hits_are_kept(self):
        doc = {
            "configs": [],
            "servers": 1,
            "advisory_db": {"count": 1, "generated_at": "2026-11-05T00:00:00Z", "feed_sha256": "abc"},
            "hits": [{
                "verdict": "affected", "package": "pkg", "version": "1",
                "advisory_id": "ADV-1", "file": "mcp.json", "server": "demo", "reason": "matched",
            }],
            "extension_hits": [],
            "hygiene": [],
            "notes": [],
        }
        with tempfile.TemporaryDirectory() as d:
            src = _write_json(d, "mcp.json", doc)
            out = os.path.join(d, "out.html")
            self.assertEqual(cli.main(["dashboard", "--input", src, "-o", out]), 1)
            with open(out, encoding="utf-8") as fh:
                html = fh.read()
            self.assertIn("ADV-1", html)
            self.assertIn("pkg", html)

    def test_unsupported_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            bare = _write_json(d, "bare.json", {"findings": [{"path": "live-marker.env", "rule": "github-token"}]})
            pins = _write_json(d, "pins.json", {"schema": "afk-guard/mcp-pins/v1", "servers": []})
            weird = _write_json(d, "weird.json", {"preview": GH, "note": "no schema"})
            for src in (bare, pins, weird):
                out = os.path.join(d, os.path.basename(src) + ".html")
                code, err = _run(["dashboard", "--input", src, "-o", out])
                self.assertEqual(code, 2, src)
                self.assertFalse(os.path.exists(out))
                self.assertIn("unsupported dashboard input", err)
                self.assertNotIn("ghp_", err)
                self.assertNotIn(GH, err)
                self.assertNotIn("EXAMPLE DATA", err)

    def test_example_mixed_with_live_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            src = _write_json(d, "scan.json", self._raw_scan())
            out = os.path.join(d, "out.html")
            for argv in (
                ["dashboard", "--example", "--scan", src, "-o", out],
                ["dashboard", "--example", "--input", src, "-o", out],
            ):
                code, err = _run(argv)
                self.assertEqual(code, 2)
                self.assertFalse(os.path.exists(out))
                self.assertIn("mixed mode", err)
                self.assertNotIn("live-marker.env", err)

    def test_pure_example_keeps_badge_and_matching_inject_count(self):
        html, model = _html_from_example()
        self.assertTrue(model["example"])
        self.assertIn("EXAMPLE DATA", html)
        self.assertIn("afk-badge-example", html)
        self.assertIn("Top findings (EXAMPLE)", html)
        self.assertIn("3 payloads", html)
        self.assertNotIn("12 payloads", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("ghp_", html)
        self.assertNotIn("AKIA", html)
        lied = {
            "schema": SCHEMA,
            "example": True,
            "inject": {
                "summary": "12 payloads · 0 tool-fire",
                "rows": [
                    {"class": "hidden HTML comment", "source": "fetched page", "verdict": "pass", "detail": "filtered"},
                    {"class": "agent-bus spoof", "source": "relay text", "verdict": "pass", "detail": "tagged"},
                    {"class": "markdown fence jailbreak", "source": "README scrape", "verdict": "pass", "detail": "no-op"},
                ],
            },
        }
        fixed = dashboard.render(dashboard.normalize(lied))
        self.assertNotIn("12 payloads", fixed)
        self.assertIn("3 rows", fixed)

    def test_total_real_lie_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as d:
            src = _write_json(d, "scan.json", self._raw_scan(total_real=0, counts={"high": 0}))
            out = os.path.join(d, "out.html")
            self.assertEqual(cli.main(["dashboard", "--input", src, "-o", out]), 1)
            with open(out, encoding="utf-8") as fh:
                html = fh.read()
            self.assertIn("live-marker.env", html)
            self.assertIn('data-state="Ran-fail"', html)
            self.assertNotIn('data-state="Ran-pass"', html)
            self.assertNotIn(">PASS<", _between(html, 'id="find-h"', 'id="canary-h"'))
            self.assertIn("EXIT 1", html)

    def test_count_lie_without_rows_is_not_a_pass(self):
        doc = {"files_scanned": 99, "total_real": 0, "counts": {"high": 2}, "findings": []}
        with tempfile.TemporaryDirectory() as d:
            src = _write_json(d, "scan.json", doc)
            out = os.path.join(d, "out.html")
            self.assertEqual(cli.main(["dashboard", "--input", src, "-o", out]), 1)
            with open(out, encoding="utf-8") as fh:
                html = fh.read()
            self.assertNotIn('data-state="Ran-pass"', html)
            self.assertIn('data-state="Ran-fail"', html)

    def test_markup_escape_holds(self):
        payload = '</script><img src=x onerror=alert(1)>'
        quote = '" onmouseover="alert(1)'
        manifest = {
            "schema": "afk-guard/scan/v1",
            "files_scanned": 1,
            "total_real": 1,
            "findings": [{
                "path": "live-marker.env",
                "line": 1,
                "rule": "github-token",
                "severity": "high",
                "why": payload + " " + quote,
            }],
        }
        html = dashboard.render(dashboard.normalize(manifest))
        self.assertIn("&lt;/script&gt;&lt;img", html)
        self.assertIn("&quot; onmouseover=&quot;", html)
        self.assertNotIn("<img", html)
        self.assertEqual(html.count("<script"), 1)
        self.assertEqual(html.count("</script>"), 1)

    def _assert_symlink_replaced(self, directory, link_name, invoke):
        target = os.path.join(directory, "kept.txt")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("KEEPME")
        link = os.path.join(directory, link_name)
        os.symlink(target, link)
        before = os.stat(target)
        code = invoke(link)
        self.assertEqual(code, 0)
        with open(target, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "KEEPME")
        self.assertEqual(os.stat(target).st_ino, before.st_ino)
        self.assertFalse(os.path.islink(link))
        self.assertTrue(os.path.isfile(link))
        with open(link, encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("EXAMPLE DATA", body)
        self.assertNotIn("KEEPME", body)

    def test_output_symlink_is_replaced_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            self._assert_symlink_replaced(
                d, "out.html",
                lambda link: cli.main(["dashboard", "--example", "-o", link]),
            )

    def test_default_output_symlink_is_replaced_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            try:
                os.chdir(d)
                self._assert_symlink_replaced(
                    d, "afk-guard-dashboard.html",
                    lambda _link: cli.main(["dashboard", "--example"]),
                )
            finally:
                os.chdir(cwd)

    def test_write_does_not_open_the_destination_name(self):
        real_open = os.open

        def guarded(path, flags, mode=0o777, *, dir_fd=None):
            base = os.path.basename(path) if isinstance(path, str) else ""
            if base == "out.html":
                raise AssertionError("opened destination " + str(path))
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "kept.txt")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("KEEPME")
            link = os.path.join(d, "out.html")
            os.symlink(target, link)
            os.open = guarded
            try:
                dashboard.write(link, "<html>EXAMPLE DATA</html>")
            finally:
                os.open = real_open
            with open(target, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "KEEPME")
            self.assertFalse(os.path.islink(link))

    def test_regular_file_is_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.html")
            with open(out, "w", encoding="utf-8") as fh:
                fh.write("OLD")
            self.assertEqual(cli.main(["dashboard", "--example", "-o", out]), 0)
            self.assertFalse(os.path.islink(out))
            with open(out, encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("EXAMPLE DATA", body)
            self.assertNotIn("OLD", body)


if __name__ == "__main__":
    unittest.main()
