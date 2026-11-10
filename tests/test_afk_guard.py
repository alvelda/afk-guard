import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.request
from contextlib import redirect_stdout

from afk_guard import scan, canary, mcpcheck, cli
from afk_guard.redact import fingerprint, length_bucket, redact

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(os.path.dirname(HERE), "test-fixtures", "mcp")

# Fake secrets are assembled at runtime so this file contains no complete token literal.
AWS = "AKIA" + "IOSFODNN7" + "EXAMPLX"
GH = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"
SLACK = "xoxb-" + "1234567890-" + "abcdefghijkl"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def w(path, data, mode="w"):
    with open(path, mode) as fh:
        fh.write(data)


def r(path):
    with open(path) as fh:
        return fh.read()


class RedactTests(unittest.TestCase):
    def test_preview_has_zero_secret_characters(self):
        # Known prefix-leak path: older previews copied value[:4] (long) or [:2].
        # Assert the 4-char leak for long values only. Do not ban 1-character pieces.
        for v in (AWS, GH, SLACK, STRIPE, "short-secret"):
            preview = redact(v, rule_id="example-rule", path="box/a.env", line=4)
            self.assertNotIn(v, preview)
            if len(v) >= 20:
                self.assertNotIn(v[:4], preview)
            self.assertRegex(
                preview,
                r"^\[REDACTED\] example-rule len=(lt8|8-15|16-31|32-63|64-127|128-255|256\+) id=[0-9a-f]{8}$",
            )
            self.assertNotIn(f"[{len(v)} chars]", preview)
            # Bucket labels such as 32-63 contain a boundary number. Exact length
            # would be "len=<n>" at the end of that field, not a range.
            self.assertNotRegex(preview, rf"len={len(v)}(?:\s|$)")
            self.assertIn(f"len={length_bucket(len(v))}", preview)
            self.assertIn(fingerprint("example-rule", "box/a.env", 4), preview)

    def test_fingerprint_is_location_only(self):
        # No credential-value argument, so two secrets at one location cannot be told apart.
        base = fingerprint("github-token", "dir/a.env", 2)
        self.assertEqual(base, fingerprint("github-token", "dir/a.env", 2))
        self.assertEqual(base, fingerprint("github-token", "dir\\a.env", 2))
        self.assertEqual(base, fingerprint("github-token", "dir/../dir/a.env", 2))
        self.assertNotEqual(base, fingerprint("github-token", "dir/b.env", 2))
        self.assertNotEqual(base, fingerprint("github-token", "dir/a.env", 3))
        self.assertNotEqual(base, fingerprint("aws-access-key-id", "dir/a.env", 2))
        self.assertEqual(len(base), 8)

    def test_length_buckets_are_not_exact(self):
        self.assertEqual(length_bucket(0), "lt8")
        self.assertEqual(length_bucket(7), "lt8")
        self.assertEqual(length_bucket(8), "8-15")
        self.assertEqual(length_bucket(15), "8-15")
        self.assertEqual(length_bucket(16), "16-31")
        self.assertEqual(length_bucket(31), "16-31")
        self.assertEqual(length_bucket(32), "32-63")
        self.assertEqual(length_bucket(63), "32-63")
        self.assertEqual(length_bucket(64), "64-127")
        self.assertEqual(length_bucket(127), "64-127")
        self.assertEqual(length_bucket(128), "128-255")
        self.assertEqual(length_bucket(255), "128-255")
        self.assertEqual(length_bucket(256), "256+")
        self.assertEqual(length_bucket(1000), "256+")


class ScanTests(unittest.TestCase):
    def test_rules_detect_and_redact(self):
        text = f"aws={AWS}\nT={GH}\nslack: {SLACK}\nk={STRIPE}\n-----BEGIN RSA PRIVATE KEY-----\n"
        fs = scan.scan_text(text, "f")
        rules = {f.rule for f in fs}
        self.assertTrue({"aws-access-key-id", "github-token", "slack-token", "stripe-live-key", "private-key-block"} <= rules)
        blob = json.dumps([f.to_dict() for f in fs])
        for v in (AWS, GH, SLACK, STRIPE):
            self.assertNotIn(v, blob)
            # Known prefix-leak path (old preview kept 4 secret characters).
            self.assertNotIn(v[:4], blob)
        for f in fs:
            self.assertTrue(f.preview.startswith("[REDACTED] "))
            self.assertIn(f"id={f.fingerprint}", f.preview)

    def test_context_masks_secret(self):
        fs = scan.scan_text(f"password = '{GH}'\n", "f", show_context=True)
        self.assertTrue(fs and all(GH not in (f.context or "") for f in fs))
        self.assertTrue(all(GH[:4] not in (f.context or "") for f in fs))
        self.assertIn("[REDACTED]", fs[0].context)

    def test_generic_entropy(self):
        hi = "Zk3pQ9xLm2Vn8RtYw4Hc7BfD"
        hi_hits = scan.scan_text(f'api_key = "{hi}"\n', "k.env")
        self.assertTrue(hi_hits)
        hi_blob = json.dumps([f.to_dict() for f in hi_hits])
        self.assertNotIn(hi, hi_blob)
        self.assertNotIn(hi[:4], hi_blob)
        self.assertFalse(scan.scan_text('api_key = "aaaaaaaaaaaaaaaaaaaaaaaa"\n'))       # low entropy
        self.assertFalse(scan.scan_text('api_key = "your_api_key_goes_here_xx"\n'))      # placeholder
        self.assertFalse(scan.scan_text('token = "%s"\n' % ("a1b2c3d4" * 8)))            # plain hex hash

    def test_ignore_tag_and_clean(self):
        self.assertFalse(scan.scan_text(f"x={AWS} # afk-guard:ignore\n"))
        self.assertFalse(scan.scan_text("hello world\nnothing here\n"))

    def test_scan_dir_skips_noise(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "node_modules"))
            w(os.path.join(d, "node_modules", "a.txt"), AWS)
            w(os.path.join(d, "b.env"), f"K={AWS}\n")
            w(os.path.join(d, "c.bin"), b"\x00\x01" + AWS.encode(), "wb")
            res = [f for fs, _ in scan.scan_paths([d]) for f in fs]
            self.assertEqual(len(res), 1)
            self.assertTrue(res[0].path.endswith("b.env"))

    def test_location_fingerprint_has_no_value_dedupe(self):
        # Same fake secret, two paths: fingerprints differ (no cross-file value dedupe).
        one = scan.scan_text(f"k={AWS}\n", "one.env")
        two = scan.scan_text(f"k={AWS}\n", "two.env")
        self.assertNotEqual(one[0].fingerprint, two[0].fingerprint)
        # Two different values, same rule, same line: one fingerprint (collision accepted).
        other = "AKIA" + "ZZZZZZZZ" + "YYYYYYYY"
        same = scan.scan_text(f"k={AWS} k={other}\n", "box.env")
        aws = [f for f in same if f.rule == "aws-access-key-id"]
        self.assertGreaterEqual(len(aws), 2)
        self.assertEqual({f.fingerprint for f in aws}, {aws[0].fingerprint})
        blob = json.dumps([f.to_dict() for f in same])
        self.assertNotIn(AWS, blob)
        self.assertNotIn(other, blob)
        self.assertNotIn(AWS[:4], blob)

    def test_exclude(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "skipme"))
            w(os.path.join(d, "skipme", "a.env"), f"K={AWS}\n")
            self.assertEqual([f for fs, _ in scan.scan_paths([d], exclude=[os.path.join(d, "skipme")]) for f in fs], [])


class CanaryTests(unittest.TestCase):
    def test_plant_scan_check(self):
        with tempfile.TemporaryDirectory() as d:
            planted = canary.plant(d)
            self.assertEqual({p["kind"] for p in planted}, set(canary.KINDS))
            # scanner recognises canaries and does not count them as real findings
            fs = [f for x, _ in scan.scan_paths([d]) for f in x]
            self.assertTrue(fs)
            self.assertTrue(all(f.canary for f in fs))
            self.assertEqual(canary.check(d), [])
            # tamper, delete, and use in a log
            c0, c1 = planted[0], planted[1]
            w(os.path.join(d, c0["file"]), "x", "a")
            os.remove(os.path.join(d, c1["file"]))
            log = os.path.join(d, "access.log")
            w(log, "GET / token=" + planted[2]["marker"] + "\n")
            types = {(a["type"], a.get("id")) for a in canary.check(d, [log])}
            self.assertIn(("modified", c0["id"]), types)
            self.assertIn(("missing", c1["id"]), types)
            self.assertIn(("seen-in-log", planted[2]["id"]), types)

    def test_plant_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            w(os.path.join(d, "github-token.txt"), "mine")
            canary.plant(d, ["github"])
            self.assertEqual(r(os.path.join(d, "github-token.txt")), "mine")

    def test_listener_logs_hit(self):
        with tempfile.TemporaryDirectory() as d:
            planted = canary.plant(d, ["github"])
            s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            log = os.path.join(d, "hits.jsonl")
            t = threading.Thread(target=canary.listen, args=(port, log, "127.0.0.1", 1), daemon=True)
            t.start(); time.sleep(0.3)
            urllib.request.urlopen(f"http://127.0.0.1:{port}/c/{planted[0]['id']}").read()
            t.join(3)
            self.assertIn("callback-hit", {a["type"] for a in canary.check(d, listener_log=log)})


class McpCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adv = mcpcheck.load_advisories()
        cls.servers = []
        for fn in ("cursor-mcp.json", "openclaw.json", "codex-config.toml"):
            s, _ = mcpcheck.parse_config(os.path.join(FIX, fn))
            cls.servers += s
        cls.hits = mcpcheck.check_servers(cls.servers, cls.adv)

    def verdict(self, server):
        return {h.verdict for h in self.hits if h.server == server}

    def test_db_has_sources(self):
        for a in self.adv["advisories"]:
            self.assertTrue(a["source"] and a["source_url"].startswith("http"), a["id"])
        self.assertGreaterEqual(len(self.adv["advisories"]), 20)

    def test_versions(self):
        self.assertEqual(self.verdict("inspector"), {"affected"})
        self.assertEqual(self.verdict("inspector-fixed"), set())
        self.assertEqual(self.verdict("obsidian"), {"check-version"})
        self.assertEqual(self.verdict("bad-skill"), {"affected"})
        self.assertEqual(self.verdict("lite"), {"affected"})
        self.assertEqual(self.verdict("n8n-mid"), {"affected"})
        self.assertEqual(self.verdict("gitbook"), {"present"})
        self.assertEqual(self.verdict("fs"), {"check-version"})
        if mcpcheck._toml is None:
            self.assertEqual(self.verdict("fastmcp-thing"), set())
        else:
            self.assertEqual(self.verdict("fastmcp-thing"), {"affected"})
        self.assertEqual(self.verdict("safe"), set())

    def test_verdict_rules(self):
        r = {"kind": "vuln", "fixed_in": ["2.42.6", "2.43.3", "3.0.1"]}
        v = lambda x: mcpcheck._verdict(r, x)[0]
        self.assertEqual(v("2.42.0"), "affected")
        self.assertEqual(v("2.42.7"), "not-affected")
        self.assertEqual(v("2.43.2"), "affected")
        self.assertEqual(v("2.44.0"), "not-affected")
        self.assertEqual(v("3.0.0"), "affected")
        self.assertEqual(v("3.1.0"), "not-affected")
        self.assertEqual(v("1.9.0"), "affected")
        self.assertEqual(v(""), "check-version")
        self.assertEqual(v("latest"), "check-version")
        rng = {"kind": "malicious", "affected_range": ["1.0.8", "1.0.10"]}
        self.assertEqual(mcpcheck._verdict(rng, "1.0.9")[0], "affected")
        self.assertEqual(mcpcheck._verdict(rng, "1.0.11")[0], "not-affected")

    def test_hits_cite_source(self):
        for h in self.hits:
            self.assertTrue(h.source and h.source_url)

    def test_openclaw_version(self):
        cfg = [os.path.join(FIX, "openclaw.json")]
        self.assertTrue(mcpcheck.openclaw_hits(cfg, self.adv, None))
        old = mcpcheck.openclaw_hits(cfg, self.adv, "2026.5.1")
        self.assertIn("affected", {h.verdict for h in old if h.advisory_id.startswith("afk-")})
        new = mcpcheck.openclaw_hits(cfg, self.adv, "2026.7.0")
        self.assertFalse([h for h in new if h.advisory_id.startswith("afk-")])

    def test_package_parsing(self):
        S = mcpcheck.Server
        self.assertEqual(mcpcheck.package_of(S("f", "n", "npx", ["-y", "@a/b@1.2.3"], "", [], "c")), ("npm", "@a/b", "1.2.3"))
        self.assertEqual(mcpcheck.package_of(S("f", "n", "uvx", ["--from", "x", "pkg==2.0"], "", [], "c"))[1], "pkg")
        self.assertIsNone(mcpcheck.package_of(S("f", "n", "/usr/bin/foo", [], "", [], "c")))

    def test_hygiene_no_secret_values(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "mcp.json")
            w(p, json.dumps({"mcpServers": {"x": {"command": "npx", "args": ["foo"], "env": {"T": GH}}}}))
            s, _ = mcpcheck.parse_config(p)
            hy = mcpcheck.hygiene(s, [p])
            self.assertTrue({h["check"] for h in hy} >= {"plaintext-secret-in-config", "unpinned-package"})
            hy_blob = json.dumps(hy)
            self.assertNotIn(GH, hy_blob)
            self.assertNotIn(GH[:4], hy_blob)


class CliTests(unittest.TestCase):
    def test_cli_scan_counts_only_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            w(os.path.join(d, "a.env"), f"K={AWS}\n")
            self.assertEqual(cli.main(["scan", d, "--counts-only"]), 1)
            self.assertEqual(cli.main(["scan", d, "--counts-only", "--exit-zero"]), 0)

    def test_scan_stdout_and_json_hide_known_prefixes(self):
        # Known prefix-leak paths: JSON findings and text stdout, including context.
        with tempfile.TemporaryDirectory() as d:
            w(os.path.join(d, "a.env"), f"K={AWS}\nT={GH}\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(cli.main(["scan", d, "--format", "json"]), 1)
            js = buf.getvalue()
            self.assertNotIn(AWS, js)
            self.assertNotIn(GH, js)
            self.assertNotIn(AWS[:4], js)
            self.assertNotIn(GH[:4], js)
            text_buf = io.StringIO()
            with redirect_stdout(text_buf):
                self.assertEqual(cli.main(["scan", d, "--show-context"]), 1)
            text = text_buf.getvalue()
            self.assertNotIn(AWS, text)
            self.assertNotIn(GH, text)
            self.assertNotIn(AWS[:4], text)
            self.assertNotIn(GH[:4], text)
            self.assertIn("[REDACTED]", text)

    def test_cli_mcp_check(self):
        self.assertEqual(cli.main(["mcp-check", FIX, "--no-discover", "--exit-zero", "--format", "json"]), 0)


class PreviewTests(unittest.TestCase):
    def test_inventory_preview_flags(self):
        from afk_guard import preview_inventory as pi
        res = pi.analyze(pi.load(os.path.join(os.path.dirname(HERE), "test-fixtures", "preview", "sample-inventory.json")))
        self.assertTrue(res["example_data"])
        by = {r["agent"]: r for r in res["grants"]}
        self.assertIn("send", by["Example Mail Helper"]["caps"])
        self.assertIn("publish", by["Example Release Bot"]["caps"])
        self.assertIn("pay", by["Example Billing Agent (restricted key)"]["caps"])
        self.assertTrue(by["Example Billing Agent (restricted key)"]["stopped"].startswith("NOT STOPPED"))
        self.assertTrue(by["Example Old Calendar Sync"]["stopped"].startswith("GRANT STILL LISTED"))
        self.assertEqual(by["Example Notes Agent"]["caps"], [])
        self.assertIn("stripe", res["revoke_list"])

    def test_inventory_rejects_bad_file(self):
        from afk_guard import preview_inventory as pi
        with tempfile.TemporaryDirectory() as d:
            w(os.path.join(d, "x.json"), "[]")
            with self.assertRaises(ValueError):
                pi.load(os.path.join(d, "x.json"))


if __name__ == "__main__":
    unittest.main()
