"""C3 pin, content-hash drift, and pin-file safety. Fake configs only. No network."""
import hashlib
import io
import json
import os
import socket
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from afk_guard import __version__, canary, cli, mcpcheck

PKG = "example-pin-fixture"
OTHER = "example-other-fixture"
VER_TOKEN = "ZZVERTOKEN99"
URL_SECRET = "ZZURLSECRET"
ARG_SECRET = "ZZARGSECRET99"
ARG_SECRET_2 = "ZZARGSECRET98"
BODY_TOKEN = "ZZBODYTOKEN"
WHEN = "2026-11-05T00:00:00Z"
# Assembled at runtime. Not a live credential.
GH = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"


def _read(path):
    with open(path) as fh:
        return fh.read()


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _write(path, servers, groups=None):
    if groups is None:
        payload = {"mcpServers": servers}
    else:
        payload = groups
    with open(path, "w") as fh:
        json.dump(payload, fh)


def _server(version="1.0.0", extra=None, env=None, command="npx", spec="at"):
    if spec == "eq":
        args = [f"{PKG}=={version}"]
        command = "uvx"
    else:
        args = ["-y", f"{PKG}@{version}"]
    if extra:
        args.extend(extra)
    item = {"command": command, "args": args}
    if env:
        item["env"] = env
    return item


def _absent(testcase, token, *blobs):
    for blob in blobs:
        testcase.assertNotIn(token, blob)
        testcase.assertNotIn(hashlib.sha256(token.encode()).hexdigest(), blob)


class McpPinDriftTests(unittest.TestCase):
    def _layout(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        cfg = os.path.join(d.name, "mcp.json")
        state = os.path.join(d.name, "pins.json")
        return d.name, cfg, state

    def _check(self, home, cfg, state, extra=()):
        argv = ["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state, *extra]
        code, out, err = _run(argv)
        self.assertEqual(err, "")
        return code, json.loads(out), out

    def test_pin_record_and_env_value_excluded(self):
        home, cfg, _state = self._layout()
        _write(cfg, {"tool": _server(env={"TOKEN": GH})})
        servers, _ = mcpcheck.parse_config(cfg)
        rec = mcpcheck.pin_record(servers[0])
        self.assertEqual(rec["package"], PKG)
        self.assertEqual(rec["pin"], "1.0.0")
        self.assertEqual(rec["integrity"], "full")
        self.assertTrue(rec["content_hash"].startswith("sha256:"))
        blob = json.dumps(rec)
        self.assertNotIn(GH, blob)
        self.assertNotIn(GH[:4], blob)
        self.assertNotEqual(rec["content_hash"], "sha256:" + hashlib.sha256(GH.encode()).hexdigest())
        _write(cfg, {"tool": _server(env={"TOKEN": "ghp_" + ("c" * 36)})})
        again, _ = mcpcheck.parse_config(cfg)
        self.assertEqual(mcpcheck.content_hash(again[0]), rec["content_hash"])
        _write(cfg, {"tool": _server(env={"OTHER": GH})})
        changed, _ = mcpcheck.parse_config(cfg)
        self.assertNotEqual(mcpcheck.content_hash(changed[0]), rec["content_hash"])
        self.assertNotIn(GH, json.dumps(mcpcheck.pin_record(changed[0])))

    def test_baseline_schema_then_clean_rerun(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server()})
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 0)
        self.assertEqual(doc["schema"], "afk-guard/mcp-check/v1")
        self.assertEqual(doc["tool"], "mcp-check")
        self.assertEqual(doc["version"], __version__)
        self.assertRegex(doc["generated_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertIsInstance(doc["findings"], list)
        self.assertEqual(doc["gate"]["fail_severities"], ["high", "medium"])
        self.assertIn("pin-drift", doc["gate"]["drift_checks"])
        self.assertIn("content-hash-drift", doc["gate"]["drift_checks"])
        self.assertTrue(any(f["check"] == "pin-baseline-recorded" and f["severity"] == "info" for f in doc["findings"]))
        self.assertEqual(doc["pins"][0]["pin"], "1.0.0")
        self.assertEqual(doc["pins"][0]["integrity"], "full")
        self.assertEqual(doc["hits"], [])
        stored = _load(state)
        self.assertEqual(stored["schema"], "afk-guard/mcp-pins/v1")
        self.assertEqual(stored["tool"], "mcp-check")
        self.assertEqual(stored["version"], __version__)
        self.assertIn("generated_at", stored)
        self.assertEqual(stored["servers"][0]["pin"], "1.0.0")
        self.assertTrue(stored["servers"][0]["content_hash"].startswith("sha256:"))
        self.assertEqual(os.stat(state).st_mode & 0o777, 0o600)
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 0)
        self.assertFalse([f for f in doc["findings"] if f["severity"] in ("high", "medium")])

    def test_pin_drift_exits_nonzero(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server("1.0.0")})
        self.assertEqual(self._check(home, cfg, state)[0], 0)
        _write(cfg, {"tool": _server("1.0.1")})
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        drift = [f for f in doc["findings"] if f["check"] == "pin-drift"]
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["severity"], "high")
        self.assertIn("1.0.0", drift[0]["message"])
        self.assertIn("1.0.1", drift[0]["message"])
        self.assertEqual(drift[0]["previous_pin"], "1.0.0")
        self.assertEqual(drift[0]["pin"], "1.0.1")
        self.assertNotEqual(drift[0]["content_hash"], drift[0]["previous_content_hash"])
        stored = _load(state)
        self.assertEqual(stored["servers"][0]["pin"], "1.0.0")

    def test_content_hash_drift_same_pin(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server()})
        self._check(home, cfg, state)
        _write(cfg, {"tool": _server(extra=["--offline"])})
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        drift = [f for f in doc["findings"] if f["check"] == "content-hash-drift"]
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["severity"], "high")
        self.assertIn("unchanged", drift[0]["message"])
        self.assertEqual(drift[0]["pin"], "1.0.0")

    def test_server_added_and_removed(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server(), "other": _server()})
        self._check(home, cfg, state)
        _write(cfg, {"tool": _server(), "fresh": _server()})
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        checks = {f["check"] for f in doc["findings"] if f["severity"] == "high"}
        self.assertEqual(checks, {"server-added", "server-removed"})
        names = {f["server"]: f["check"] for f in doc["findings"] if f["severity"] == "high"}
        self.assertEqual(names["fresh"], "server-added")
        self.assertEqual(names["other"], "server-removed")

    def test_exit_zero_keeps_high_severity(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server("1.0.0")})
        self._check(home, cfg, state)
        _write(cfg, {"tool": _server("9.9.9")})
        code, doc, _raw = self._check(home, cfg, state, extra=("--exit-zero",))
        self.assertEqual(code, 0)
        self.assertTrue(any(f["check"] == "pin-drift" and f["severity"] == "high" for f in doc["findings"]))

    def test_update_pins_accepts_drift(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server("1.0.0")})
        self._check(home, cfg, state)
        _write(cfg, {"tool": _server("2.0.0")})
        code, doc, _raw = self._check(home, cfg, state, extra=("--update-pins",))
        self.assertEqual(code, 0)
        self.assertTrue(any(f["check"] == "pin-baseline-updated" and f["severity"] == "info" for f in doc["findings"]))
        self.assertFalse([f for f in doc["findings"] if f["check"] == "pin-drift"])
        self.assertEqual(_load(state)["servers"][0]["pin"], "2.0.0")
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 0)
        self.assertFalse([f for f in doc["findings"] if f["severity"] == "high"])

    def test_bad_pin_state_fails_closed(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server()})
        with open(state, "w") as fh:
            fh.write("{not json " + BODY_TOKEN)
        before = _read(state)
        code, doc, raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        self.assertTrue(any(f["check"] == "pin-state-unreadable" and f["severity"] == "high" for f in doc["findings"]))
        self.assertEqual(_read(state), before)
        _absent(self, BODY_TOKEN, raw)
        with open(state, "w") as fh:
            json.dump({"schema": "other"}, fh)
        before = _read(state)
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        self.assertTrue(any(f["check"] == "pin-state-schema" and f["severity"] == "high" for f in doc["findings"]))
        self.assertEqual(_read(state), before)
        code, doc, _raw = self._check(home, cfg, state, extra=("--update-pins",))
        self.assertEqual(code, 0)
        self.assertEqual(_load(state)["schema"], "afk-guard/mcp-pins/v1")

    def test_update_pins_requires_path(self):
        home, cfg, _state = self._layout()
        _write(cfg, {"tool": _server()})
        code, _out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--update-pins"])
        self.assertEqual(code, 2)
        self.assertIn("--pin-state", err)

    def test_text_drift_and_fixture_envelope(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server("1.0.0")})
        self._check(home, cfg, state)
        _write(cfg, {"tool": _server("1.2.0")})
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--pin-state", state])
        self.assertEqual(err, "")
        self.assertEqual(code, 1)
        self.assertIn("PIN-DRIFT", out)
        self.assertIn("pin changed", out)
        fix = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test-fixtures", "mcp")
        code, out, _err = _run(["mcp-check", fix, "--no-discover", "--home", home, "--format", "json"])
        self.assertEqual(code, 1)
        doc = json.loads(out)
        for key in ("schema", "tool", "version", "generated_at", "findings"):
            self.assertIn(key, doc)
        self.assertEqual(doc["schema"], mcpcheck.MCP_CHECK_SCHEMA)
        self.assertTrue(any(f["check"] == "advisory" for f in doc["findings"]))
        self.assertTrue(doc["pins"])
        self.assertTrue(all(p["integrity"] == "full" and p["content_hash"].startswith("sha256:") for p in doc["pins"]))

    def test_reconcile_offline(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server()})
        servers, _ = mcpcheck.parse_config(cfg)
        records = [mcpcheck.pin_record(s) for s in servers]

        def _boom(*_a, **_k):
            raise AssertionError("network used")

        with patch.object(socket, "socket", _boom), patch.object(socket, "create_connection", _boom):
            findings = mcpcheck.reconcile_pin_state(state, records, version="0.1.0", generated_at=WHEN)
        self.assertEqual(findings[0]["check"], "pin-baseline-recorded")
        self.assertEqual(findings[0]["severity"], "info")
        stored = _load(state)
        self.assertEqual(stored["generated_at"], WHEN)
        self.assertEqual(stored["schema"], "afk-guard/mcp-pins/v1")
        with patch.object(socket, "socket", _boom), patch.object(socket, "create_connection", _boom):
            again = mcpcheck.reconcile_pin_state(state, records, version="0.1.0", generated_at=WHEN)
        self.assertEqual(again, [])

    def test_umask_zero_still_mode_0600(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server()})
        old = os.umask(0)
        try:
            code, _doc, _raw = self._check(home, cfg, state)
        finally:
            os.umask(old)
        self.assertEqual(code, 0)
        self.assertEqual(stat.S_IMODE(os.stat(state).st_mode), 0o600)

    def test_loose_pin_mode_repaired_on_reread(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server()})
        self.assertEqual(self._check(home, cfg, state)[0], 0)
        os.chmod(state, 0o666)
        before = _read(state)
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 0)
        self.assertFalse([f for f in doc["findings"] if f["severity"] in ("high", "medium")])
        self.assertEqual(_read(state), before)
        self.assertEqual(stat.S_IMODE(os.stat(state).st_mode), 0o600)

    def test_unreadable_pin_and_directory_not_rewritten(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server()})
        with open(state, "w") as fh:
            fh.write("{}\n")
        # Mode 000 is unreadable even for the owner here; capture bytes before locking it.
        before = _read(state)
        os.chmod(state, 0)
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        self.assertTrue(any(f["check"] == "pin-state-unreadable" for f in doc["findings"]))
        os.chmod(state, 0o600)
        self.assertEqual(_read(state), before)
        os.remove(state)
        os.mkdir(state)
        code, _doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        self.assertTrue(os.path.isdir(state))

    def test_version_token_absent_on_refuse_and_on_drift(self):
        home, cfg, state = self._layout()
        for spec in ("at", "eq"):
            _write(cfg, {"tool": _server(VER_TOKEN, spec=spec)})
            code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
            self.assertNotEqual(code, 0, spec)
            self.assertFalse(os.path.exists(state), spec)
            _absent(self, VER_TOKEN, out, err)
            doc = json.loads(out)
            self.assertTrue(any(f["check"] == "launch-integrity-unsupported" and f["severity"] == "high" for f in doc["findings"]))
            self.assertTrue(all(p.get("integrity") == "unsupported" for p in doc["pins"]))
            self.assertTrue(all("content_hash" not in p for p in doc["pins"]))
            self.assertNotIn(VER_TOKEN, json.dumps(doc["pins"]))

        _write(cfg, {"tool": _server("1.0.0")})
        self.assertEqual(self._check(home, cfg, state)[0], 0)
        for spec, fmt in (("at", "json"), ("eq", "text")):
            _write(cfg, {"tool": _server(VER_TOKEN, spec=spec)})
            if fmt == "json":
                code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
            else:
                code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--pin-state", state])
            self.assertEqual(code, 1, spec)
            _absent(self, VER_TOKEN, out, err, _read(state))
            stored = _load(state)
            self.assertEqual(stored["servers"][0]["pin"], "1.0.0")
            self.assertNotIn(VER_TOKEN, json.dumps(stored))

    def test_package_of_drops_unrecognized_version_tail(self):
        S = mcpcheck.Server
        bad_npm = S("f", "n", "npx", ["-y", f"{PKG}@{VER_TOKEN}"], "", [], "c")
        bad_py = S("f", "n", "uvx", [f"{PKG}=={VER_TOKEN}"], "", [], "c")
        self.assertEqual(mcpcheck.package_of(bad_npm), ("npm", PKG, ""))
        self.assertEqual(mcpcheck.package_spec(bad_npm)[3], "version-syntax")
        self.assertEqual(mcpcheck.package_of(bad_py), ("pypi", PKG, ""))
        self.assertNotIn(VER_TOKEN, json.dumps(mcpcheck.package_spec(bad_npm)))
        self.assertNotIn(VER_TOKEN, json.dumps(mcpcheck.package_spec(bad_py)))
        with self.assertRaises(ValueError):
            mcpcheck.content_hash(bad_npm)

    def test_credential_arg_and_url_userinfo_fail_closed(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server(extra=["--token", ARG_SECRET])})
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(state))
        _absent(self, ARG_SECRET, out, err)
        doc = json.loads(out)
        self.assertTrue(all(p.get("integrity") == "unsupported" and "content_hash" not in p for p in doc["pins"]))
        self.assertTrue(any("credential-arg" in f["message"] for f in doc["findings"] if f["check"] == "launch-integrity-unsupported"))

        _write(cfg, {"tool": _server(extra=["--token", ARG_SECRET_2])})
        code2, out2, err2 = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
        self.assertNotEqual(code2, 0)
        self.assertFalse(os.path.exists(state))
        _absent(self, ARG_SECRET, out2, err2)
        _absent(self, ARG_SECRET_2, out2, err2)
        doc2 = json.loads(out2)
        self.assertTrue(all(p.get("integrity") != "full" for p in doc2["pins"]))

        _write(cfg, {"tool": _server()})
        self.assertEqual(self._check(home, cfg, state)[0], 0)
        before = _read(state)
        item = _server()
        item["url"] = f"https://user:{URL_SECRET}@example.test/mcp"
        _write(cfg, {"tool": item})
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
        self.assertEqual(code, 1)
        _absent(self, URL_SECRET, out, err, _read(state))
        self.assertEqual(_read(state), before)
        doc = json.loads(out)
        self.assertTrue(any("url-userinfo" in f["message"] for f in doc["findings"]))
        self.assertTrue(all("content_hash" not in p or p.get("integrity") != "full" for p in doc["pins"] if p["server"] == "tool"))

        item["url"] = f"https://user:{ARG_SECRET}@example.test/mcp"
        _write(cfg, {"tool": item})
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--pin-state", state])
        self.assertEqual(code, 1)
        _absent(self, ARG_SECRET, out, err, _read(state))
        self.assertEqual(_read(state), before)

    def test_duplicate_server_names_do_not_collapse(self):
        home, cfg, state = self._layout()
        groups = {
            "mcpServers": {"tool": {"command": "npx", "args": ["-y", f"{PKG}@1.0.0"]}},
            "mcp": {"tool": {"command": "uvx", "args": [f"{OTHER}==9.9.9"]}},
        }
        _write(cfg, None, groups=groups)
        servers, notes = mcpcheck.parse_config(cfg)
        self.assertEqual(notes, [])
        self.assertEqual(len(servers), 2)
        code, doc, raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        self.assertIn(PKG, raw)
        self.assertIn(OTHER, raw)
        self.assertEqual(len(doc["pins"]), 2)
        packages = {p["package"] for p in doc["pins"]}
        self.assertEqual(packages, {PKG, OTHER})
        self.assertEqual(len({p["server_key"] for p in doc["pins"]}), 2)
        self.assertTrue(any(f["check"] == "duplicate-server-name" and f["severity"] == "high" for f in doc["findings"]))
        stored = _load(state)
        self.assertEqual(len(stored["servers"]), 2)
        self.assertEqual({row["package"] for row in stored["servers"]}, {PKG, OTHER})

    def test_unparseable_config_does_not_record_empty_baseline(self):
        home, cfg, state = self._layout()
        with open(cfg, "w") as fh:
            fh.write("{not-json " + BODY_TOKEN)
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(state))
        _absent(self, BODY_TOKEN, out, err)
        doc = json.loads(out)
        self.assertTrue(any(f["check"] == "config-unparseable" and f["severity"] == "high" for f in doc["findings"]))
        self.assertNotIn("recorded 0", out)

        _write(cfg, {"tool": _server()})
        self.assertEqual(self._check(home, cfg, state)[0], 0)
        before = _read(state)
        with open(cfg, "w") as fh:
            fh.write("{still-not-json " + BODY_TOKEN)
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--pin-state", state])
        self.assertEqual(code, 1)
        _absent(self, BODY_TOKEN, out, err)
        self.assertEqual(_read(state), before)
        self.assertIn("SERVER-REMOVED", out)

    def test_valid_empty_config_can_record_zero(self):
        home, cfg, state = self._layout()
        _write(cfg, {})
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 0)
        self.assertTrue(any(f["check"] == "pin-baseline-recorded" and f.get("count") == 0 for f in doc["findings"]))
        self.assertEqual(_load(state)["servers"], [])

    def test_scalar_args_do_not_become_python_repr(self):
        home, cfg, _state = self._layout()
        with open(cfg, "w") as fh:
            json.dump({"mcpServers": {"tool": {
                "command": None,
                "args": [True, False, 1, {"nested": "no"}],
                "url": "https://example.test/mcp",
            }}}, fh)
        servers, _ = mcpcheck.parse_config(cfg)
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0].command, "")
        self.assertEqual(servers[0].args, ["true", "false", "1"])
        self.assertNotIn("True", servers[0].args)
        self.assertNotIn("None", servers[0].command)
        self.assertIn("nonscalar-arg", servers[0].launch_flags)
        rec = mcpcheck.pin_record(servers[0])
        self.assertEqual(rec["integrity"], "unsupported")
        self.assertNotIn("True", json.dumps(rec))
        self.assertNotIn("None", json.dumps(rec))
        self.assertNotIn("nested", json.dumps(rec))


class PathHashResidualTests(unittest.TestCase):
    """R9: path arguments stay inside a full hash. Docs must not call that secret-free."""

    def _layout(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return d.name, os.path.join(d.name, "mcp.json"), os.path.join(d.name, "pins.json")

    def _check(self, home, cfg, state):
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
        self.assertEqual(err, "")
        return code, json.loads(out), out

    def test_path_secret_is_hashed_and_not_echoed(self):
        home, cfg, state = self._layout()
        marker = "ZZPATHSECRET99"
        _write(cfg, {"tool": {"command": "npx", "args": ["-y", f"{PKG}@1.0.0", f"/tmp/{marker}"]}})
        code, doc, raw = self._check(home, cfg, state)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(state))
        pin = doc["pins"][0]
        self.assertEqual(pin["integrity"], "full")
        self.assertTrue(pin["content_hash"].startswith("sha256:"))
        _absent(self, marker, raw, _read(state))
        for i, path in enumerate((f"./secrets/{marker}", f"../{marker}", f"--config=/opt/{marker}")):
            _write(cfg, {"tool": {"command": "npx", "args": ["-y", f"{PKG}@1.0.0", path]}})
            fresh = f"{state}.{i}"
            code, doc, raw = self._check(home, cfg, fresh)
            self.assertEqual(code, 0, path)
            self.assertEqual(doc["pins"][0]["integrity"], "full")
            _absent(self, marker, raw, _read(fresh))

    def test_config_path_flag_is_full_and_path_change_drifts(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": {"command": "npx", "args": ["-y", f"{PKG}@1.0.0", "--config=/opt/example/config.json"]}})
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 0)
        self.assertEqual(doc["pins"][0]["integrity"], "full")
        first = doc["pins"][0]["content_hash"]
        _write(cfg, {"tool": {"command": "npx", "args": ["-y", f"{PKG}@1.0.0", "--config=/opt/example/other.json"]}})
        code, doc, _raw = self._check(home, cfg, state)
        self.assertEqual(code, 1)
        self.assertTrue(any(f["check"] == "content-hash-drift" for f in doc["findings"]))
        self.assertNotEqual(doc["pins"][0]["content_hash"], first)

    def test_token_and_url_secrets_stay_unsupported(self):
        home, cfg, state = self._layout()
        _write(cfg, {"tool": _server(extra=["--token", ARG_SECRET])})
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(state))
        _absent(self, ARG_SECRET, out, err)
        item = {"command": "npx", "args": ["-y", f"{PKG}@1.0.0"], "url": f"https://user:{URL_SECRET}@example.test/mcp"}
        _write(cfg, {"tool": item})
        code, out, err = _run(["mcp-check", cfg, "--no-discover", "--home", home, "--format", "json", "--pin-state", state])
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(state))
        _absent(self, URL_SECRET, out, err)

    def test_docs_say_full_includes_paths_and_is_not_secret_free(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "README.md")) as fh:
            readme = fh.read()
        self.assertIn("not a secret-free claim over path strings", readme)
        self.assertIn("includes path arguments", readme)
        self.assertIn("not a secret-free claim over path strings", mcpcheck._HASH_COVERAGE)
        self.assertIn("Path arguments are included", mcpcheck._HASH_COVERAGE)


class CanaryRegistryModeTests(unittest.TestCase):
    def test_registry_is_owner_only_and_has_no_value_hash(self):
        with tempfile.TemporaryDirectory() as d:
            planted = canary.plant(d, ["github"])
            reg_path = os.path.join(d, canary.REGISTRY_NAME)
            self.assertEqual(stat.S_IMODE(os.stat(reg_path).st_mode), 0o600)
            blob = _read(reg_path)
            self.assertNotIn("value_sha256", blob)
            self.assertNotIn("value_sha256", planted[0])
            decoy = os.path.join(d, planted[0]["file"])
            self.assertEqual(stat.S_IMODE(os.stat(decoy).st_mode), 0o600)
            with open(decoy, "rb") as fh:
                file_hash = hashlib.sha256(fh.read()).hexdigest()
            self.assertEqual(planted[0]["sha256"], file_hash)


if __name__ == "__main__":
    unittest.main()
