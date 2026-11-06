"""DEF-006: show-context must mask the union of overlapping spans.

Fake fixtures only. The marker is not a credential. Do not claim every
one-character secret is absent; assert the known spans and the marker.
"""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from afk_guard import cli, scan
from afk_guard.redact import redact_line

MARKER = "TAILMARK99"


def _jwt_line():
    header = "eyJ" + ("A" * 20)
    payload = "eyJ" + ("B" * 20)
    signature = "C" * 20
    jwt = f"{header}.{payload}.{signature}"
    return f"Bearer {jwt}.{MARKER}", jwt


class RedactSpanUnionTests(unittest.TestCase):
    def test_order_overlap_containment_and_adjacency(self):
        line = "0123456789"
        cases = [
            ([(0, 4), (2, 8)], "[REDACTED]89"),
            ([(2, 8), (0, 4)], "[REDACTED]89"),
            ([(0, 8), (2, 4)], "[REDACTED]89"),
            ([(0, 3), (0, 7)], "[REDACTED]789"),
            ([(0, 7), (0, 3)], "[REDACTED]789"),
            ([(1, 4), (1, 4)], "0[REDACTED]456789"),
            ([(0, 3), (3, 6)], "[REDACTED]6789"),
            ([(0, 2), (4, 6)], "[REDACTED]23[REDACTED]6789"),
            ([(4, 6), (0, 2)], "[REDACTED]23[REDACTED]6789"),
        ]
        for spans, expected in cases:
            self.assertEqual(redact_line(line, spans), expected, spans)
            self.assertEqual(redact_line(line, list(reversed(spans))), expected, spans)

    def test_offset_overlap_hides_the_longer_tail(self):
        # The old loop kept the suffix of a span that started inside an earlier one.
        line = "AAAA" + MARKER + "ZZ"
        short = (0, 4)
        longer = (2, 4 + len(MARKER))
        for spans in ((short, longer), (longer, short)):
            out = redact_line(line, spans)
            self.assertNotIn(MARKER, out)
            self.assertNotIn("AAAA", out)
            self.assertTrue(out.endswith("ZZ"))
            self.assertIn("[REDACTED]", out)


class ShowContextOverlapTests(unittest.TestCase):
    def test_scan_masks_bearer_tail_past_jwt(self):
        line, jwt = _jwt_line()
        findings = scan.scan_text(line + "\n", "o.env", show_context=True)
        rules = {f.rule for f in findings}
        self.assertIn("jwt", rules)
        self.assertIn("bearer-token", rules)
        blob = json.dumps([f.to_dict() for f in findings])
        self.assertNotIn(MARKER, blob)
        self.assertNotIn(jwt, blob)
        self.assertTrue(all(MARKER not in (f.context or "") for f in findings))
        self.assertTrue(all("[REDACTED]" in (f.context or "") for f in findings))
        bare = scan.scan_text(line + "\n", "o.env", show_context=False)
        bare_blob = json.dumps([f.to_dict() for f in bare])
        self.assertNotIn(MARKER, bare_blob)
        self.assertNotIn(jwt, bare_blob)
        self.assertTrue(all(f.context is None for f in bare))

    def test_cli_json_and_text_hide_marker(self):
        line, jwt = _jwt_line()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "o.env")
            with open(path, "w") as fh:
                fh.write(line + "\n")
            for argv in (
                ["scan", path, "--format", "json", "--show-context"],
                ["scan", path, "--show-context"],
                ["scan", path, "--format", "json"],
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = cli.main(argv)
                text = buf.getvalue()
                self.assertEqual(code, 1, argv)
                self.assertNotIn(MARKER, text)
                self.assertNotIn(jwt, text)
                self.assertIn("[REDACTED]", text)


if __name__ == "__main__":
    unittest.main()
