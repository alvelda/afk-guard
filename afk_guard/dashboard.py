"""Self-contained local HTML evidence report. Offline: no network, no CDN, no font files.

The page is a single HTML file (inline CSS, inline SVG, one JSON block). It opens
from disk. Findings show a fixed ``[REDACTED]`` token, a length bucket, and a
location fingerprint (sha256 of rule, path, and line). Secret prefixes and
secret-derived fingerprints are not written. An integer ``length`` on a dashboard
fixture still selects this file's display bucket. Core ``len=`` / ``length_bucket``
labels are passed through when the input already has them. Those label sets are
not the same scale; this module does not claim they are equivalent.

This file does not change ``scan.py`` or ``redact.py``. DEF-006 is closed there:
redacted findings show no secret prefix, and ``--show-context`` masks the union
of overlapping spans. This page displays that redacted form.

Accepted inputs (anything else is an error, and no HTML is written):

- ``afk-guard/dashboard-html/v1`` manifest
- ``afk-guard/scan/v1``, or schema-less scan JSON with ``findings`` plus
  ``files_scanned``, ``total_real``, or ``counts``
- ``afk-guard/inject-check/v1``, or schema-less JSON with ``tool: inject-check``
- ``afk-guard/mcp-check/v1``, or schema-less mcp-check JSON with ``hits``,
  ``extension_hits``, or ``advisory_db``
- ``afk-guard/canary/v1``, or schema-less canary JSON with ``alerts`` / ``planted``

``afk-guard/mcp-check/v1`` is displayed when a document already carries it.
This branch does not modify the mcp-check emitter. Pin and drift rows show up
only when that document includes them.

Output replaces the final directory entry. The HTML is created with
``O_EXCL | O_NOFOLLOW`` in the destination directory, then ``os.replace`` on
that directory descriptor. A symlink at the destination is not opened, so its
target is not truncated. Parent-path races are not claimed closed.

Manifest schema: ``afk-guard/dashboard-html/v1``.
The report stamp matches the EXAMPLE visual reference: ``afk-guard.report.v1``.

Narrow layout follows the patched EXAMPLE mock: findings stack to one column
at 640px, the page hides horizontal overflow, focus rings are orange, the
first findings row is at least 44px, and data tables sit in a scroll wrapper.
"""
import hashlib
import html
import json
import os
import re
import secrets
from typing import Dict, Iterable, List, Optional

from . import __version__
from .scan import RULES

SCHEMA = "afk-guard/dashboard-html/v1"
REPORT_SCHEMA = "afk-guard.report.v1"
SCAN_SCHEMA = "afk-guard/scan/v1"
INJECT_SCHEMA = "afk-guard/inject-check/v1"
MCP_SCHEMA = "afk-guard/mcp-check/v1"
CANARY_SCHEMA = "afk-guard/canary/v1"
_SECTION_KEYS = ("scan", "canary", "mcp", "inject", "drift")
HONESTY = "Clean ≠ safe. Absence of logs ≠ stopped. Secrets redacted."
SIZE_WARN = 1_500_000
SIZE_TARGET = 400_000

KILL_LABEL = "Kill switch: n/a on free CLI"
KILL_NOTE = "(report-only; no trip control in this offer)."

_SKIP = {
    "scan": "No scan JSON was provided. The scanner did not run for this file.",
    "canary": "No canary check JSON was provided. Planted markers were not compared.",
    "mcp": "No mcp-check JSON was provided. Advisory match did not run.",
    "drift": "No MCP drift JSON was provided. Pin and content-hash compare did not run.",
    "inject": "No inject-check JSON was provided. That check is not in this report.",
}

_SEV_META = {
    "critical": ("CRITICAL", "▦", "afk-sev-critical", "#e24a2b"),
    "high": ("HIGH", "▲", "afk-sev-high", "#ff8a00"),
    "medium": ("MEDIUM", "●", "afk-sev-medium", "#e6b84d"),
    "low": ("LOW", "ℹ", "afk-sev-info", "#b3ad98"),
    "info": ("INFO", "ℹ", "afk-sev-info", "#b3ad98"),
    "pass": ("PASS", "✓", "afk-sev-pass", "#c9d33b"),
}
_BAR_ORDER = ("critical", "high", "medium", "low", "info")
_BAR_SHORT = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "pass": 5}
_LEN_RE = re.compile(r"\[(\d+)\s*chars?\]", re.I)
_R1_LEN_RE = re.compile(r"\blen=([^\s]+)")
_BUCKET_EQ_RE = re.compile(r"\bbucket=([^\s]+)")
# Legacy preview shapes. A truncated prefix is still secret-derived, so the
# whole token including an ellipsis and a "[N chars]" tail is removed.
# Case-sensitive on purpose: core prefixes are fixed ("ghp_", "AKIA").
_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"gh[pousr]_[A-Za-z0-9]*"
    r"|github_pat_[A-Za-z0-9_]*"
    r"|(?:AKIA|ASIA)[A-Z0-9]*"
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]*"
    r"|xox[abposr]-[A-Za-z0-9-]*"
    r"|sk-ant-[A-Za-z0-9_-]*"
    r"|xai-[A-Za-z0-9]*"
    r"|AIza[0-9A-Za-z_-]*"
    r")(?:…|\.{2,3})?(?:\[\d+\s*chars?\])?"
)
_DROP_KEYS = {
    "value", "secret", "token", "password", "api_key", "raw", "credential",
    "marker", "preview", "fingerprint", "value_sha256", "aws_secret_access_key",
}
_BUCKETS = (
    (12, "1-11"),
    (20, "12-19"),
    (32, "20-31"),
    (48, "32-47"),
    (64, "48-63"),
    (128, "64-127"),
)

_NEXT = {
    "critical": "Treat the match as urgent. Rotate or remove it, then re-scan. This report does not change files.",
    "high": "Rotate the credential at the provider. The path is the location. This report does not change files.",
    "medium": "Check whether the match is live, then rotate it if it is. This report does not change files.",
    "low": "Confirm the match before ignoring it. This report does not change files.",
    "info": "This row is a limit or a label gap, not a secret preview.",
}


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _bucket(n: Optional[int]) -> str:
    if not isinstance(n, int) or n <= 0:
        return "unknown"
    for limit, name in _BUCKETS:
        if n < limit:
            return name
    return "128+"


def _secret_spans(text: str):
    spans = []
    for _rule, _sev, _desc, cre, group in RULES:
        for match in cre.finditer(text):
            spans.append(match.span(group) if match.group(group) is not None else match.span())
    spans.sort()
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def scrub_text(text: str) -> str:
    """Replace secret-shaped spans. Does not keep a prefix of the secret.

    Full matches of ``scan.RULES`` are removed, then leftover legacy prefixes
    (``ghp_``, ``AKIA``, and the same family, including ``…[N chars]`` tails).
    """
    if not isinstance(text, str) or not text:
        return "" if text is None else str(text)
    spans = _secret_spans(text)
    if spans:
        out, last = [], 0
        for start, end in spans:
            out.append(text[last:start])
            out.append("[REDACTED]")
            last = end
        out.append(text[last:])
        text = "".join(out)
    return _PREFIX_RE.sub("[REDACTED]", text)


def _looks_secret(text: str) -> bool:
    return bool(text) and bool(_secret_spans(text))


def location_fingerprint(rule: str, path: str, line) -> str:
    """Short id of the location only. The secret value is not an input."""
    blob = f"{rule}|{path}|{line}".encode("utf-8", "replace")
    return hashlib.sha256(blob).hexdigest()[:12]


def _explicit_length(raw: dict) -> Optional[int]:
    """Author-supplied integer only. Never the length of a secret preview."""
    if isinstance(raw.get("length"), int) and not isinstance(raw.get("length"), bool) and raw["length"] > 0:
        return raw["length"]
    return None


def _bucket_label(raw: dict) -> Optional[str]:
    """Bucket text for display. Core labels pass through; integers use the fixture scale."""
    for key in ("length_bucket", "bucket"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return scrub_text(value.strip())
    preview = raw.get("preview")
    if isinstance(preview, str):
        match = _R1_LEN_RE.search(preview) or _BUCKET_EQ_RE.search(preview)
        if match:
            return scrub_text(match.group(1))
        legacy = _LEN_RE.search(preview)
        if legacy:
            return _bucket(int(legacy.group(1)))
    length = _explicit_length(raw)
    if length is not None:
        return _bucket(length)
    return None


def _sev(value, default="info") -> str:
    named = _named_sev(value)
    return named if named is not None else default


def _named_sev(value) -> Optional[str]:
    """Map a severity word. Unknown and empty stay unknown (never an implied pass)."""
    if value is None:
        return None
    key = str(value).strip().lower()
    if not key:
        return None
    if key in ("med",):
        return "medium"
    if key in _SEV_META:
        return key
    return None


def present_finding(raw: dict) -> dict:
    """R1 view of one finding. The returned dict has no secret characters."""
    rule = scrub_text(str(raw.get("rule") or "unspecified"))
    path = scrub_text(str(raw.get("path") or raw.get("file") or ""))
    line = raw.get("line") if isinstance(raw.get("line"), int) else 0
    display = scrub_text(str(raw.get("display_path") or path))
    sev = _sev(raw.get("sev") or raw.get("severity"))
    if raw.get("canary") and sev == "info":
        sev = "low"
    length = _explicit_length(raw)
    preview = raw.get("preview") if isinstance(raw.get("preview"), str) else ""
    bucket = _bucket_label(raw)
    secretish = bool(bucket) or _looks_secret(preview) or bool(_PREFIX_RE.search(preview)) or (
        preview.startswith("[REDACTED]") and ("len=" in preview or "bucket=" in preview)
    )
    if secretish and not bucket:
        bucket = "unknown"
    why = scrub_text(str(raw.get("why") or raw.get("description") or ""))
    nxt = scrub_text(str(raw.get("next") or ""))
    if not nxt:
        nxt = _NEXT.get(sev, _NEXT["info"])
    if raw.get("canary"):
        why = why or "This match is a planted canary. It is a decoy, not a vendor credential."
        nxt = "The value is fake and contacts no vendor. An alert means something touched the decoy."
    return {
        "sev": sev,
        "rule": rule,
        "rule_code": scrub_text(str(raw.get("rule_code") or "")),
        "path": path,
        "display_path": display,
        "line": line,
        "canary": bool(raw.get("canary")),
        "length": length,
        "bucket": bucket if secretish else None,
        "redacted": bool(secretish),
        "fingerprint": location_fingerprint(rule, path, line),
        "fingerprint_kind": "location",
        "why": why,
        "next": nxt,
    }


def _read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def example_manifest() -> dict:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "dashboard-example.json")
    return _read_json(path)


def _as_dict(value, kind: str) -> dict:
    if value is None:
        return {}
    if isinstance(value, str):
        value = _read_json(value)
    if isinstance(value, list):
        if kind == "canary":
            return {"alerts": value}
        if kind == "scan":
            return {"findings": value}
        raise ValueError(f"{kind} JSON must be an object")
    if not isinstance(value, dict):
        raise ValueError(f"{kind} JSON must be an object")
    return value


def _is_manifest_shape(data: dict) -> bool:
    if isinstance(data.get("tiles"), dict):
        return True
    return any(isinstance(data.get(key), (dict, list, str)) for key in _SECTION_KEYS)


def _looks_scan(data: dict) -> bool:
    has_count = any(key in data for key in ("files_scanned", "total_real", "counts"))
    if not has_count:
        return False
    if "findings" in data and not isinstance(data.get("findings"), list):
        return False
    return True


def _looks_mcp(data: dict) -> bool:
    return any(key in data for key in ("advisory_db", "hits", "extension_hits"))


def _looks_inject(data: dict) -> bool:
    return data.get("tool") == "inject-check" and isinstance(data.get("findings"), list)


def _looks_canary(data: dict) -> bool:
    if "findings" in data or _looks_scan(data) or _looks_mcp(data):
        return False
    return any(key in data for key in ("alerts", "planted", "canaries"))


def _wrap_kind(kind: str, doc: dict) -> dict:
    """Nest one CLI document under a dashboard manifest. Does not mark it EXAMPLE."""
    outer = {"schema": SCHEMA, kind: doc, "example": False}
    if isinstance(doc, dict):
        generated = doc.get("generated_at")
        if isinstance(generated, str) and generated:
            outer["generated_at"] = generated
        if kind == "inject" and isinstance(doc.get("source"), str) and doc["source"]:
            outer["workspace"] = doc["source"]
    return outer


def _reject_input(reason: str) -> None:
    raise ValueError(
        "unsupported dashboard input: "
        + reason
        + " Supported schemas: afk-guard/dashboard-html/v1, afk-guard/scan/v1, "
        "afk-guard/inject-check/v1, afk-guard/mcp-check/v1, afk-guard/canary/v1. "
        "No HTML was written."
    )


def _coerce_input(data: dict) -> dict:
    """Accept one documented envelope. Ambiguous or unknown shapes raise.

    A top-level ``findings`` array is not enough. Raw scan JSON is wrapped only
    when it also has scan counters (or schema ``afk-guard/scan/v1``). Inject and
    mcp-check documents are wrapped on their own schema so their findings are
    not mistaken for an empty dashboard manifest.
    """
    if isinstance(data, list):
        _reject_input("top-level JSON array.")
    if not isinstance(data, dict):
        _reject_input("JSON must be an object.")
    schema = data.get("schema")
    if schema is None:
        schema = ""
    elif not isinstance(schema, str):
        _reject_input("schema is not a string.")
    if schema == SCHEMA or (schema == REPORT_SCHEMA and _is_manifest_shape(data)):
        return data
    if schema == REPORT_SCHEMA:
        _reject_input("afk-guard.report.v1 is the HTML stamp, not an input envelope.")
    if schema == SCAN_SCHEMA:
        return _wrap_kind("scan", data)
    if schema == INJECT_SCHEMA:
        return _wrap_kind("inject", data)
    if schema == MCP_SCHEMA:
        return _wrap_kind("mcp", data)
    if schema == CANARY_SCHEMA:
        return _wrap_kind("canary", data)
    if schema:
        _reject_input(f"schema {schema!r} is not accepted.")
    if _is_manifest_shape(data):
        return data
    scan_like = _looks_scan(data)
    mcp_like = _looks_mcp(data)
    if scan_like and mcp_like:
        _reject_input("object matches both scan and mcp-check shapes.")
    if scan_like:
        return _wrap_kind("scan", data)
    if _looks_inject(data):
        return _wrap_kind("inject", data)
    if mcp_like:
        return _wrap_kind("mcp", data)
    if _looks_canary(data):
        return _wrap_kind("canary", data)
    if "findings" in data:
        _reject_input(
            "findings array has no scan, inject-check, or mcp-check schema. "
            "Refusing to drop it."
        )
    _reject_input("unrecognized object.")


def _state_chip(state: str) -> str:
    if state == "Ran-fail":
        return "Ran-fail"
    if state == "Ran-pass":
        return "Ran-pass"
    return "Not-run"


def _highest(findings: List[dict]) -> str:
    if not findings:
        return "info"
    return min((f["sev"] for f in findings), key=lambda s: _RANK.get(s, 9))


def _tile(command, state, sev, big, sub, proof, href, chip="") -> dict:
    return {
        "id": command,
        "title": {"scan": "Scan", "canary": "Canary", "mcp": "MCP", "inject": "Inject"}[command],
        "state": state,
        "sev": sev,
        "big": big,
        "sub": scrub_text(sub),
        "proof": scrub_text(proof),
        "href": href,
        "chip": scrub_text(chip),
    }


def _scan_failed(scan: dict, findings: List[dict]) -> bool:
    """True when real findings exist or ``total_real`` disagrees with them.

    A declared ``total_real`` of 0 does not clear a finding that is actually
    in the list, and a positive ``total_real`` with an empty list is not a pass.
    """
    real = [f for f in findings if not f.get("canary")]
    declared = scan.get("total_real") if isinstance(scan, dict) else None
    if real:
        return True
    if isinstance(declared, int) and not isinstance(declared, bool) and declared != 0:
        return True
    counts = scan.get("counts") if isinstance(scan, dict) else None
    if isinstance(counts, dict):
        for key, value in counts.items():
            if str(key).lower() == "canary":
                continue
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                return True
    return False


def _scan_tile(scan: dict, findings: List[dict]) -> dict:
    if not scan and not findings:
        return _tile("scan", "Not-run", "", "—", _SKIP["scan"], "exit skip · " + _SKIP["scan"], "#find-h")
    real = [f for f in findings if not f.get("canary")]
    failed = _scan_failed(scan, findings)
    state = "Ran-fail" if failed else "Ran-pass"
    sev = _highest(real) if failed else "pass"
    proof_f = next((f for f in findings if not f.get("canary")), findings[0] if findings else None)
    if proof_f and proof_f.get("redacted"):
        proof = f"exit {1 if failed else 0} · {proof_f['rule']} · {proof_f['display_path']}:{proof_f['line']} · [REDACTED] · bucket {proof_f['bucket']}"
    elif proof_f:
        proof = f"exit {1 if failed else 0} · {proof_f['rule']} · {proof_f['display_path']}:{proof_f['line']}"
    elif failed:
        proof = (
            f"exit 1 · total_real {scan.get('total_real')!s} does not match "
            f"{len(real)} findings in this JSON"
        )
    else:
        proof = f"exit 0 · rules ran · {scan.get('files_scanned', 0)} files in this JSON · no real finding"
    big = str(len(findings))
    return _tile("scan", state, sev, big, proof, proof, "#find-h")


def _canary_tile(canary: dict) -> dict:
    if not canary:
        return _tile("canary", "Not-run", "", "—", _SKIP["canary"], "exit skip · " + _SKIP["canary"], "#canary-h")
    alerts = canary.get("alerts") or []
    planted = canary.get("planted") or canary.get("canaries") or []
    failed = bool(alerts)
    state = "Ran-fail" if failed else "Ran-pass"
    if alerts:
        a = alerts[0]
        proof = f"exit 1 · {a.get('type', 'alert')} · {a.get('id', '')} · {a.get('log') or a.get('file') or ''}"
        big = str(len(alerts))
        sub = proof
    else:
        proof = f"exit 0 · {len(planted)} planted · no alerts in this JSON"
        big = f"{len(planted)}/{len(planted)}" if planted else "0"
        sub = proof
    return _tile("canary", state, "high" if failed else "pass", big, sub, proof, "#canary-h")


def _mcp_tile(mcp: dict, drift: dict) -> dict:
    if not mcp and not drift:
        reason = _SKIP["mcp"] + " " + _SKIP["drift"]
        return _tile("mcp", "Not-run", "", "—", reason, "exit skip · " + reason, "#mcp-h")
    hits = (mcp or {}).get("hits") or []
    ext = (mcp or {}).get("extension_hits") or []
    changes = (drift or {}).get("changes") or []
    mcp_findings = [f for f in ((mcp or {}).get("findings") or []) if isinstance(f, dict)]
    high_finding = next(
        (
            f for f in mcp_findings
            if _named_sev(f.get("severity") or f.get("sev")) in ("critical", "high")
        ),
        None,
    )
    failed = bool(hits or ext or changes or (drift or {}).get("status") == "drift" or high_finding)
    state = "Ran-fail" if failed else "Ran-pass"
    if changes:
        c = changes[0]
        proof = f"exit 1 · drift {c.get('kind', 'changed')} · {c.get('server', '')} · {c.get('field', '')}"
    elif hits:
        h = hits[0]
        proof = f"exit {1 if failed else 0} · {h.get('verdict', 'hit')} · {h.get('package', '')} · {h.get('advisory_id', '')}"
    elif ext:
        proof = f"exit 1 · extension · {ext[0].get('advisory_id', '')}"
    elif high_finding:
        proof = (
            f"exit 1 · {high_finding.get('rule') or high_finding.get('check') or 'finding'} · "
            f"{high_finding.get('package') or high_finding.get('file') or ''}"
        )
    else:
        proof = "exit 0 · advisory match ran · no hit in this JSON"
    pinned = (mcp or {}).get("servers")
    big = proof if not isinstance(pinned, int) else f"pinned {pinned}"
    if not hits and not changes and isinstance(pinned, int):
        big = f"pinned {pinned}"
    if changes and isinstance(pinned, int):
        big = f"pinned {pinned} · drift {len(changes)}"
    elif changes:
        big = f"drift {len(changes)}"
    elif hits:
        big = str(len(hits))
    return _tile("mcp", state, "high" if failed else "pass", str(big), proof, proof, "#mcp-h")


def _inject_source_rows(inject: dict) -> List[dict]:
    rows = inject.get("rows") if isinstance(inject.get("rows"), list) else None
    if rows is None:
        rows = inject.get("findings") if isinstance(inject.get("findings"), list) else []
    return [row for row in rows if isinstance(row, dict)]


def _inject_row_sev(row: dict, inject: dict) -> str:
    """Row chip severity. High and medium never fall through to pass.

    An explicit pass/ok verdict stays pass. A missing row verdict uses the
    document severity or risk when that word is a real severity. Otherwise the
    chip is info, not pass.
    """
    for key in ("severity", "sev", "verdict", "risk"):
        named = _named_sev(row.get(key))
        if named is not None:
            return named
    for key in ("severity", "risk"):
        named = _named_sev(inject.get(key))
        if named is not None:
            return named
    return "info"


def _inject_blocking(inject: dict) -> bool:
    if not inject:
        return False
    if _named_sev(inject.get("severity")) in ("critical", "high") or _named_sev(inject.get("risk")) in ("critical", "high"):
        return True
    return any(_inject_row_sev(row, inject) in ("critical", "high") for row in _inject_source_rows(inject))


def _inject_tile(inject: dict) -> dict:
    if not inject:
        return _tile("inject", "Not-run", "", "—", _SKIP["inject"], "exit skip · " + _SKIP["inject"], "#inject-h")
    rows = _inject_source_rows(inject)
    high = _inject_blocking(inject)
    state = "Ran-fail" if high else "Ran-pass"
    if rows:
        r = rows[0]
        proof = f"exit {1 if high else 0} · {r.get('class') or r.get('label') or r.get('rule') or 'payload'} · {r.get('source') or r.get('file') or ''}"
    else:
        proof = f"exit {1 if high else 0} · inject-check ran · no row in this JSON"
    declared = inject.get("payloads")
    if isinstance(declared, int) and not isinstance(declared, bool) and rows and declared != len(rows):
        big = str(len(rows))
    elif isinstance(declared, int) and not isinstance(declared, bool):
        big = str(declared)
    else:
        big = str(len(rows))
    return _tile("inject", state, "high" if high else "pass", big, proof, proof, "#inject-h")


def _forbid_false_pass(tile: dict, bad: bool) -> dict:
    """A Ran-pass tile cannot stand when the underlying rows are a real fail."""
    if bad and tile.get("state") == "Ran-pass":
        out = dict(tile)
        out["state"] = "Ran-fail"
        if out.get("sev") in ("", "pass", "info", None):
            out["sev"] = "high"
        return out
    return tile


def _override_tile(command: str, base: dict, override: Optional[dict]) -> dict:
    if not override:
        return base
    out = dict(base)
    for key in ("state", "sev", "big", "sub", "proof"):
        if override.get(key):
            out[key] = scrub_text(str(override[key])) if key != "sev" else _sev(override[key], base.get("sev") or "info")
    if out["state"] not in ("Ran-fail", "Ran-pass", "Not-run"):
        out["state"] = base["state"]
    if override.get("chip"):
        out["chip"] = scrub_text(str(override["chip"]))
    return out


def _findings_from_scan(scan: dict) -> List[dict]:
    return [present_finding(f) for f in (scan.get("findings") or [])]


def _explicit_findings(rows: Iterable[dict]) -> List[dict]:
    return [present_finding(f) for f in rows]


def _counts(findings: List[dict]) -> Dict[str, int]:
    counts = {}
    for f in findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    return counts


def _canary_events(canary: dict) -> List[dict]:
    if canary.get("events"):
        events = []
        for ev in canary["events"]:
            events.append({
                "at": scrub_text(str(ev.get("at") or "")),
                "tone": "ok" if ev.get("tone") == "ok" else "alert",
                "text": scrub_text(str(ev.get("text") or "")),
                "sev": _sev(ev.get("sev"), "medium") if ev.get("sev") else "",
            })
        return events
    events = []
    for p in canary.get("planted") or canary.get("canaries") or []:
        events.append({
            "at": scrub_text(str(p.get("planted_at") or "")),
            "tone": "ok",
            "text": f"planted {scrub_text(str(p.get('kind') or ''))} · id {scrub_text(str(p.get('id') or ''))} · {scrub_text(str(p.get('file') or ''))}",
            "sev": "",
        })
    for a in canary.get("alerts") or []:
        events.append({
            "at": scrub_text(str(a.get("at") or "")),
            "tone": "alert",
            "text": f"alert {scrub_text(str(a.get('type') or ''))} · id {scrub_text(str(a.get('id') or ''))} · {scrub_text(str(a.get('log') or a.get('file') or ''))}",
            "sev": "medium",
        })
    return events


def _drift_view(drift: dict, callout: Optional[dict]) -> dict:
    if callout:
        return {
            "callout_level": _sev(callout.get("level"), "high"),
            "callout_title": scrub_text(str(callout.get("title") or "MCP hash drift")),
            "callout_text": scrub_text(str(callout.get("text") or "")),
            "status": "drift",
            "before_label": "PINNED",
            "before": "",
            "after_label": "OBSERVED",
            "after": "",
            "arrow": "DRIFT",
            "note": "",
            "hits": [],
        }
    return {}


def _hash_cell(value: str) -> str:
    text = scrub_text(value or "")
    if not text:
        return "—"
    if _looks_secret(text):
        return "[REDACTED]"
    if len(text) > 80:
        return text[:12] + "…"
    return text


def _drift_diff(drift: dict, explicit: Optional[dict]) -> dict:
    if explicit:
        return {
            "status": explicit.get("status") or "drift",
            "before_label": scrub_text(str(explicit.get("before_label") or "PINNED")),
            "before": _hash_cell(str(explicit.get("before") or "")),
            "after_label": scrub_text(str(explicit.get("after_label") or "OBSERVED")),
            "after": _hash_cell(str(explicit.get("after") or "")),
            "arrow": scrub_text(str(explicit.get("arrow") or "DRIFT")),
            "note": scrub_text(str(explicit.get("note") or "")),
        }
    changes = (drift or {}).get("changes") or []
    if not drift:
        return {
            "status": "skip",
            "before_label": "PINNED",
            "before": "—",
            "after_label": "OBSERVED",
            "after": "—",
            "arrow": "Not-run",
            "note": _SKIP["drift"],
        }
    if not changes and drift.get("status") != "drift":
        return {
            "status": "match",
            "before_label": "PINNED",
            "before": _hash_cell(str(drift.get("before") or "—")),
            "after_label": "OBSERVED",
            "after": _hash_cell(str(drift.get("after") or "—")),
            "arrow": "MATCH",
            "note": scrub_text(str(drift.get("note") or "No pin change in this JSON.")),
        }
    first = changes[0] if changes else drift
    return {
        "status": "drift",
        "before_label": "PINNED",
        "before": _hash_cell(str(first.get("before") or drift.get("before") or "—")),
        "after_label": "OBSERVED",
        "after": _hash_cell(str(first.get("after") or drift.get("after") or "—")),
        "arrow": "DRIFT",
        "note": scrub_text(str(drift.get("note") or first.get("server") or "")),
    }


def _inject_summary(inject: dict, row_count: int) -> str:
    """Keep a supplied summary only when its leading count matches the rows."""
    summary = scrub_text(str(inject.get("summary") or ""))
    if not summary:
        noun = "row" if row_count == 1 else "rows"
        return f"{row_count} {noun} in this JSON"
    match = re.match(r"\s*(\d+)\s+(payloads?|rows?)\b", summary)
    if match and int(match.group(1)) != row_count:
        rest = summary[match.end():]
        noun = "row" if row_count == 1 else "rows"
        return f"{row_count} {noun}{rest}"
    return summary


def _inject_detail(row: dict) -> str:
    parts = []
    for key in ("detail", "reason", "message", "advice"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(scrub_text(value.strip()))
            break
    bucket = row.get("length_bucket") if isinstance(row.get("length_bucket"), str) else row.get("bucket")
    if isinstance(bucket, str) and bucket.strip():
        parts.append("bucket " + scrub_text(bucket.strip()))
    return " · ".join(parts)


def _inject_view(inject: dict) -> dict:
    if not inject:
        return {"state": "Not-run", "summary": _SKIP["inject"], "rows": []}
    rows = []
    for i, row in enumerate(_inject_source_rows(inject), 1):
        klass = scrub_text(str(row.get("class") or row.get("label") or row.get("rule") or "payload"))
        source = scrub_text(str(
            row.get("source") or row.get("file") or row.get("path") or inject.get("source") or ""
        ))
        verdict = _inject_row_sev(row, inject)
        line = row.get("line") if isinstance(row.get("line"), int) else i
        rows.append({
            "class": klass,
            "source": source,
            "verdict": verdict,
            "detail": _inject_detail(row),
            "fingerprint": location_fingerprint(klass, source, line),
        })
    state = "Ran-fail" if _inject_blocking(inject) or any(
        r["verdict"] in ("critical", "high") for r in rows
    ) else "Ran-pass"
    return {"state": state, "summary": _inject_summary(inject, len(rows)), "rows": rows}


def _mcp_hits(mcp: dict) -> List[dict]:
    hits = []
    for h in (mcp or {}).get("hits") or []:
        hits.append({
            "verdict": scrub_text(str(h.get("verdict") or "")),
            "server": scrub_text(str(h.get("server") or "")),
            "package": scrub_text(str(h.get("package") or "")),
            "version": scrub_text(str(h.get("version") or "")),
            "advisory_id": scrub_text(str(h.get("advisory_id") or "")),
            "file": scrub_text(str(h.get("file") or "")),
            "reason": scrub_text(str(h.get("reason") or "")),
        })
    hygiene = []
    for item in (mcp or {}).get("hygiene") or []:
        presented = present_finding({
            "rule": item.get("rule") or item.get("check") or "hygiene",
            "path": item.get("file") or "",
            "line": item.get("line") or 0,
            "severity": "medium",
            "preview": item.get("preview") or "",
            "length": item.get("length"),
            "description": item.get("check") or "",
        })
        hygiene.append({
            "check": scrub_text(str(item.get("check") or "")),
            "file": presented["display_path"],
            "line": presented["line"],
            "bucket": presented["bucket"],
            "fingerprint": presented["fingerprint"],
            "redacted": presented["redacted"],
        })
    return hits, hygiene


def _mcp_findings(mcp: dict) -> List[dict]:
    """Surface mcp-check findings so a ``findings`` array is not dropped."""
    rows = []
    for item in (mcp or {}).get("findings") or []:
        if not isinstance(item, dict):
            continue
        sev = _named_sev(item.get("severity") or item.get("sev")) or "info"
        rows.append({
            "sev": sev,
            "rule": scrub_text(str(item.get("rule") or item.get("check") or "")),
            "package": scrub_text(str(item.get("package") or "")),
            "advisory_id": scrub_text(str(item.get("advisory_id") or "")),
            "file": scrub_text(str(item.get("file") or item.get("path") or "")),
            "message": scrub_text(str(item.get("message") or item.get("reason") or "")),
        })
    return rows


def _limits(data: dict, not_run: List[dict], workspace: str) -> str:
    """Scope sentence only. Kill n/a and the honesty line are added in the HTML."""
    if data.get("limits_scope"):
        return scrub_text(str(data["limits_scope"]))
    scope = f"paths outside this JSON · process environments · vendor accounts · anything outside {workspace or 'the files you passed'}"
    extra = [f"{item['name']}: {item['reason']}" for item in not_run if item["name"] != "Kill"]
    if extra:
        scope = scope + ". " + " ".join(extra)
    return scope


def _overall(tiles: List[dict]):
    if any(t["state"] == "Ran-fail" for t in tiles):
        return 1, "Ran-fail"
    if any(t["state"] == "Ran-pass" for t in tiles):
        return 0, "Ran-pass"
    return None, "Not-run"


def normalize(data: dict) -> dict:
    """Build the display model. Secret prefixes never survive this step."""
    data = _coerce_input(data)
    example = bool(data.get("example") or data.get("example_data"))
    workspace = scrub_text(str(data.get("workspace") or ("workspace://foundry-EXAMPLE" if example else "local files")))
    host = scrub_text(str(data.get("host") or "local"))
    mode = scrub_text(str(data.get("mode") or "offline"))
    generated = scrub_text(str(data.get("generated_at") or ""))
    if not generated:
        import time
        generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    scan = _as_dict(data.get("scan"), "scan") if data.get("scan") is not None else {}
    if "findings" in data and "scan" not in data and "tiles" in data:
        findings = _explicit_findings(data.get("findings") or [])
        scan_present = True
    else:
        findings = _findings_from_scan(scan) if scan else []
        scan_present = bool(scan)

    canary = _as_dict(data.get("canary"), "canary") if data.get("canary") is not None else {}
    if data.get("canary_events") and not canary:
        canary = {"events": data.get("canary_events")}
    mcp = _as_dict(data.get("mcp"), "mcp") if data.get("mcp") is not None else {}
    drift = _as_dict(data.get("drift"), "drift") if isinstance(data.get("drift"), (dict, str)) else {}
    inject = _as_dict(data.get("inject"), "inject") if isinstance(data.get("inject"), (dict, str)) else {}
    if data.get("inject") and isinstance(data.get("inject"), dict):
        inject = data["inject"]

    overrides = data.get("tiles") or {}
    tiles = [
        _override_tile("scan", _scan_tile(scan if scan_present else {}, findings), overrides.get("scan")),
        _override_tile("canary", _canary_tile(canary), overrides.get("canary")),
        _override_tile("mcp", _mcp_tile(mcp, drift or (data.get("drift_diff") and {"status": "drift", "changes": [{}]}) or {}), overrides.get("mcp")),
        _override_tile("inject", _inject_tile(inject), overrides.get("inject")),
    ]
    # Example fixture has no mcp/drift objects; the override plus drift_diff carry the evidence.
    if data.get("drift_diff") and not mcp and not drift:
        tiles[2] = _override_tile("mcp", tiles[2], overrides.get("mcp"))

    scan_bad = _scan_failed(scan if isinstance(scan, dict) else {}, findings) or any(
        not f.get("canary") for f in findings
    )
    mcp_bad = bool((mcp or {}).get("hits") or (mcp or {}).get("extension_hits")) or any(
        isinstance(row, dict) and _named_sev(row.get("severity") or row.get("sev")) in ("critical", "high")
        for row in ((mcp or {}).get("findings") or [])
    )
    tiles[0] = _forbid_false_pass(tiles[0], scan_bad)
    tiles[3] = _forbid_false_pass(tiles[3], _inject_blocking(inject))
    tiles[2] = _forbid_false_pass(tiles[2], mcp_bad)

    exit_code, run_state = _overall(tiles)
    not_run = [{"name": "Kill", "reason": KILL_LABEL + " " + KILL_NOTE}]
    for tile in tiles:
        if tile["state"] == "Not-run":
            not_run.append({"name": tile["title"], "reason": tile["sub"]})
    if not drift and not data.get("drift_diff"):
        not_run.append({"name": "MCP drift", "reason": _SKIP["drift"]})

    if data.get("drift_callout"):
        call = data["drift_callout"]
        callout = {
            "level": _sev(call.get("level"), "high"),
            "title": scrub_text(str(call.get("title") or "")),
            "text": scrub_text(str(call.get("text") or "")),
            "skip": False,
        }
    elif drift or (mcp and (drift.get("changes") if isinstance(drift, dict) else False)):
        diff_preview = _drift_diff(drift, None)
        callout = {
            "level": "high" if diff_preview["status"] == "drift" else "info",
            "title": "MCP hash drift above fold" if diff_preview["status"] == "drift" else "MCP drift",
            "text": diff_preview["note"] or diff_preview["arrow"],
            "skip": diff_preview["status"] == "skip",
        }
    else:
        callout = {
            "level": "info",
            "title": "MCP drift",
            "text": _SKIP["drift"],
            "skip": True,
        }

    counts = _counts(findings)
    sev_segments = [(name, counts.get(name, 0)) for name in _BAR_ORDER if counts.get(name, 0)]
    hits, hygiene = _mcp_hits(mcp)
    mcp_findings = _mcp_findings(mcp)
    diff = _drift_diff(drift, data.get("drift_diff"))
    inject_view = _inject_view(inject)

    return {
        "schema": REPORT_SCHEMA,
        "manifest_schema": SCHEMA,
        "product": "afk-guard",
        "version": __version__,
        "offer": "free-cli",
        "example": example,
        "generated_at": generated,
        "workspace": workspace,
        "host": host,
        "mode": mode,
        "exit_code": exit_code,
        "run_state": run_state,
        "honesty": HONESTY,
        "callout": callout,
        "tiles": tiles,
        "not_run": not_run,
        "findings": findings,
        "severity": [{"sev": name, "n": n} for name, n in sev_segments],
        "canary_intro": scrub_text(str(data.get("canary_intro") or "Canary evidence from the JSON you passed. Values are not printed.")),
        "canary_events": _canary_events(canary if canary else {"events": data.get("canary_events") or []}),
        "drift": diff,
        "mcp_hits": hits,
        "mcp_findings": mcp_findings,
        "hygiene": hygiene,
        "inject": inject_view,
        "limits": _limits(data, not_run, workspace),
        "pass_note": _pass_note(tiles),
    }


def _pass_note(tiles: List[dict]) -> str:
    passed = [t["id"] for t in tiles if t["state"] == "Ran-pass"]
    if not passed:
        return ""
    return "/".join(passed)


def _sev_chip(sev: str) -> str:
    label, glyph, cls, _fill = _SEV_META.get(sev, _SEV_META["info"])
    return f'<span class="afk-sev {cls}"><span aria-hidden="true">{glyph}</span>{label}</span>'


def _run_chip(state: str) -> str:
    if state == "Ran-fail":
        return '<span class="afk-run-fail">Ran-fail</span>'
    if state == "Ran-pass":
        return '<span class="afk-run-pass">Ran-pass</span>'
    return '<span class="afk-skip"><span aria-hidden="true">⊘</span> Not-run</span>'


def _bar_svg(segments: List[dict]) -> str:
    if not segments:
        return (
            '<svg viewBox="0 0 640 36" width="100%" height="36" role="img" aria-label="No findings in this JSON">'
            '<rect x="0" y="8" width="640" height="20" fill="none" stroke="#b3ad98"/>'
            '<text x="8" y="22" fill="#b3ad98" font-family="ui-monospace,Menlo,monospace" font-size="11">NO FINDINGS</text>'
            "</svg>"
        )
    total = sum(s["n"] for s in segments) or 1
    x = 0
    rects, texts, labels = [], [], []
    for i, seg in enumerate(segments):
        sev = seg["sev"]
        _label, _glyph, _cls, fill = _SEV_META[sev]
        w = 640 - x if i == len(segments) - 1 else int(round(seg["n"] / total * 640))
        short = _BAR_SHORT[sev]
        labels.append(f"{seg['n']} {short.lower()}")
        if sev == "critical":
            rects.append(f'<rect x="{x}" y="8" width="{w}" height="20" fill="url(#sev-critical)"/>')
        else:
            rects.append(f'<rect x="{x}" y="8" width="{w}" height="20" fill="{fill}"/>')
        if w >= 72:
            texts.append(
                f'<text x="{x + 8}" y="22" fill="#14140f" font-family="ui-monospace,Menlo,monospace" font-size="11" font-weight="700">{short} {seg["n"]}</text>'
            )
        x += w
    aria = "Stacked severity: " + ", ".join(labels)
    pattern = (
        '<defs><pattern id="sev-critical" patternUnits="userSpaceOnUse" width="6" height="6" patternTransform="rotate(45)">'
        '<rect width="6" height="6" fill="#e24a2b"/>'
        '<line x1="0" y1="0" x2="0" y2="6" stroke="#14140f" stroke-width="2"/>'
        "</pattern></defs>"
    )
    return (
        f'<svg viewBox="0 0 640 36" width="100%" height="36" role="img" aria-label="{_e(aria)}">'
        f"{pattern}{''.join(rects)}{''.join(texts)}</svg>"
    )


def _finding_body(f: dict) -> str:
    bits = []
    if f.get("rule_code"):
        bits.append(f"Rule <code>{_e(f['rule_code'])}</code>")
    else:
        bits.append(f"Rule <code>{_e(f['rule'])}</code>")
    if f.get("redacted"):
        bits.append(f"[REDACTED] · bucket {_e(f['bucket'])}")
    bits.append(f"location fingerprint <code class=\"afk-hash\">{_e(f['fingerprint'])}</code>")
    if f.get("why"):
        bits.append(f"Why it matters: {_e(f['why'])}")
    if f.get("next"):
        bits.append(f"Next: {_e(f['next'])}")
    return " · ".join(bits)


def _json_script(model: dict) -> str:
    payload = {
        "schema": model["schema"],
        "manifest_schema": model["manifest_schema"],
        "product": model["product"],
        "version": model["version"],
        "offer": model["offer"],
        "example": model["example"],
        "generated_at": model["generated_at"],
        "exit_code": model["exit_code"],
        "run_state": model["run_state"],
        "honesty": model["honesty"],
        "mosaic": {t["id"]: {"state": t["state"], "big": t["big"], "proof": t["proof"]} for t in model["tiles"]},
        "not_run": model["not_run"],
        "findings": [
            {
                "sev": f["sev"],
                "rule": f["rule"],
                "path": f["path"],
                "line": f["line"],
                "preview": "[REDACTED]" if f["redacted"] else "",
                "bucket": f["bucket"],
                "length": f["length"],
                "fp": f["fingerprint"],
                "fingerprint_kind": "location",
            }
            for f in model["findings"]
        ],
    }
    text = json.dumps(payload, indent=2)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


_CSS = r"""
:root{
  --bg:#14140f;--fg:#e9e4d8;--mu:#b3ad98;--ac:#ff8a00;--ac2:#c9d33b;
  --ok:#1a9e55;--warn:#e6b84d;--bad:#ff8a00;--ln:rgba(233,228,216,.14);
  --panel:rgba(233,228,216,.04);--demo:#c9d33b;
  --on-ac:#14140f;--on-ac2:#14140f;--on-warn:#14140f;--on-bad:#14140f;
  --mono:ui-monospace,Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);font:14px/1.45 var(--sans)}
code,kbd,.mono,.afk-hash{font-family:var(--mono)}
a{color:var(--ac)}
.afk-badge-example{
  display:inline-flex;align-items:center;gap:.4rem;
  background:var(--demo);color:var(--on-ac2);font:700 11px/1 var(--mono);
  letter-spacing:.04em;padding:.35rem .55rem;border-radius:2px;text-transform:uppercase;
}
.afk-sev{
  display:inline-flex;align-items:center;gap:.35rem;
  font:700 10px/1 var(--mono);letter-spacing:.06em;padding:.28rem .45rem;border-radius:2px;
  text-transform:uppercase;vertical-align:middle;
}
.afk-sev-high{background:var(--ac);color:var(--on-ac)}
.afk-sev-medium{background:var(--warn);color:var(--on-warn)}
.afk-sev-info{background:transparent;color:var(--fg);border:1px solid var(--ln)}
.afk-sev-pass{background:var(--ac2);color:var(--on-ac2)}
.afk-sev-critical{
  color:var(--on-ac);background-color:#e24a2b;
  background-image:repeating-linear-gradient(-45deg,transparent,transparent 3px,rgba(20,20,15,.4) 3px,rgba(20,20,15,.4) 5px);
}
.afk-skip{
  display:inline-flex;align-items:center;gap:.3rem;
  font:700 10px/1 var(--mono);letter-spacing:.04em;padding:.28rem .45rem;
  border:1px dashed var(--mu);color:var(--mu);border-radius:2px;text-transform:uppercase;
}
.afk-run-pass{color:var(--on-ac2);background:var(--ac2);font:700 10px/1 var(--mono);padding:.28rem .45rem;border-radius:2px;text-transform:uppercase}
.afk-run-fail{color:var(--on-ac);background:var(--ac);font:700 10px/1 var(--mono);padding:.28rem .45rem;border-radius:2px;text-transform:uppercase}
.afk-honesty,.afk-limits{
  border:1px solid var(--ln);background:var(--panel);padding:.75rem 1rem;color:var(--mu);font-size:12px;
}
.afk-evidence{
  border-left:3px solid var(--ac);background:var(--panel);padding:.75rem 1rem;margin:.75rem 0;
}
.afk-tile{
  background:var(--panel);border:1px solid var(--ln);padding:1rem;border-radius:4px;
}
.afk-hash{font-size:12px;color:var(--mu)}
.panel{background:var(--panel);border:1px solid var(--ln);border-radius:4px;padding:1rem 1.1rem}
h1,h2,h3{font-family:var(--mono);font-weight:700;letter-spacing:.02em;margin:0 0 .5rem}
h1{font-size:clamp(22px,3vw,28px)}
h2{font-size:18px;margin-top:1.5rem}
h3{font-size:14px;color:var(--mu);text-transform:uppercase;letter-spacing:.08em}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:.55rem .6rem;border-bottom:1px solid var(--ln);vertical-align:top}
th{color:var(--mu);font:700 11px/1.2 var(--mono);text-transform:uppercase;letter-spacing:.06em}
caption{caption-side:top;text-align:left;color:var(--mu);font-size:12px;margin-bottom:.5rem}
.chip-row{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center}
.muted{color:var(--mu)}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
footer.afk-footer{margin-top:2rem;padding:1rem 0;border-top:1px solid var(--ln);color:var(--mu);font-size:12px}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
body{padding:0}
.wrap{max-width:980px;margin:0 auto;padding:1rem 1.25rem 2.5rem}
.topstrip{
  display:flex;flex-wrap:wrap;gap:.75rem;align-items:center;justify-content:space-between;
  border-bottom:1px solid var(--ln);padding:.75rem 1.25rem;background:#10100c;position:sticky;top:0;z-index:5;
}
.topstrip .meta{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;font:12px/1.2 var(--mono);color:var(--mu)}
.hero{display:grid;grid-template-columns:1fr auto;gap:1rem;align-items:end;padding:1.25rem 0 .5rem}
.hero .brand{display:flex;gap:.75rem;align-items:center}
.exit{
  font:700 12px/1 var(--mono);padding:.45rem .7rem;border-radius:2px;
  background:var(--ac);color:var(--on-ac);
}
.exit.pass{background:var(--ac2);color:var(--on-ac2)}
.exit.skip{background:transparent;color:var(--mu);border:1px dashed var(--mu)}
.mosaic{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem;margin:1rem 0}
@media(max-width:800px){.mosaic{grid-template-columns:1fr 1fr}.hero{grid-template-columns:1fr}}
.mosaic .afk-tile h3{margin:0 0 .4rem}
.mosaic .big{font:700 28px/1 var(--mono);margin:.35rem 0}
.mosaic .sub{font-size:12px;color:var(--mu)}
.bar-wrap{margin:1rem 0}
.findings details{border-bottom:1px solid var(--ln)}
.findings summary{cursor:pointer;list-style:none;padding:.65rem 0;min-height:44px;display:grid;grid-template-columns:90px 1fr 1.2fr 140px;gap:.5rem;align-items:center}
.findings summary::-webkit-details-marker{display:none}
.findings details[open] summary{color:var(--fg)}
.findings .body{padding:0 0 .9rem 0;color:var(--mu);font-size:13px}
.rail{display:flex;flex-direction:column;gap:.5rem;margin:.5rem 0 1rem;padding-left:.5rem;border-left:2px solid var(--ln)}
.rail .ev{position:relative;padding-left:1rem}
.rail .ev::before{content:"";position:absolute;left:-.55rem;top:.35rem;width:8px;height:8px;border-radius:50%;background:var(--ac)}
.rail .ev.ok::before{background:var(--ac2)}
.drift-callout{border:1px solid var(--ac);background:rgba(255,138,0,.08);padding:.85rem 1rem;margin:1rem 0}
.drift-callout.skip{border-style:dashed;border-color:var(--mu);background:var(--panel)}
.hashdiff{display:grid;grid-template-columns:1fr auto 1fr;gap:.75rem;align-items:center;font-family:var(--mono);font-size:12px}
.hashdiff .box{background:#0c0c09;border:1px solid var(--ln);padding:.6rem;word-break:break-all}
/* #16 focus + tap targets */
a:focus-visible,button:focus-visible,summary:focus-visible,[tabindex]:focus-visible{
  outline:2px solid var(--ac);outline-offset:2px;
}
/* #14 mobile findings stack — no horizontal page scroll */
html,body{overflow-x:hidden}
main.wrap{overflow-x:hidden;max-width:100%}
.afk-hash,code.afk-hash{overflow-wrap:anywhere;word-break:break-all}
@media (max-width:640px){
  .findings summary{
    grid-template-columns:1fr;
    gap:.25rem .5rem;
    padding:.65rem 0;
    align-items:start;
  }
  .findings summary > .mono{grid-row:auto}
  .findings summary > .muted{grid-row:auto}
  .findings summary > .afk-hash, .findings summary > code.afk-hash{grid-row:auto}
}
/* #20 table scroll wrappers */
.table-scroll{display:block;width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
.table-scroll table{min-width:0}
@media (max-width:640px){
  .table-scroll table{table-layout:fixed;width:100%}
  .table-scroll th,.table-scroll td{word-break:break-word;overflow-wrap:anywhere}
}
@media print{
  :root{--bg:#fff;--fg:#111;--mu:#444;--panel:#f7f5ef;--ln:rgba(0,0,0,.12)}
  body{background:#fff;color:#111}
  .topstrip{position:static;background:#fff;border-color:#ccc}
  .afk-badge-example{border:1px solid #111}
  .exit,.afk-sev-high,.afk-run-fail{background:#fff;color:#111;border:1.5px solid #ff8a00}
  .afk-sev-medium{background:#fff;color:#111;border:1.5px solid #e6b84d}
  .afk-sev-critical{background:#fff;color:#111;border:1.5px solid #e24a2b}
  .afk-sev-pass,.afk-run-pass{background:#fff;color:#111;border:1.5px solid #c9d33b}
  .drift-callout{background:#fff8f0}
}
"""

_MARK = (
    '<svg class="afk-mark" width="28" height="28" viewBox="0 0 28 28" aria-hidden="true">'
    '<rect x="1" y="1" width="26" height="26" fill="none" stroke="#ff8a00" stroke-width="1.5"/>'
    '<path d="M7 19 V9 h3.2 l2.3 6.2 L14.8 9 H18 v10 h-2.2 v-5.6 L13.4 19 h-1.3 l-2.4-5.6V19H7z" fill="#e9e4d8"/>'
    '<circle cx="21" cy="8" r="2" fill="#c9d33b"/></svg>'
)


def render(model: dict) -> str:
    """Render a normalized model to one HTML document."""
    if "tiles" not in model:
        model = normalize(model)
    exit_code = model["exit_code"]
    if exit_code is None:
        exit_label, exit_cls = "SKIP", "exit skip"
    elif exit_code:
        exit_label, exit_cls = f"EXIT {exit_code}", "exit"
    else:
        exit_label, exit_cls = "EXIT 0", "exit pass"
    call = model["callout"]
    call_cls = "drift-callout afk-evidence skip" if call.get("skip") else "drift-callout afk-evidence"
    call_chip = '<span class="afk-skip"><span aria-hidden="true">⊘</span> Not-run</span>' if call.get("skip") else _sev_chip(call["level"])

    tiles_html = []
    for tile in model["tiles"]:
        sev = _sev_chip(tile["sev"]) if tile["sev"] in _SEV_META and tile["state"] != "Not-run" else ""
        big = str(tile["big"])
        if re.fullmatch(r"\d+(?:/\d+)?", big):
            big_html = f'<div class="big">{_e(big)}</div>'
        else:
            big_html = f'<div class="big mono" style="font-size:18px;margin-top:.5rem">{_e(big)}</div>'
        tiles_html.append(
            f'<article class="afk-tile" data-command="{_e(tile["id"])}" data-state="{_e(tile["state"])}">'
            f"<h3>{_e(tile['title'])}</h3>"
            f'<div class="chip-row">{_run_chip(tile["state"])}{sev}</div>'
            f"{big_html}"
            f'<div class="sub">{_e(tile["sub"])}</div>'
            f"</article>"
        )

    chips = []
    for seg in model["severity"]:
        chips.append(f'{_sev_chip(seg["sev"])} ×{seg["n"]}')
    chip_row = " · ".join(chips) if chips else '<span class="muted">No findings in this JSON.</span>'
    if model.get("pass_note"):
        chip_row += f' · {_sev_chip("pass")} {_e(model["pass_note"])}'
    for tile in model["tiles"]:
        if tile["state"] == "Not-run":
            chip_row += f' · <span class="afk-skip"><span aria-hidden="true">⊘</span> Not-run</span> {_e(tile.get("chip") or tile["id"])}'

    rows = []
    for i, f in enumerate(model["findings"]):
        opened = " open" if i == 0 else ""
        rows.append(
            f"<details{opened}>"
            f"<summary>{_sev_chip(f['sev'])}"
            f'<span class="mono">{_e(f["rule"])}</span>'
            f'<span class="muted">{_e(f["display_path"])}</span>'
            f'<code class="afk-hash">{_e(f["fingerprint"])}</code>'
            f"</summary>"
            f'<div class="body">{_finding_body(f)}</div>'
            f"</details>"
        )
    if not rows:
        rows.append('<p class="muted">No findings in this JSON.</p>')

    events = []
    for ev in model["canary_events"]:
        klass = "ev ok" if ev["tone"] == "ok" else "ev"
        sev = _sev_chip(ev["sev"]) if ev.get("sev") else ""
        events.append(
            f'<div class="{klass}" role="listitem"><span class="mono">{_e(ev["at"])}</span> {_e(ev["text"])} {sev}</div>'
        )
    if not events:
        events.append('<div class="ev" role="listitem"><span class="muted">No canary events in this JSON.</span></div>')

    diff = model["drift"]
    arrow_color = "var(--ac)" if diff["status"] == "drift" else "var(--mu)"
    hit_rows = []
    for h in model["mcp_hits"]:
        hit_rows.append(
            "<tr>"
            f"<td>{_e(h['verdict'])}</td><td class=\"mono\">{_e(h['package'])}</td>"
            f"<td>{_e(h['version'])}</td><td class=\"mono\">{_e(h['advisory_id'])}</td>"
            f"<td class=\"muted\">{_e(h['file'])}</td>"
            "</tr>"
        )
    hits_table = ""
    if hit_rows:
        hits_table = (
            '<div class="table-scroll"><table><caption>Advisory hits in this JSON</caption>'
            "<thead><tr><th>Verdict</th><th>Package</th><th>Version</th><th>Advisory</th><th>File</th></tr></thead>"
            f"<tbody>{''.join(hit_rows)}</tbody></table></div>"
        )
    mcp_finding_rows = []
    for row in model.get("mcp_findings") or []:
        mcp_finding_rows.append(
            "<tr>"
            f"<td>{_sev_chip(row['sev'])}</td>"
            f"<td class=\"mono\">{_e(row['rule'])}</td>"
            f"<td class=\"mono\">{_e(row['package'])}</td>"
            f"<td class=\"mono\">{_e(row['advisory_id'])}</td>"
            f"<td class=\"muted\">{_e(row['file'])}</td>"
            f"<td>{_e(row['message'])}</td>"
            "</tr>"
        )
    mcp_findings_table = ""
    if mcp_finding_rows:
        mcp_findings_table = (
            '<div class="table-scroll"><table><caption>MCP findings in this JSON</caption>'
            "<thead><tr><th>Sev</th><th>Rule</th><th>Package</th><th>Advisory</th><th>File</th><th>Message</th></tr></thead>"
            f"<tbody>{''.join(mcp_finding_rows)}</tbody></table></div>"
        )
    hyg_bits = []
    for item in model["hygiene"]:
        red = " · [REDACTED] · bucket " + _e(item["bucket"]) if item["redacted"] else ""
        hyg_bits.append(
            f'<li>{_e(item["check"])} · {_e(item["file"])}:{item["line"]}{red} · '
            f'<code class="afk-hash">{_e(item["fingerprint"])}</code></li>'
        )
    hyg_html = f'<ul>{"".join(hyg_bits)}</ul>' if hyg_bits else ""

    inj = model["inject"]
    inj_rows = []
    for row in inj["rows"]:
        inj_rows.append(
            "<tr>"
            f"<td>{_e(row['class'])}</td><td>{_e(row['source'])}</td>"
            f"<td>{_sev_chip(row['verdict'])} {_e(row['detail'])}</td>"
            f'<td><code class="afk-hash">{_e(row["fingerprint"])}</code></td>'
            "</tr>"
        )
    inj_caption = "Injection checks (EXAMPLE classes only)" if model["example"] else "Injection checks in this JSON"
    if inj_rows:
        inj_table = (
            f'<div class="table-scroll"><table><caption>{_e(inj_caption)}</caption>'
            "<thead><tr><th>Class</th><th>Source</th><th>Verdict</th><th>Fingerprint</th></tr></thead>"
            f"<tbody>{''.join(inj_rows)}</tbody></table></div>"
        )
    else:
        inj_table = f'<p class="muted">{_e(inj["summary"])}</p>'

    caption = (
        "Top findings (EXAMPLE). Expand for rule + next step."
        if model["example"] else
        "Findings in this JSON. Expand for rule, length bucket, and next step."
    )
    if model["example"]:
        example_note = "EXAMPLE DATA only · not a customer deliverable · "
        page_title = "AFK Guard · Scan report · EXAMPLE DATA"
        example_badge = '<span class="afk-badge-example" aria-label="Example data">EXAMPLE DATA</span>'
    else:
        example_note = ""
        page_title = "AFK Guard · Scan report"
        example_badge = ""

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8"/>',
        '<meta name="viewport" content="width=device-width,initial-scale=1"/>',
        f"<title>{page_title}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        '<a class="sr-only" href="#main">Skip to main</a>',
        '<header class="topstrip" role="banner">',
        '<div class="chip-row">',
        _MARK,
        '<strong class="mono">AFK Guard</strong>',
        '<span class="muted mono">· Free CLI</span>',
        example_badge,
        "</div>",
        '<div class="meta">',
        f'<span>generated_at {_e(model["generated_at"])}</span>',
        f'<span>schema {_e(model["schema"])}</span>',
        f'<span>manifest {_e(model["manifest_schema"])}</span>',
        f'<span>afk-guard {_e(model["version"])}</span>',
        "</div></header>",
        '<main id="main" class="wrap" role="main">',
        '<section class="hero" aria-labelledby="hero-title">',
        '<div class="brand"><div>',
        '<h1 id="hero-title">Scan report</h1>',
        f'<p class="muted mono" style="margin:0">{_e(model["workspace"])} · host {_e(model["host"])} · mode {_e(model["mode"])}</p>',
        "</div></div>",
        '<div class="chip-row" style="justify-content:flex-end">',
        f'<span class="{exit_cls}" title="Process exit code">{exit_label}</span>',
        _run_chip(model["run_state"]),
        "</div></section>",
        f'<div id="mcp-drift" class="{call_cls}" role="status" data-section="drift">',
        '<div class="chip-row" style="margin-bottom:.4rem">',
        call_chip,
        f'<strong class="mono">{_e(call["title"])}</strong>',
        "</div>",
        f'<p style="margin:0;font-size:13px">{_e(call["text"])}</p>',
        "</div>",
        '<section aria-labelledby="mosaic-h" data-section="mosaic">',
        '<h2 id="mosaic-h" class="sr-only">Command mosaic</h2>',
        f'<div class="mosaic">{"".join(tiles_html)}</div>',
        "</section>",
        '<section aria-labelledby="sev-h" data-section="scan">',
        '<h2 id="sev-h">Severity mix</h2>',
        '<div class="bar-wrap panel">',
        _bar_svg(model["severity"]),
        f'<div class="chip-row" style="margin-top:.5rem">{chip_row}</div>',
        "</div></section>",
        '<section class="findings" aria-labelledby="find-h">',
        '<h2 id="find-h">Findings</h2>',
        "<table>",
        f"<caption>{_e(caption)}</caption>",
        "<thead><tr><th>Sev</th><th>Rule</th><th>Path</th><th>Fingerprint</th></tr></thead>",
        "</table>",
        "".join(rows),
        "</section>",
        '<section aria-labelledby="canary-h" data-section="canary">',
        '<h2 id="canary-h">Canary rail</h2>',
        f'<p class="muted" style="margin-top:0">{_e(model["canary_intro"])}</p>',
        f'<div class="rail" role="list">{"".join(events)}</div>',
        "</section>",
        '<section aria-labelledby="mcp-h" data-section="mcp">',
        '<h2 id="mcp-h">MCP pin / hash drift</h2>',
        '<div class="panel">',
        '<div class="hashdiff" aria-label="Hash drift before after">',
        f'<div class="box"><div class="muted">{_e(diff["before_label"])}</div>{_e(diff["before"])}</div>',
        f'<div class="mono" style="color:{arrow_color};font-weight:700">→ {_e(diff["arrow"])}</div>',
        f'<div class="box"><div class="muted">{_e(diff["after_label"])}</div>{_e(diff["after"])}</div>',
        "</div>",
        f'<p class="muted" style="margin:.75rem 0 0;font-size:12px">{_e(diff["note"])}</p>',
        hits_table,
        mcp_findings_table,
        hyg_html,
        "</div></section>",
        '<section aria-labelledby="inject-h" data-section="inject">',
        '<h2 id="inject-h">Inject panel</h2>',
        '<div class="panel">',
        f'<div class="chip-row" style="margin-bottom:.6rem">{_run_chip(inj["state"])}<span class="muted mono">{_e(inj["summary"])}</span></div>',
        inj_table,
        "</div></section>",
        '<section aria-labelledby="limits-h" data-section="not-checked">',
        '<h2 id="limits-h">Limits</h2>',
        '<div class="afk-limits afk-honesty">',
        "<strong>What was not checked (always visible):</strong> ",
        f'{_e(model["limits"])}. ',
        f"<strong>{_e(KILL_LABEL)}</strong> {_e(KILL_NOTE)} ",
        f"{_e(HONESTY)}",
        "</div></section>",
        "</main>",
        '<footer class="afk-footer wrap" role="contentinfo">',
        f'AFK Guard {_e(model["version"])} · {example_note}',
        f'{_e(HONESTY)} · ',
        'Raw JSON: <a href="#afk-data">#afk-data</a>',
        "</footer>",
        f'<script type="application/json" id="afk-data">{_json_script(model)}</script>',
        "</body></html>",
    ]
    return _PREFIX_RE.sub("[REDACTED]", "\n".join(parts))


def assemble(manifest=None, scan=None, canary=None, mcp=None, inject=None, drift=None, example=False, title=None) -> dict:
    """Load JSON paths into one manifest. ``example`` uses the built-in fixture when no manifest is given.

    ``--example`` mixed with a real input is rejected. Live rows are never
    badged EXAMPLE.
    """
    live = {"scan": scan, "canary": canary, "mcp": mcp, "inject": inject, "drift": drift}
    if example and (manifest is not None or any(value is not None for value in live.values())):
        raise ValueError(
            "refusing mixed mode: --example cannot be combined with --input, --scan, "
            "--canary, --mcp, --inject, or --drift"
        )
    if manifest is not None:
        data = _coerce_input(_read_json(manifest) if isinstance(manifest, str) else manifest)
    elif any(value is not None for value in live.values()):
        data = {"schema": SCHEMA, "example": False}
    elif example:
        data = example_manifest()
    else:
        raise ValueError("pass --example, --input, or at least one of --scan --canary --mcp --inject --drift")
    for key, value in live.items():
        if value is None:
            continue
        if manifest is not None and key in data:
            raise ValueError(
                f"refusing to overwrite {key} JSON from --input with --{key}; pass one source"
            )
        data[key] = _read_json(value) if isinstance(value, str) else value
    if data.get("example") and any(value is not None for value in live.values()):
        raise ValueError(
            "refusing mixed mode: an example manifest cannot be combined with live JSON inputs"
        )
    if title:
        data["workspace"] = title
    return normalize(data)


def write(path: str, document: str) -> None:
    """Write HTML by replacing the final directory entry. Do not follow a symlink there.

    The bytes go to a new file in the same directory (``O_EXCL | O_NOFOLLOW``),
    then ``os.replace`` on that directory descriptor swaps the name. ``rename(2)``
    replaces a symlink node and does not open or truncate its target. Replacing
    an existing regular file is intentional.

    Parent-path races are not closed: the directory is opened by path.
    """
    if not isinstance(path, str) or not path:
        raise OSError("dashboard output path is empty")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("refusing to write dashboard HTML: no-follow create is unavailable")
    directory, name = os.path.split(os.path.abspath(path))
    if not directory or not name or name in (".", ".."):
        raise OSError(f"refusing to write dashboard HTML to {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    tmp_name = f".afk-dashboard-{os.getpid()}-{secrets.token_hex(8)}.tmp"
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fd = os.open(tmp_name, flags, 0o666, dir_fd=dir_fd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(document)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except Exception:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(dir_fd)
