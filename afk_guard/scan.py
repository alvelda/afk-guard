"""Secret scanner: regex rules plus Shannon entropy. Output is always redacted.

Previews are [REDACTED] + rule + length bucket + a location fingerprint
(rule, normalized path, line). Secret bytes are not hashed and not copied.
The same secret in two files does not share a fingerprint (no value dedupe).
Two values with the same rule, path, and line share one fingerprint.
"""
import math
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable, Iterator, List, Optional

from .redact import fingerprint, format_preview, redact_line

# (rule id, severity, description, compiled regex, group index holding the secret)
RULES = [
    ("aws-access-key-id", "high", "AWS access key id", re.compile(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b"), 1),
    ("github-token", "high", "GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), 1),
    ("github-fine-grained-pat", "high", "GitHub fine-grained PAT", re.compile(r"\b(github_pat_[A-Za-z0-9_]{50,255})\b"), 1),
    ("slack-token", "high", "Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,200})\b"), 1),
    ("stripe-live-key", "high", "Stripe live secret/restricted key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,247})\b"), 1),
    ("stripe-test-key", "low", "Stripe test secret/restricted key", re.compile(r"\b((?:sk|rk)_test_[A-Za-z0-9]{16,247})\b"), 1),
    ("anthropic-key", "high", "Anthropic API key", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,200})\b"), 1),
    ("openai-key", "high", "OpenAI-style API key", re.compile(r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,200})\b"), 1),
    ("xai-key", "high", "xAI API key", re.compile(r"\b(xai-[A-Za-z0-9]{40,100})\b"), 1),
    ("google-api-key", "medium", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 1),
    ("private-key-block", "high", "PEM private key header", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), 1),
    ("jwt", "medium", "JSON Web Token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"), 1),
    ("bearer-token", "medium", "Bearer token in text", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{24,}=*)"), 1),
    ("url-credentials", "medium", "Password embedded in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]{1,64}:([^\s:/@]{6,128})@"), 1),
]

# keyword = value assignments; the value is only reported when its entropy is high enough
GENERIC = re.compile(
    r"""(?ix)
    (?:api[_-]?key|secret|token|passwd|password|private[_-]?key|access[_-]?key|auth)[\w.-]*
    ["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{16,200})["']?"""
)

CANARY_MARK = "AFKGUARD"  # every canary value contains this marker (see canary.py)
IGNORE_TAG = "afk-guard:ignore"
PLACEHOLDER = re.compile(r"(?i)(x{6,}|\*{4,}|example|placeholder|changeme|your[_-]|<.*>|\$\{|\{\{|dummy|sample|redacted)")

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".cache", ".npm", ".next", "dist-packages",
             "site-packages", ".mypy_cache", ".pytest_cache", ".tox", "chrome-profile", ".gradle"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z",
            ".mp4", ".mov", ".mp3", ".wav", ".woff", ".woff2", ".ttf", ".otf", ".so", ".dll", ".exe", ".bin",
            ".pyc", ".class", ".jar", ".xlsx", ".docx", ".pptx", ".sqlite", ".db", ".parquet", ".onnx", ".pt",
            ".safetensors", ".npy", ".webm", ".avif", ".heic", ".glb", ".obj", ".stl"}
MAX_BYTES = 1_000_000


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    description: str
    preview: str          # [REDACTED] + rule + length bucket + location fingerprint
    fingerprint: str
    canary: bool = False
    context: Optional[str] = None  # only filled with --show-context, redacted

    def to_dict(self):
        d = asdict(self)
        if d["context"] is None:
            d.pop("context")
        return d


def scan_text(text: str, path: str = "<text>", show_context: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:
            line = line[:5000]
        if IGNORE_TAG in line:
            continue
        spans, seen = [], set()
        for rid, sev, desc, rx, grp in RULES:
            for m in rx.finditer(line):
                val = m.group(grp)
                if (m.start(grp), m.end(grp)) in seen:
                    continue
                seen.add((m.start(grp), m.end(grp)))
                is_canary = CANARY_MARK in val
                if not is_canary and rid in ("bearer-token", "url-credentials") and PLACEHOLDER.search(val):
                    continue
                spans.append((m.start(grp), m.end(grp)))
                # Location id only. ``val`` contributes its length, never its bytes.
                fp = fingerprint(rid, path, lineno)
                findings.append(Finding(path, lineno, rid, "info" if is_canary else sev, desc,
                                        format_preview(rid, len(val), fp), fp, is_canary))
        for m in GENERIC.finditer(line):
            val = m.group(1)
            if any(s <= m.start(1) < e for s, e in spans):
                continue  # already caught by a specific rule
            if PLACEHOLDER.search(val) or val.isdigit() or len(set(val)) < 6:
                continue
            if re.fullmatch(r"[0-9a-f]{32,64}", val):  # looks like a plain hash, not a credential
                continue
            if entropy(val) < 3.5:
                continue
            spans.append((m.start(1), m.end(1)))
            is_canary = CANARY_MARK in val
            rid = "generic-high-entropy"
            fp = fingerprint(rid, path, lineno)
            findings.append(Finding(path, lineno, rid, "info" if is_canary else "medium",
                                    "High-entropy value assigned to a secret-like name",
                                    format_preview(rid, len(val), fp), fp, is_canary))
        if show_context and spans:
            ctx = redact_line(line, spans)
            for f in findings:
                if f.line == lineno and f.context is None:
                    f.context = ctx
    return findings


def _looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def iter_files(roots: Iterable[str], skip_dirs=SKIP_DIRS, max_bytes=MAX_BYTES, exclude: Iterable[str] = ()) -> Iterator[str]:
    exclude = [os.path.abspath(e) for e in exclude]
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dp, dns, fns in os.walk(root, followlinks=False):
            adp = os.path.abspath(dp)
            if any(adp == e or adp.startswith(e + os.sep) for e in exclude):
                dns[:] = []
                continue
            dns[:] = [d for d in dns if d not in skip_dirs]
            for fn in fns:
                p = os.path.join(dp, fn)
                if os.path.splitext(fn)[1].lower() in SKIP_EXT or os.path.islink(p):
                    continue
                try:
                    if os.path.getsize(p) > max_bytes:
                        continue
                except OSError:
                    continue
                yield p


def scan_path(path: str, show_context: bool = False) -> List[Finding]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES + 1)
    except (OSError, PermissionError):
        return []
    if _looks_binary(data[:4096]):
        return []
    return scan_text(data.decode("utf-8", "replace"), path, show_context)


def scan_paths(roots: Iterable[str], show_context: bool = False, exclude: Iterable[str] = ()):
    """Yield (findings, files_scanned_so_far) lazily."""
    n = 0
    for p in iter_files(roots, exclude=exclude):
        n += 1
        yield scan_path(p, show_context), n


def scan_processes(show_context: bool = False) -> List[Finding]:
    """Scan /proc/*/cmdline for secrets (Linux only, read-only).

    Only command lines are scanned; environment values are never read.
    """
    out: List[Finding] = []
    if not os.path.isdir("/proc"):
        return out
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read(20000).replace(b"\x00", b" ").decode("utf-8", "replace")
        except (OSError, PermissionError):
            continue
        out.extend(scan_text(cmd, f"proc:{pid}", show_context))
    return out
