"""Redaction helpers. Output never contains secret-derived characters.

Preview = ``[REDACTED]`` + rule id + length bucket + location fingerprint.
The length bucket is coarse (not the exact length). No characters from the
secret are copied, including a short prefix.

The location fingerprint is a short SHA-256 of non-secret ids only:
``rule_id``, the normalized path, and the line number. Secret bytes are
never hashed. v1 does not dedupe by credential value, so the same secret in
two places does not share an id. Collision risk is accepted: two different
values with the same rule, path, and line share one fingerprint, and a short
digest can also collide across locations. The id is not a secret identifier
and is not proof of uniqueness.
"""
import hashlib
import os

# Coarse buckets. Exact lengths are not shown.
_BUCKETS = (
    (8, "lt8"),
    (16, "8-15"),
    (32, "16-31"),
    (64, "32-63"),
    (128, "64-127"),
    (256, "128-255"),
)


def normalize_path(path: str) -> str:
    """Normalize a path for fingerprinting. Does not read the filesystem."""
    if path is None:
        return ""
    text = str(path).replace("\\", "/")
    if text in ("", "<text>", "<stdin>"):
        return text
    return os.path.normpath(text).replace("\\", "/")


def length_bucket(n: int) -> str:
    """Map a character count to a coarse bucket. Not the exact length."""
    n = 0 if n is None else int(n)
    for limit, label in _BUCKETS:
        if n < limit:
            return label
    return "256+"


def fingerprint(rule_id: str, path: str, line: int) -> str:
    """Short hash of rule id + normalized path + line. Never hashes secret bytes.

    There is no credential-value dedupe. Same secret, different location →
    different id. Same rule, path, and line → same id even if the values differ.
    """
    material = f"{rule_id}\n{normalize_path(path)}\n{int(line)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:8]


def format_preview(rule_id: str, length: int, fingerprint_id: str) -> str:
    """Build a preview from non-secret fields only."""
    return f"[REDACTED] {rule_id} len={length_bucket(length)} id={fingerprint_id}"


def redact(value: str, rule_id: str = "value", path: str = "", line: int = 0) -> str:
    """Preview a value. ``value`` is used only for its length, never its characters."""
    n = len(value) if value else 0
    return format_preview(rule_id, n, fingerprint(rule_id, path, line))


def _merge_spans(line: str, spans):
    """Union of half-open spans, clamped to ``line``. Order does not matter.

    Overlap, containment, equal starts, and adjacent spans become one interval.
    A later span that starts inside an earlier one still extends the mask
    through its own end. Disjoint spans stay disjoint.
    """
    n = len(line)
    cleaned = []
    for raw in spans or ():
        try:
            s, e = raw
            s, e = int(s), int(e)
        except (TypeError, ValueError):
            continue
        if s < 0:
            s = 0
        if e > n:
            e = n
        if s < e:
            cleaned.append((s, e))
    if not cleaned:
        return []
    cleaned.sort()
    merged = [list(cleaned[0])]
    for s, e in cleaned[1:]:
        if s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1][1] = e
        else:
            merged.append([s, e])
    return [(s, e) for s, e in merged]


def redact_line(line: str, spans) -> str:
    """Return the line with the union of spans replaced by ``[REDACTED]``.

    The replacement is a fixed mask. No characters from any span are kept,
    including the tail of an overlapping span that extends past an earlier one.
    """
    out, last = [], 0
    for s, e in _merge_spans(line, spans):
        out.append(line[last:s])
        out.append("[REDACTED]")
        last = e
    out.append(line[last:])
    text = "".join(out).strip()
    return text if len(text) <= 160 else text[:157] + "..."
