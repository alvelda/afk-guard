"""Check OpenClaw / MCP client config files against the bundled advisory list.

Python 3.11+ reads TOML with ``tomllib``. Python 3.9 and 3.10 use the conditional
``tomli`` dependency. A missing parser, a broken install, and a parser crash are
separate notes. None of those notes includes the config body.


Pin state (``afk-guard/mcp-pins/v1``) records a syntax-validated package pin and a
content hash of the non-secret launch projection. The hash is SHA-256 of canonical
JSON (sorted keys, compact separators), prefixed ``sha256:``.

Hashed when ``integrity`` is ``full``: server name, command, boolean flags,
path arguments, the syntax-valid package spec, sorted env **key names**,
and URL scheme/host/port/path. Path arguments are part of the hash. ``full``
is not a secret-free claim over path strings (a credential in a path is still
hashed). Env **values** are not hashed and are not stored.

Not hashed, and not a verified pin (``integrity`` ``unsupported``, fail closed, no
baseline write): credential-shaped arguments, URL userinfo, URL query or fragment,
version tails that are not a recognized version, and other args that cannot be
classified without treating them as secret. Those launches are refused rather than
stripped and then described as fully covered.
"""
import hashlib
import importlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

def _try_import(name: str):
    """Return ``(module, status, exc_name)``.

    ``ModuleNotFoundError`` means the module is not installed. Any other import
    failure is ``broken-import`` and ``exc_name`` is that exception's class.
    The exception text is discarded.
    """
    try:
        return importlib.import_module(name), "ok", ""
    except ModuleNotFoundError:
        return None, "missing", ""
    except Exception as exc:
        return None, "broken-import", exc.__class__.__name__


def _load_toml_parser():
    """Return ``(module or None, status, exc_name)``.

    Status is ``ok``, ``missing``, or ``broken-import``. Python 3.11+ uses
    ``tomllib``. Python 3.9 and 3.10 use ``tomli``.
    """
    mod, status, exc_name = _try_import("tomllib")
    if mod is not None:
        return mod, "ok", ""
    if status != "missing":
        return None, status, exc_name
    mod, status, exc_name = _try_import("tomli")
    if mod is not None:
        return mod, "ok", ""
    return None, status, exc_name


_toml, _toml_status, _toml_exc_name = _load_toml_parser()

from .scan import scan_text

DATA = os.path.join(os.path.dirname(__file__), "data", "advisories.json")

# well-known config locations relative to a home directory (only listed if they exist)
KNOWN_CONFIGS = [
    ".cursor/mcp.json", ".claude.json", ".claude/settings.json", ".claude/mcp.json", ".codex/config.toml",
    ".config/Claude/claude_desktop_config.json", "Library/Application Support/Claude/claude_desktop_config.json",
    ".config/Code/User/mcp.json", ".config/Code/User/settings.json", ".vscode/mcp.json", ".gemini/settings.json",
    ".openclaw/openclaw.json", ".openclaw/config.json", ".config/openclaw/config.json", ".config/opencode/opencode.json",
    ".windsurf/mcp.json", ".codeium/windsurf/mcp_config.json", ".mcp.json",
]
PROJECT_CONFIG_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "openclaw.json", "mcp_config.json"}


def load_advisories(path: str = DATA) -> Dict:
    with open(path) as fh:
        return json.load(fh)


def norm(name: str) -> str:
    return name.lower().replace("_", "-")


def vparse(v: str) -> Optional[Tuple[int, ...]]:
    m = re.match(r"^v?(\d+(?:\.\d+)*)", v.strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def vcmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


@dataclass
class Server:
    file: str
    name: str
    command: str
    args: List[str]
    url: str
    env_keys: List[str]
    client: str
    group: str = ""
    launch_flags: Tuple[str, ...] = ()


@dataclass
class Hit:
    file: str
    server: str
    advisory_id: str
    cve: List[str]
    verdict: str          # affected | possibly-affected | check-version | present
    package: str
    version: str
    reason: str
    source: str
    source_url: str
    upstream_url: str
    confidence: str

    def to_dict(self):
        return asdict(self)


def _strip_jsonc(text: str) -> str:
    out, i, n, in_s = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_s:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 1
            elif c == '"':
                in_s = False
        elif c == '"':
            in_s = True; out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 1
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


_GROUP_KEYS = frozenset({"mcpServers", "mcp_servers", "servers", "mcp"})
_LAUNCH_KEYS = ("command", "url", "args", "type", "serverUrl", "httpUrl")


def _looks_like_server(sv: dict) -> bool:
    return any(k in sv for k in _LAUNCH_KEYS)


def _servers_in_map(map_obj: dict, group: Tuple[str, ...]) -> Iterator[Tuple[Tuple[str, ...], str, dict]]:
    """Yield servers inside one mcpServers/mcp/servers map. Nested maps extend ``group``."""
    for sn, sv in map_obj.items():
        if not isinstance(sv, dict):
            continue
        if _looks_like_server(sv):
            yield group, sn, sv
            # A server block can itself wrap another mcp map. Do not treat its keys as names.
            yield from _find_servers(sv, group)
        else:
            yield from _servers_in_map(sv, group + (str(sn),))


def _find_servers(obj, group: Tuple[str, ...] = ()) -> Iterator[Tuple[Tuple[str, ...], str, dict]]:
    """Yield (group path, name, server dict) under mcpServers / mcp_servers / servers / mcp."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _GROUP_KEYS and isinstance(v, dict):
                yield from _servers_in_map(v, group + (k,))
            elif isinstance(v, (dict, list)):
                yield from _find_servers(v, group)
    elif isinstance(obj, list):
        for v in obj:
            yield from _find_servers(v, group)


def parse_config(path: str) -> Tuple[List[Server], List[str]]:
    notes: List[str] = []
    try:
        with open(path, "r", errors="replace") as fh:
            raw = fh.read()
    except OSError as e:
        return [], [f"{path}: unreadable ({e.__class__.__name__})"]
    if path.endswith(".toml"):
        if _toml is None:
            if _toml_status == "broken-import":
                label = _toml_exc_name or "Exception"
                notes.append(f"{path}: TOML parser failed to load ({label}); config skipped")
            else:
                notes.append(f"{path}: TOML parsing unavailable; config skipped")
            return [], notes
        try:
            data = _toml.loads(raw)
        except Exception as exc:
            if exc.__class__.__name__ == "TOMLDecodeError":
                notes.append(f"{path}: could not parse as JSON/TOML; skipped")
            else:
                notes.append(f"{path}: TOML parser crashed ({exc.__class__.__name__}); config skipped")
            return [], notes
    else:
        try:
            data = json.loads(_strip_jsonc(raw))
        except Exception:
            notes.append(f"{path}: could not parse as JSON/TOML; skipped")
            return [], notes
    client = "openclaw" if "openclaw" in path.lower() else os.path.basename(os.path.dirname(path)) or "unknown"
    servers = []
    for group, sn, sv in _find_servers(data):
        args, flags = _coerce_args(sv.get("args", []))
        command, cmd_flags = _coerce_command(sv)
        url, url_flags = _coerce_url(sv)
        env = sv.get("env") if isinstance(sv.get("env"), dict) else {}
        servers.append(Server(
            path, str(sn), command, args, url, sorted(k for k in env if isinstance(k, str)), client,
            group=".".join(group), launch_flags=tuple(flags + cmd_flags + url_flags),
        ))
    return servers, notes


def _coerce_args(raw) -> Tuple[List[str], List[str]]:
    """JSON scalars become strings. Nested values are not stringified (``True``/``None``)."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], ["nonscalar-args"]
    args: List[str] = []
    flags: List[str] = []
    for item in raw:
        if isinstance(item, str):
            args.append(item)
        elif isinstance(item, bool):
            args.append("true" if item else "false")
        elif isinstance(item, int):
            args.append(str(item))
        elif isinstance(item, float):
            args.append(str(item))
        else:
            flags.append("nonscalar-arg")
    return args, flags


def _coerce_command(sv: dict) -> Tuple[str, List[str]]:
    if "command" not in sv or sv.get("command") is None:
        return "", []
    raw = sv.get("command")
    if isinstance(raw, str):
        return raw, []
    return "", ["nonscalar-command"]


def _coerce_url(sv: dict) -> Tuple[str, List[str]]:
    flags: List[str] = []
    for key in ("url", "serverUrl", "httpUrl"):
        if key not in sv or sv.get(key) in (None, ""):
            continue
        raw = sv.get(key)
        if isinstance(raw, str):
            return raw, flags
        flags.append("nonscalar-url")
    return "", flags


def package_of(server: Server) -> Optional[Tuple[str, str, str]]:
    """Return (ecosystem, package name, syntax-valid version or '').

    A version tail that is not a recognized version is not returned. Callers that
    need the refusal use ``package_spec``.
    """
    spec = package_spec(server)
    if not spec:
        return None
    eco, name, ver, status = spec
    if status != "ok":
        return (eco, name, "")
    return (eco, name, ver)


def _name_matches(rule: Dict, eco: str, name: str, server: Server) -> bool:
    names = [norm(rule["name"])] + [norm(x) for x in rule.get("also_names", [])]
    if rule.get("eco") not in ("any", eco):
        return False
    if rule.get("match") == "contains":
        hay = norm(" ".join([server.name, server.url, name]))
        return any(n in hay for n in names)
    return norm(name) in names


def _verdict(rule: Dict, version: str) -> Tuple[str, str]:
    kind = rule["kind"]
    pv = vparse(version) if version and version not in ("latest", "next") else None
    if kind == "incident":
        return "present", "server/URL name matches a vendor incident in the feed; rotate credentials per the advisory"
    if kind == "malicious":
        if rule.get("affected_exact"):
            if pv is None:
                return "check-version", "specific version is malicious; config does not pin a version"
            hit = any(vcmp(pv, vparse(x)) == 0 for x in rule["affected_exact"])
            return ("affected", f"pinned version is the malicious release") if hit else ("not-affected", "")
        if rule.get("affected_range"):
            lo, hi = (vparse(x) for x in rule["affected_range"])
            if pv is None:
                return "check-version", f"versions {rule['affected_range'][0]}-{rule['affected_range'][1]} are malicious; config does not pin a version"
            return ("affected", "pinned version is inside the malicious range") if (vcmp(lo, pv) <= 0 and vcmp(pv, hi) <= 0) else ("not-affected", "")
        return "affected", "package is flagged as malware in the feed (any version)"
    fixed_s = rule.get("fixed_in") or []
    fixed = [vparse(x) for x in fixed_s]
    if not fixed:
        return "check-version", "advisory lists no usable fixed version in the feed; check the upstream advisory"
    if pv is None:
        return "check-version", f"config does not pin a version; fixed in {', '.join(fixed_s)}"
    same_major = [f for f in fixed if f[0] == pv[0]]
    if same_major:
        same_minor = [f for f in same_major if f[:2] == pv[:2]]
        if same_minor:
            f = same_minor[0]
            return ("not-affected", "") if vcmp(pv, f) >= 0 else ("affected", f"pinned {version} is below fixed version {'.'.join(map(str, f))}")
        if vcmp(pv, min(same_major)) < 0:
            return "affected", f"pinned {version} is below fixed version {'.'.join(map(str, min(same_major)))}"
        if vcmp(pv, max(same_major)) >= 0:
            return "not-affected", ""
        return "possibly-affected", f"pinned {version} sits between fix lines {', '.join(fixed_s)}; check your release line"
    if pv[0] > max(f[0] for f in fixed):
        return "not-affected", ""
    if pv[0] < min(f[0] for f in fixed):
        return "affected", f"pinned {version} is on an older major line than the fixed versions ({', '.join(fixed_s)})"
    return "possibly-affected", f"pinned {version} is on a line with no listed fix ({', '.join(fixed_s)}); check upstream"


def check_servers(servers: Iterable[Server], adv: Dict, openclaw_version: Optional[str] = None) -> List[Hit]:
    hits: List[Hit] = []
    for sv in servers:
        pk = package_of(sv)
        for a in adv["advisories"]:
            for rule in a["packages"]:
                eco, name, ver = pk if pk else ("any", sv.name, "")
                if rule.get("match") != "contains" and not pk:
                    continue
                if not _name_matches(rule, eco, name, sv):
                    continue
                verdict, why = _verdict(rule, ver)
                if verdict == "not-affected":
                    continue
                conf = "low (package id unverified)" if rule.get("name_unverified") else ("medium (feed-derived cut-off)" if a["source_type"] == "afk-feed" else "low (survey note, no version data)")
                hits.append(Hit(sv.file, sv.name, a["id"], a.get("cve", []), verdict, name, ver, why, a["source"],
                                a["source_url"], a.get("upstream_url", ""), conf))
    return hits


def openclaw_hits(configs: List[str], adv: Dict, version: Optional[str]) -> List[Hit]:
    """OpenClaw configs rarely record a version. If one is passed in, compare; else mark check-version."""
    hits = []
    oc = [c for c in configs if "openclaw" in c.lower()]
    if not oc:
        return hits
    for a in adv["advisories"]:
        for rule in a["packages"]:
            if rule.get("product") != "openclaw":
                continue
            verdict, why = _verdict(rule, version or "")
            if verdict == "not-affected":
                continue
            if not version:
                why = "OpenClaw config found but version unknown (pass --openclaw-version); " + why
            hits.append(Hit(oc[0], "(openclaw)", a["id"], a.get("cve", []), verdict, "openclaw", version or "", why,
                            a["source"], a["source_url"], a.get("upstream_url", ""),
                            "low (survey note, no version data)" if a["source_type"] != "afk-feed" else "medium (feed-derived cut-off)"))
    return hits


def discover(home: str, roots: Iterable[str] = ()) -> List[str]:
    found = [os.path.join(home, rel) for rel in KNOWN_CONFIGS if os.path.isfile(os.path.join(home, rel))]
    for r in roots:
        if os.path.isfile(r):
            found.append(r)
            continue
        for dp, dns, fns in os.walk(r):
            dns[:] = [d for d in dns if d not in {".git", "node_modules", "site-packages", "__pycache__", ".venv", "venv", ".cache"}]
            for fn in fns:
                if fn in PROJECT_CONFIG_NAMES or fn.endswith(".mcp.json"):
                    found.append(os.path.join(dp, fn))
    return sorted(set(found))


def check_extension_dirs(home: str, adv: Dict) -> List[Dict]:
    out = []
    for base in (".cursor/extensions", ".vscode/extensions", ".vscode-server/extensions"):
        d = os.path.join(home, base)
        if not os.path.isdir(d):
            continue
        names = [n.lower() for n in os.listdir(d)]
        for rule in adv.get("extensions", []):
            for dn in rule["dir_names"]:
                for n in names:
                    if n.startswith(dn):
                        out.append({"advisory_id": rule["id"], "path": os.path.join(d, n), "source": rule["source"],
                                    "source_url": rule["source_url"], "upstream_url": rule["upstream_url"]})
    return out


def hygiene(servers: Iterable[Server], configs: List[str]) -> List[Dict]:
    """Three cheap hygiene checks. Secret values are never printed."""
    out = []
    for c in configs:
        try:
            with open(c, errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for f in scan_text(text, c):
            if not f.canary:
                out.append({"file": c, "line": f.line, "check": "plaintext-secret-in-config", "rule": f.rule,
                            "severity": "high", "preview": f.preview, "fingerprint": f.fingerprint})
    for sv in servers:
        spec = package_spec(sv)
        if spec and spec[3] != "ok":
            # Rejected version tails are an integrity finding, not an "unpinned" claim.
            pass
        else:
            pk = package_of(sv)
            if pk and pk[0] == "npm" and pk[2] in ("", "latest", "next"):
                out.append({"file": sv.file, "server": sv.name, "check": "unpinned-package", "severity": "medium",
                            "package": pk[1]})
        if sv.url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", sv.url):
            out.append({"file": sv.file, "server": sv.name, "check": "remote-http-no-tls", "severity": "medium"})
    return out


# --- pin / hash / drift (C3) -------------------------------------------------

MCP_CHECK_SCHEMA = "afk-guard/mcp-check/v1"
MCP_PINS_SCHEMA = "afk-guard/mcp-pins/v1"
# CI fail severities. ``info`` does not fail the mcp-check process.
GATE_SEVERITIES = ("high", "medium")
DRIFT_CHECKS = (
    "pin-drift",
    "content-hash-drift",
    "server-added",
    "server-removed",
    "pin-state-unreadable",
    "pin-state-schema",
    "pin-state-unwritable",
)
SAFETY_CHECKS = (
    "launch-integrity-unsupported",
    "duplicate-server-name",
    "config-unparseable",
    "pin-state-permissions",
)
BLOCKING_CHECKS = DRIFT_CHECKS + SAFETY_CHECKS

# Recognized package versions only. Anything else in the version slot is refused
# and is not stored. Tags are the two floating names hygiene already treats as unpinned.
_VERSION_TAGS = frozenset({"latest", "next"})
_SEMVER = re.compile(
    r"^v?(?:0|[1-9]\d{0,5})(?:\.(?:0|[1-9]\d{0,5})){0,3}"
    r"(?:-(?:[0-9A-Za-z]{1,10})(?:\.(?:[0-9A-Za-z]{1,10})){0,3})?$"
)
_NPM_SPEC = re.compile(r"^(@[^/@]+/[^@]+|[^@]+)(?:@(.+))?$")
_PY_SPEC = re.compile(r"^([A-Za-z0-9._-]+)(?:(?:==|@)(.+))?$")
_CREDENTIAL_FLAG = re.compile(
    r"^(?:token|password|passwd|secret|api[-_]?key|apikey|authorization|auth|credential|access[-_]?key|bearer|header)$",
    re.I,
)
_SAFE_FLAG_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
# A path must contain a slash so a bare token is not treated as a path.
_SAFE_PATH = re.compile(r"^(?:[A-Za-z]:)?(?:\.{1,2}/|/)[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_SAFE_WORD = re.compile(r"^[a-z][a-z0-9._-]{0,31}$")
_SAFE_NUMBER = re.compile(r"^\d{1,6}$")
_SAFE_DOTTED = re.compile(r"^[0-9]+(?:\.[0-9]+){0,3}$")
_TOKEN_SHAPED = re.compile(
    r"(?i)(?:ghp_|gho_|github_pat_|sk-|sk_|xox[baprs]-|^AKIA[0-9A-Z]{8,}|Bearer\s+|eyJ[A-Za-z0-9_-]{8,})"
)
_URL_SCHEMES = frozenset({"http", "https", "ws", "wss"})
_PY_VALUE_FLAGS = frozenset({"--from", "--with", "-p", "--python"})
_HASH_COVERAGE = (
    "sha256 of canonical JSON: name, command, boolean flags, path arguments, "
    "syntax-valid package identity, sorted env key names, URL scheme/host/port/path. "
    "Path arguments are included; full is not a secret-free claim over path strings. "
    "Env values are omitted. Credential-shaped args, URL userinfo, URL query/fragment, "
    "unrecognized version tails, and unclassified args are unsupported: they are not hashed "
    "and no verified baseline is written."
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def notes_indicate_parse_failure(notes: Iterable[str]) -> bool:
    for note in notes:
        if any(marker in note for marker in (
            "could not parse",
            "unreadable",
            "TOML parsing unavailable",
            "TOML parser failed to load",
            "TOML parser crashed",
        )):
            return True
    return False


def pin_path(path: str) -> str:
    """Absolute path for pin keys. Not realpath (symlink paths can still differ)."""
    return os.path.abspath(path)


def server_key(server: Server) -> str:
    return pin_path(server.file) + "\n" + (server.group or "") + "\n" + server.name


def _version_ok(version: str) -> bool:
    if version in _VERSION_TAGS:
        return True
    return _SEMVER.fullmatch(version) is not None


def _add_reason(reasons: List[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def _split_flag(arg: str) -> Optional[Tuple[str, Optional[str]]]:
    """Return (name, inline value or None) for a flag, else None."""
    if not arg.startswith("-") or arg == "-":
        return None
    body = arg[2:] if arg.startswith("--") else arg[1:]
    if not body or body.startswith("-"):
        return None
    if "=" in body:
        name, val = body.split("=", 1)
        return name, val
    return body, None


def _is_safe_value(value: str) -> bool:
    if not value or _TOKEN_SHAPED.search(value):
        return False
    if _SAFE_NUMBER.fullmatch(value) or _SAFE_DOTTED.fullmatch(value):
        return True
    if _SAFE_WORD.fullmatch(value) or _SAFE_PATH.fullmatch(value):
        return True
    return False


def _classify_url(url: str) -> Tuple[Optional[Dict], List[str]]:
    """Return a non-secret URL projection, or reasons the URL cannot be covered."""
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None:
        return None, ["url-userinfo"]
    if parts.query or parts.fragment:
        return None, ["url-query"]
    if parts.scheme not in _URL_SCHEMES or not parts.hostname:
        return None, ["url-unclassified"]
    return {
        "scheme": parts.scheme,
        "host": parts.hostname,
        "port": parts.port or 0,
        "path": parts.path or "",
    }, []


def _empty_url() -> Dict:
    return {"scheme": "", "host": "", "port": 0, "path": ""}


def _command_ok(command: str) -> bool:
    if command == "":
        return True
    if "://" in command or "@" in command or _TOKEN_SHAPED.search(command):
        return False
    return re.fullmatch(r"[A-Za-z0-9_./+-]+", command) is not None


def _finish_spec(eco: str, name: str, raw: Optional[str]) -> Tuple[str, str, str, str]:
    """Drop the raw tail unless it is a recognized version. Never return the raw tail."""
    if not raw:
        return (eco, name, "", "ok")
    if _version_ok(raw):
        return (eco, name, raw, "ok")
    return (eco, name, "", "version-syntax")


def package_spec(server: Server) -> Optional[Tuple[str, str, str, str]]:
    """Return (ecosystem, name, version, status) or None.

    ``status`` is ``ok`` or ``version-syntax``. ``version`` is empty unless the
    tail matched a recognized version. The raw tail is never part of the tuple.
    """
    found = _find_package(server)
    return found[0] if found else None


def _find_package(server: Server) -> Optional[Tuple[Tuple[str, str, str, str], int]]:
    """Return (spec, index into ``server.args``) for the launcher package arg."""
    cmd = os.path.basename(server.command or "").lower()
    args = list(server.args)
    base = 0
    if cmd in ("pnpm", "yarn") and args and args[0] in ("dlx", "exec"):
        base, args, cmd = 1, args[1:], "npx"
    if cmd in ("npx", "bunx", "pnpx", "npm"):
        if cmd == "npm" and args and args[0] in ("exec", "x"):
            base += 1
            args = args[1:]
        elif cmd == "npm":
            return None
        for offset, arg in enumerate(args):
            if arg.startswith("-"):
                continue
            match = _NPM_SPEC.fullmatch(arg)
            if not match:
                return None
            name = match.group(1)
            if not re.fullmatch(r"(@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|[A-Za-z0-9._-]+)", name):
                return None
            return _finish_spec("npm", name, match.group(2)), base + offset
        return None
    if cmd in ("uvx", "pipx", "uv"):
        if cmd == "uv" and args[:1] == ["tool"]:
            drop = 2 if args[1:2] == ["run"] else 1
            base += drop
            args = args[drop:]
        elif cmd == "uv" and args[:1] == ["run"]:
            base += 1
            args = args[1:]
        skip_next = False
        for offset, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if arg in _PY_VALUE_FLAGS:
                skip_next = True
                continue
            if arg.startswith("-"):
                continue
            match = _PY_SPEC.fullmatch(arg)
            if not match:
                return None
            return _finish_spec("pypi", match.group(1), match.group(2)), base + offset
        return None
    if cmd.startswith("python") and "-m" in args:
        i = args.index("-m")
        if i + 1 < len(args) and _is_safe_value(args[i + 1].split(".")[0]):
            name = args[i + 1].split(".")[0].replace("_", "-")
            return ("pypi", name, "", "ok"), i + 1
    return None


def _canonical_spec(eco: str, name: str, version: str) -> str:
    return f"{eco}:{name}@{version}" if version else f"{eco}:{name}"


def _classify_args(server: Server) -> Tuple[List[str], List[str], Optional[Tuple[str, str, str, str]]]:
    """Classify args. On any refusal, ``safe_args`` is empty so nothing secret is hashed."""
    reasons: List[str] = []
    safe: List[str] = []
    found = _find_package(server)
    spec = found[0] if found else None
    package_at = found[1] if found else None
    if spec and spec[3] != "ok":
        _add_reason(reasons, spec[3])
    args = list(server.args)
    kind = _launcher_kind(server)
    skip_next = False
    for index, arg in enumerate(args):
        if skip_next:
            skip_next = False
            if _TOKEN_SHAPED.search(arg) or not _is_safe_value(arg):
                _add_reason(reasons, "opaque-arg")
            elif not reasons:
                safe.append(arg)
            continue
        flag = _split_flag(arg)
        if flag:
            name, inline = flag
            if _CREDENTIAL_FLAG.fullmatch(name):
                _add_reason(reasons, "credential-arg")
                if inline is None and index + 1 < len(args) and not args[index + 1].startswith("-"):
                    skip_next = True
                continue
            if inline is None and kind == "pypi" and (arg in _PY_VALUE_FLAGS or f"--{name}" in _PY_VALUE_FLAGS):
                if not reasons:
                    safe.append(arg if arg.startswith("--") else f"-{name}")
                skip_next = True
                continue
            if inline is None and _SAFE_FLAG_NAME.fullmatch(name) and "=" not in arg:
                if not reasons:
                    safe.append(arg)
                continue
            if inline is not None and _SAFE_FLAG_NAME.fullmatch(name) and _is_safe_value(inline):
                if not reasons:
                    safe.append(arg)
                continue
            _add_reason(reasons, "opaque-arg")
            continue
        if "://" in arg:
            _doc, url_reasons = _classify_url(arg)
            if url_reasons:
                for code in url_reasons:
                    _add_reason(reasons, code)
            elif not reasons and _doc is not None:
                safe.append("{scheme}://{host}:{port}{path}".format(**{
                    "scheme": _doc["scheme"], "host": _doc["host"], "port": _doc["port"], "path": _doc["path"],
                }))
            continue
        if package_at == index and spec is not None:
            if spec[3] == "ok" and not reasons:
                safe.append(_canonical_spec(spec[0], spec[1], spec[2]))
            continue
        if _TOKEN_SHAPED.search(arg):
            _add_reason(reasons, "credential-arg")
            continue
        if _is_safe_value(arg):
            if not reasons:
                safe.append(arg)
            continue
        _add_reason(reasons, "opaque-arg")
    if reasons:
        safe = []
    return reasons, safe, spec


def _launcher_kind(server: Server) -> Optional[str]:
    cmd = os.path.basename(server.command or "").lower()
    args = list(server.args)
    if cmd in ("pnpm", "yarn") and args and args[0] in ("dlx", "exec"):
        return "npm"
    if cmd in ("npx", "bunx", "pnpx"):
        return "npm"
    if cmd == "npm" and args and args[0] in ("exec", "x"):
        return "npm"
    if cmd in ("uvx", "pipx", "uv"):
        return "pypi"
    if cmd.startswith("python"):
        return "python"
    return None


def assess_launch(server: Server) -> Dict:
    """Project a server onto the hash coverage, or mark it unsupported.

    The returned dict never contains credential values or unrecognized version tails.
    """
    reasons: List[str] = []
    for flag in server.launch_flags:
        _add_reason(reasons, flag)
    if not _command_ok(server.command or ""):
        _add_reason(reasons, "command-unclassified")
    url_doc = _empty_url()
    if server.url:
        classified, url_reasons = _classify_url(server.url)
        if url_reasons:
            for code in url_reasons:
                _add_reason(reasons, code)
        elif classified is not None:
            url_doc = classified
    arg_reasons, safe_args, spec = _classify_args(server)
    for code in arg_reasons:
        _add_reason(reasons, code)
    eco, name, ver = ("", "", "")
    if spec:
        eco, name, ver = spec[0], spec[1], spec[2] if spec[3] == "ok" else ""
        if spec[3] != "ok":
            _add_reason(reasons, spec[3])
    view = {
        "integrity": "unsupported" if reasons else "full",
        "reasons": list(reasons),
        "ecosystem": eco,
        "package": name,
        "pin": ver if not reasons or "version-syntax" not in reasons else "",
        "content_hash": None,
    }
    # A recognized pin may still be recorded in memory, but a hash is only minted
    # when every part of the projection is covered. Stripped secrets are not hashed.
    if reasons:
        view["pin"] = ver if "version-syntax" not in reasons else ""
        return view
    payload = {
        "args": safe_args,
        "command": server.command or "",
        "env_keys": list(server.env_keys),
        "name": server.name,
        "package": {"ecosystem": eco, "name": name, "version": ver},
        "url": url_doc,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    view["content_hash"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    view["pin"] = ver
    return view


def content_hash(server: Server) -> str:
    """Hash of the full non-secret projection. Refuses launches that cannot be covered."""
    view = assess_launch(server)
    if view["integrity"] != "full" or not view["content_hash"]:
        raise ValueError("launch integrity unsupported")
    return view["content_hash"]


def pin_record(server: Server) -> Dict:
    view = assess_launch(server)
    rec = {
        "server_key": server_key(server),
        "file": pin_path(server.file),
        "server": server.name,
        "group": server.group,
        "client": server.client,
        "ecosystem": view["ecosystem"],
        "package": view["package"],
        "pin": view["pin"],
        "integrity": view["integrity"],
    }
    if view["reasons"]:
        rec["integrity_reasons"] = list(view["reasons"])
    if view["integrity"] == "full" and view["content_hash"]:
        rec["content_hash"] = view["content_hash"]
    return rec


def pin_records(servers: Iterable[Server]) -> List[Dict]:
    """One record per group+name. Identical parser duplicates collapse; different groups do not."""
    by_key = {}
    for server in servers:
        rec = pin_record(server)
        by_key[rec["server_key"]] = rec
    return [by_key[key] for key in sorted(by_key)]


def _pin_label(rec: Dict) -> str:
    eco = rec.get("ecosystem") or ""
    pkg = rec.get("package") or ""
    pin = rec.get("pin") or ""
    if not pkg and not pin:
        return "unpinned"
    base = f"{eco}:{pkg}" if (eco or pkg) else "package"
    return f"{base}@{pin or 'unpinned'}"


def _finding(check: str, severity: str, message: str, file: str = "", server: str = "",
             rule: Optional[str] = None, **extra) -> Dict:
    item = {"check": check, "severity": severity, "file": file, "server": server,
            "rule": rule or check, "message": message}
    for key, value in extra.items():
        if value is not None:
            item[key] = value
    return item


def integrity_findings(records: Iterable[Dict]) -> List[Dict]:
    findings = []
    for rec in records:
        if rec.get("integrity", "full") == "full":
            continue
        reasons = ",".join(rec.get("integrity_reasons") or ["unclassified"])
        findings.append(_finding(
            "launch-integrity-unsupported", "high",
            f"MCP server '{rec.get('server', '')}' launch cannot be integrity-checked ({reasons}); no verified pin was recorded",
            file=rec.get("file", ""), server=rec.get("server", ""),
            server_key=rec.get("server_key"), integrity="unsupported",
        ))
    return findings


def duplicate_findings(records: Iterable[Dict]) -> List[Dict]:
    """Same file + server name under more than one group is a conflict, not last-wins."""
    buckets: Dict[Tuple[str, str], List[str]] = {}
    for rec in records:
        buckets.setdefault((rec.get("file", ""), rec.get("server", "")), [])
        group = rec.get("group") or ""
        if group not in buckets[(rec.get("file", ""), rec.get("server", ""))]:
            buckets[(rec.get("file", ""), rec.get("server", ""))].append(group)
    findings = []
    for (file, name), groups in sorted(buckets.items()):
        if len(groups) < 2:
            continue
        listed = ", ".join(groups)
        findings.append(_finding(
            "duplicate-server-name", "high",
            f"MCP server name '{name}' is configured in {len(groups)} groups ({listed}); each group is pinned separately",
            file=file, server=name,
        ))
    return findings


def safety_findings(records: Iterable[Dict]) -> List[Dict]:
    recs = list(records)
    return duplicate_findings(recs) + integrity_findings(recs)


def parse_skip_findings(notes: Iterable[str]) -> List[Dict]:
    """High ``config-unparseable`` findings for configs that were not parsed.

    The check name is already in ``SAFETY_CHECKS``, so ``exit_code`` returns 1
    unless ``--exit-zero``. The message does not include the config body.
    """
    findings = []
    for note in notes:
        if not notes_indicate_parse_failure([note]):
            continue
        findings.append(_finding(
            "config-unparseable", "high",
            "config could not be parsed; result is incomplete",
            file=note.split(":", 1)[0],
        ))
    return findings


def compare_pins(saved: List[Dict], current: List[Dict]) -> List[Dict]:
    """High-severity findings when a covered pin or content hash drifted.

    Unsupported current launches are not described as a pin change and are not
    treated as a removal; ``integrity_findings`` reports them.
    """
    prev = _index_pins(saved)
    cur = _index_pins(current)
    findings = []
    for key in sorted(set(prev) | set(cur)):
        old, new = prev.get(key), cur.get(key)
        if new and new.get("integrity", "full") != "full":
            continue
        if old and not new:
            findings.append(_finding(
                "server-removed", "high",
                f"MCP server '{old.get('server', '')}' was removed since the pin state was recorded ({_pin_label(old)})",
                file=old.get("file", ""), server=old.get("server", ""),
                server_key=key, package=old.get("package") or None, pin=old.get("pin") or None,
                content_hash=old.get("content_hash"),
            ))
            continue
        if new and not old:
            findings.append(_finding(
                "server-added", "high",
                f"MCP server '{new.get('server', '')}' was added since the pin state was recorded ({_pin_label(new)})",
                file=new.get("file", ""), server=new.get("server", ""),
                server_key=key, package=new.get("package") or None, pin=new.get("pin") or None,
                content_hash=new.get("content_hash"),
            ))
            continue
        pin_changed = (old.get("pin"), old.get("package"), old.get("ecosystem")) != (
            new.get("pin"), new.get("package"), new.get("ecosystem"))
        hash_changed = old.get("content_hash") != new.get("content_hash")
        if pin_changed:
            extra = " and content hash changed" if hash_changed else ""
            findings.append(_finding(
                "pin-drift", "high",
                f"MCP server '{new.get('server', '')}' pin changed from {_pin_label(old)} to {_pin_label(new)}{extra}",
                file=new.get("file", ""), server=new.get("server", ""),
                server_key=key, package=new.get("package") or None, pin=new.get("pin") or None,
                previous_pin=old.get("pin") or "", previous_package=old.get("package") or "",
                content_hash=new.get("content_hash"), previous_content_hash=old.get("content_hash"),
            ))
        elif hash_changed:
            findings.append(_finding(
                "content-hash-drift", "high",
                f"MCP server '{new.get('server', '')}' content hash changed and pin is unchanged ({_pin_label(new)})",
                file=new.get("file", ""), server=new.get("server", ""),
                server_key=key, package=new.get("package") or None, pin=new.get("pin") or None,
                content_hash=new.get("content_hash"), previous_content_hash=old.get("content_hash"),
            ))
    return findings


def _index_pins(records: List[Dict]) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    for rec in records:
        if not isinstance(rec, dict) or not isinstance(rec.get("server_key"), str):
            raise ValueError("pin record missing server_key")
        out[rec["server_key"]] = rec
    return out


def pin_document(records: List[Dict], version: str, generated_at: str) -> Dict:
    covered = [rec for rec in records if rec.get("integrity", "full") == "full"]
    return {
        "schema": MCP_PINS_SCHEMA,
        "tool": "mcp-check",
        "version": version,
        "generated_at": generated_at,
        "hash_coverage": _HASH_COVERAGE,
        "servers": sorted(covered, key=lambda r: r["server_key"]),
    }


def _write_pin_state(path: str, records: List[Dict], version: str, generated_at: str) -> None:
    text = json.dumps(pin_document(records, version, generated_at), indent=2, sort_keys=True) + "\n"
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".afk-pins-", suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fd = None
            fh.write(text)
        os.replace(tmp, path)
        tmp = None
        os.chmod(path, 0o600)
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise


def _read_pin_text(path: str) -> Tuple[Optional[str], Optional[Dict]]:
    """Read pin JSON. Repair a regular file that is readable by group or other."""
    try:
        st = os.lstat(path)
    except OSError:
        return None, _finding("pin-state-unreadable", "high", "pin state could not be read", file=path)
    if stat.S_ISLNK(st.st_mode):
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read(), None
        except OSError:
            return None, _finding("pin-state-unreadable", "high", "pin state could not be read", file=path)
    if not stat.S_ISREG(st.st_mode):
        return None, _finding("pin-state-unreadable", "high", "pin state path is not a regular file", file=path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None, _finding("pin-state-unreadable", "high", "pin state could not be read", file=path)
    try:
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        if mode & 0o077:
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                return None, _finding(
                    "pin-state-permissions", "high",
                    "pin state is readable by group or other and could not be repaired to owner-only",
                    file=path,
                )
        with os.fdopen(fd, "r", errors="replace") as fh:
            fd = None
            return fh.read(), None
    finally:
        if fd is not None:
            os.close(fd)


def reconcile_pin_state(path: str, records: List[Dict], version: str, generated_at: str,
                        update: bool = False, parse_failed: bool = False) -> List[Dict]:
    """Record pins when the file is missing (or ``update``), otherwise report drift.

    An unparseable config does not create a 0-server baseline. A launch that cannot
    be integrity-checked does not create a verified baseline. An existing pin file
    is not rewritten unless ``update`` is set and the current launch is covered.
    """
    records = sorted(records, key=lambda r: r["server_key"])
    existed = os.path.lexists(path)
    unsupported = any(rec.get("integrity", "full") != "full" for rec in records)
    if (update or not existed) and (parse_failed or unsupported):
        findings = safety_findings(records)
        if parse_failed:
            findings.insert(0, _finding(
                "config-unparseable", "high",
                "config could not be parsed; no pin baseline was written",
                file=path,
            ))
        return findings
    if update or not existed:
        try:
            _write_pin_state(path, records, version, generated_at)
        except OSError:
            return [_finding("pin-state-unwritable", "high", "could not write pin state", file=path)]
        check = "pin-baseline-updated" if update and existed else "pin-baseline-recorded"
        verb = "updated" if check == "pin-baseline-updated" else "recorded"
        return [_finding(check, "info", f"{verb} {len(records)} MCP server pin(s)", file=path, count=len(records))] + safety_findings(records)
    text, problem = _read_pin_text(path)
    if problem:
        return [problem]
    try:
        doc = json.loads(text or "")
    except json.JSONDecodeError:
        return [_finding("pin-state-unreadable", "high", "pin state could not be read as JSON", file=path)]
    if not isinstance(doc, dict) or doc.get("schema") != MCP_PINS_SCHEMA or not isinstance(doc.get("servers"), list):
        return [_finding("pin-state-schema", "high", f"pin state schema is not {MCP_PINS_SCHEMA}", file=path)]
    try:
        findings = safety_findings(records) + compare_pins(doc["servers"], records)
    except ValueError:
        return [_finding("pin-state-schema", "high", f"pin state schema is not {MCP_PINS_SCHEMA}", file=path)]
    if parse_failed and not records:
        # Preserved behavior once a baseline exists: an unparseable config looks like removal.
        return findings
    if parse_failed:
        findings.insert(0, _finding(
            "config-unparseable", "high",
            "config could not be parsed; pin state was not rewritten",
            file=path,
        ))
    return findings


def _advisory_severity(verdict: str) -> str:
    return "high" if verdict in ("affected", "present") else "medium"


def build_report(version: str, generated_at: str, configs: List[str], servers: List[Server], adv: Dict,
                 hits: List[Hit], ext: List[Dict], hyg: List[Dict], notes: List[str],
                 pins: List[Dict], pin_findings: List[Dict]) -> Dict:
    """JSON envelope ``afk-guard/mcp-check/v1``."""
    findings: List[Dict] = []
    for h in hits:
        findings.append(_finding(
            "advisory", _advisory_severity(h.verdict), h.reason, file=h.file, server=h.server, rule=h.advisory_id,
            verdict=h.verdict, package=h.package or None, pin=h.version or None,
            advisory_id=h.advisory_id, confidence=h.confidence, source_url=h.source_url,
        ))
    for e in ext:
        findings.append(_finding(
            "extension", "high", f"extension matches {e.get('advisory_id', '')}",
            file=e.get("path", ""), rule=e.get("advisory_id"),
            advisory_id=e.get("advisory_id"), source_url=e.get("source_url"),
        ))
    for item in hyg:
        check = item.get("check") or "hygiene"
        extra = {}
        for key in ("preview", "fingerprint", "line", "package"):
            if item.get(key) not in (None, ""):
                extra[key] = item[key]
        findings.append(_finding(
            check, item.get("severity") or "medium", check,
            file=item.get("file", ""), server=item.get("server", ""), rule=item.get("rule") or check, **extra,
        ))
    findings.extend(pin_findings)
    return {
        "schema": MCP_CHECK_SCHEMA,
        "tool": "mcp-check",
        "version": version,
        "generated_at": generated_at,
        "findings": findings,
        "gate": {
            "fail_severities": list(GATE_SEVERITIES),
            "drift_checks": list(DRIFT_CHECKS),
            "safety_checks": list(SAFETY_CHECKS),
            "hash_coverage": _HASH_COVERAGE,
            "process_exit": (
                "Exit 1 when advisory hits, extension hits, pin drift, or safety findings "
                "with severity high or medium are present, unless --exit-zero. An unparseable "
                "config is a high config-unparseable safety finding, including when no pin file "
                "is requested. Severity info (baseline recorded or refreshed) does not fail the "
                "process. Hygiene findings carry severity for CI but do not by themselves change "
                "the process exit."
            ),
        },
        "configs": list(configs),
        "servers": len(servers),
        "advisory_db": {
            "count": len(adv["advisories"]),
            "generated_at": adv["generated_at"],
            "feed_sha256": adv["feed"]["sha256"],
        },
        "hits": [h.to_dict() for h in hits],
        "extension_hits": ext,
        "hygiene": hyg,
        "notes": notes,
        "pins": pins,
    }


def exit_code(hits: List[Hit], ext: List[Dict], pin_findings: List[Dict], exit_zero: bool) -> int:
    """Non-zero when advisory hits, extension hits, drift, or safety findings block."""
    if exit_zero:
        return 0
    blocking = [f for f in pin_findings if f.get("check") in BLOCKING_CHECKS and f.get("severity") in GATE_SEVERITIES]
    return 1 if hits or ext or blocking else 0
