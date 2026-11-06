"""Local-only canary tokens.

A canary is a fake credential planted in a decoy file. Every value carries the marker
AFKGUARD plus a random id, and is NOT a valid credential for any service (we never contact
a vendor). We tell you if a canary file was touched or if its value shows up in logs you own.
Optionally a canary can point at YOUR OWN local listener (`canary listen`), which logs hits to
a JSONL file. Nothing leaves the machine.
"""
import hashlib
import json
import os
import secrets
import stat
import string
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Iterable, List, Optional

REGISTRY_NAME = ".afk-guard-canaries.json"
KINDS = ("aws", "github", "openai", "stripe-test", "env", "mcp")
# The registry directory is the directory the caller names. It must be exactly
# mode 0700, owned by this user, and not a symlink. Ancestors are not walked
# (R10, DEF-007 closed): a sticky parent such as /tmp above that directory is
# accepted. This does not claim protection against root or a replaced mount.


class CanaryRegistryError(Exception):
    """Registry access refused. The message never includes registry contents."""
_ALNUM_UP = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_value(kind: str, cid: str) -> str:
    """Return a fake credential in the shape of the real thing, containing AFKGUARD + id."""
    tag = "AFKGUARD" + cid  # 8 + 8 = 16 chars
    if kind == "aws":      # AKIA + 16 upper-alnum
        return "AKIA" + tag.upper()[:16]
    if kind == "github":   # ghp_ + 36
        return "ghp_" + tag + _rand(_ALNUM, 36 - len(tag))
    if kind == "openai":   # sk-proj- + body
        return "sk-proj-" + tag + _rand(_ALNUM, 32)
    if kind == "stripe-test":  # test prefix on purpose: never looks like a live key to other scanners
        return "sk_test_" + tag + _rand(_ALNUM, 16)
    raise ValueError(f"unknown kind {kind}")


def _render(kind: str, cid: str, callback_url: Optional[str]):
    """Return (relative file name, file content, secret value)."""
    cb = f"\nAFK_CALLBACK_URL={callback_url}/c/{cid}\n" if callback_url else "\n"
    if kind == "aws":
        v = make_value("aws", cid)
        sec = "AFKGUARD" + cid + _rand(_ALNUM, 24)
        return "aws-credentials-backup", f"[default]\naws_access_key_id = {v}\naws_secret_access_key = {sec}\n", v
    if kind == "github":
        v = make_value("github", cid)
        return "github-token.txt", f"GITHUB_TOKEN={v}{cb}", v
    if kind == "openai":
        v = make_value("openai", cid)
        return "openai.env.old", f"OPENAI_API_KEY={v}{cb}", v
    if kind == "stripe-test":
        v = make_value("stripe-test", cid)
        return "stripe-restricted-key.txt", f"STRIPE_API_KEY={v}{cb}", v
    if kind == "env":
        v = make_value("openai", cid)
        return ".env.production.bak", f"DATABASE_URL=postgres://app:AFKGUARD{cid}{_rand(_ALNUM, 12)}@localhost:5432/app\nOPENAI_API_KEY={v}{cb}", v
    if kind == "mcp":
        v = make_value("github", cid)
        cfg = {"mcpServers": {"github-backup": {"command": "npx", "args": ["-y", "@example/github-mcp@1.0.0"],
                                                  "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": v}}}}
        return "mcp.json.bak", json.dumps(cfg, indent=2) + "\n", v
    raise ValueError(f"unknown kind {kind}")


def _sha_fd(fd: int) -> str:
    """Integrity hash of an already-open file. Not a hash of the secret value."""
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _require_posix_dir_fd() -> None:
    """Fail closed when directory-descriptor operations are unavailable.

    Directory operations use ``os.open(..., dir_fd=)`` and ``O_NOFOLLOW``.
    A platform without that support is refused. No ack flag.
    """
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise CanaryRegistryError(
            "canary registry requires POSIX O_DIRECTORY and O_NOFOLLOW; refusing"
        )
    if not hasattr(os, "geteuid"):
        raise CanaryRegistryError("canary registry cannot verify directory ownership on this platform; refusing")
    for fn in (os.open, os.rename, os.unlink, os.stat):
        if fn not in os.supports_dir_fd:
            raise CanaryRegistryError(
                "canary registry requires directory-descriptor file operations; refusing"
            )


def _leaf_name(name: str) -> bool:
    return bool(name) and name not in (".", "..") and "/" not in name and "\\" not in name and "\x00" not in name


def _ensure_registry_directory(directory: str) -> None:
    """Create a missing leaf as mode 0700. Never chmod an existing directory."""
    if os.path.lexists(directory):
        return
    parent = os.path.dirname(os.path.abspath(directory))
    if not parent or not os.path.isdir(parent):
        raise CanaryRegistryError("canary registry directory is missing")
    try:
        os.mkdir(directory, 0o700)
    except OSError:
        raise CanaryRegistryError("canary registry directory could not be created")


def _open_registry_dir(directory: str) -> int:
    """Return a directory fd for an owner-only, non-symlink registry directory.

    Refuses group/other access, the sticky bit, a symlink, or a uid that is not
    the current user. Does not change the directory mode.
    """
    _require_posix_dir_fd()
    try:
        st = os.lstat(directory)
    except OSError:
        raise CanaryRegistryError("canary registry directory is missing or not usable")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise CanaryRegistryError("canary registry directory must be a real directory, not a symlink")
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise CanaryRegistryError(
            "canary registry directory must be owner-only mode 0700; shared or sticky directories are refused"
        )
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise CanaryRegistryError("canary registry directory could not be opened without following links")
    try:
        fst = os.fstat(fd)
        if (not stat.S_ISDIR(fst.st_mode) or fst.st_dev != st.st_dev or fst.st_ino != st.st_ino
                or fst.st_uid != st.st_uid or stat.S_IMODE(fst.st_mode) != 0o700):
            raise CanaryRegistryError("canary registry directory changed while opening; refusing")
    except Exception:
        os.close(fd)
        raise
    return fd


def _stat_at(dirfd: int, name: str):
    try:
        return os.stat(name, dir_fd=dirfd, follow_symlinks=False)
    except OSError:
        return None


def _read_registry(dirfd: int) -> Optional[Dict]:
    """Read the registry through dirfd. Missing file returns None. Loose files are refused."""
    if not _leaf_name(REGISTRY_NAME):
        raise CanaryRegistryError("canary registry name is not a single path component")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        fd = os.open(REGISTRY_NAME, flags, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    except OSError:
        raise CanaryRegistryError("canary registry could not be opened without following links")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise CanaryRegistryError("canary registry must be a regular owner-only file (mode 0600); refusing")
        data = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(fd)
    try:
        doc = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise CanaryRegistryError("canary registry could not be read")
    if not isinstance(doc, dict) or not isinstance(doc.get("canaries", []), list):
        raise CanaryRegistryError("canary registry could not be read")
    doc.setdefault("canaries", [])
    return doc


def _write_registry(dirfd: int, reg: Dict) -> None:
    """Replace the registry via a 0600 temp file in the same directory. Does not follow links."""
    existing = _stat_at(dirfd, REGISTRY_NAME)
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
            raise CanaryRegistryError("canary registry must be a regular file; refusing to follow a link")
        if existing.st_uid != os.geteuid() or stat.S_IMODE(existing.st_mode) != 0o600:
            raise CanaryRegistryError("canary registry must be a regular owner-only file (mode 0600); refusing")
    tmpname = ".afk-canary-" + secrets.token_hex(6) + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(tmpname, flags, 0o600, dir_fd=dirfd)
    try:
        os.fchmod(fd, 0o600)
        payload = (json.dumps(reg, indent=2) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            wrote = os.write(fd, view)
            view = view[wrote:]
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            os.unlink(tmpname, dir_fd=dirfd)
        except OSError:
            pass
        raise
    os.close(fd)
    # Re-check the destination after the temp exists. renameat replaces a directory
    # entry and does not write through a symlink. A symlink seen here is refused
    # so the link and its target stay in place.
    existing = _stat_at(dirfd, REGISTRY_NAME)
    if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
                                 or existing.st_uid != os.geteuid() or stat.S_IMODE(existing.st_mode) != 0o600):
        try:
            os.unlink(tmpname, dir_fd=dirfd)
        except OSError:
            pass
        raise CanaryRegistryError("canary registry must be a regular owner-only file (mode 0600); refusing")
    try:
        os.rename(tmpname, REGISTRY_NAME, src_dir_fd=dirfd, dst_dir_fd=dirfd)
    except OSError:
        try:
            os.unlink(tmpname, dir_fd=dirfd)
        except OSError:
            pass
        raise CanaryRegistryError("canary registry could not be written")
    try:
        os.fsync(dirfd)
    except OSError:
        pass


def _write_leaf(dirfd: int, name: str, content: str) -> Optional[Dict]:
    """Create ``name`` as mode 0600. Returns None if the name already exists. Never follows a link."""
    if not _leaf_name(name):
        raise CanaryRegistryError("canary file name is not a single path component")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, 0o600, dir_fd=dirfd)
    except FileExistsError:
        return None
    except OSError:
        raise CanaryRegistryError("canary file could not be created without following links")
    try:
        os.fchmod(fd, 0o600)
        payload = content.encode("utf-8")
        view = memoryview(payload)
        while view:
            wrote = os.write(fd, view)
            view = view[wrote:]
        os.fsync(fd)
        digest = _sha_fd(fd)
        st = os.fstat(fd)
        if stat.S_IMODE(st.st_mode) != 0o600 or not stat.S_ISREG(st.st_mode):
            raise CanaryRegistryError("canary file mode is not 0600; refusing")
    except Exception:
        os.close(fd)
        try:
            os.unlink(name, dir_fd=dirfd)
        except OSError:
            pass
        raise
    os.close(fd)
    return {"sha256": digest, "mtime": st.st_mtime, "atime": st.st_atime}


def load_registry(directory: str) -> Dict:
    dirfd = _open_registry_dir(directory)
    try:
        doc = _read_registry(dirfd)
    finally:
        os.close(dirfd)
    return doc if doc is not None else {"version": 1, "canaries": []}


def plant(directory: str, kinds: Iterable[str] = KINDS, callback_url: Optional[str] = None) -> List[Dict]:
    """Plant canary files inside `directory`. Never overwrites existing files.

    The directory must be mode 0700 and owned by the current user. An existing
    directory is not chmod'd. A symlink directory or registry is refused.
    """
    _ensure_registry_directory(directory)
    dirfd = _open_registry_dir(directory)
    try:
        reg = _read_registry(dirfd)
        if reg is None:
            reg = {"version": 1, "canaries": []}
        planted = []
        for kind in kinds:
            cid = secrets.token_hex(4)
            name, content, _value = _render(kind, cid, callback_url)
            if not _leaf_name(name):
                raise CanaryRegistryError("canary file name is not a single path component")
            existing = _stat_at(dirfd, name)
            if existing is not None:
                name = f"{cid}-{name}"
            if _stat_at(dirfd, name) is not None:
                continue
            written = _write_leaf(dirfd, name, content)
            if written is None:
                continue
            entry = {"id": cid, "kind": kind, "file": name, "planted_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                     "sha256": written["sha256"], "mtime": written["mtime"], "atime": written["atime"],
                     "marker": "AFKGUARD" + cid, "callback": bool(callback_url)}
            reg["canaries"].append(entry)
            planted.append(entry)
        _write_registry(dirfd, reg)
        return planted
    finally:
        os.close(dirfd)


def check(directory: str, log_paths: Iterable[str] = (), listener_log: Optional[str] = None) -> List[Dict]:
    """Return alerts. Alert types: missing, modified, accessed (atime heuristic), seen-in-log, callback-hit."""
    dirfd = _open_registry_dir(directory)
    try:
        reg = _read_registry(dirfd) or {"version": 1, "canaries": []}
        alerts: List[Dict] = []
        markers = {c["marker"]: c for c in reg["canaries"]}
        for c in reg["canaries"]:
            name = c.get("file") or ""
            if not _leaf_name(name):
                alerts.append({"type": "modified", "id": c.get("id"), "file": name})
                continue
            flags = os.O_RDONLY | os.O_NOFOLLOW
            try:
                fd = os.open(name, flags, dir_fd=dirfd)
            except FileNotFoundError:
                alerts.append({"type": "missing", "id": c["id"], "file": name})
                continue
            except OSError:
                alerts.append({"type": "modified", "id": c["id"], "file": name})
                continue
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or _sha_fd(fd) != c["sha256"]:
                    alerts.append({"type": "modified", "id": c["id"], "file": name})
                # atime is only a hint: relatime/noatime mounts and our own checks can hide or fake it
                if st.st_atime > c["atime"] + 1:
                    alerts.append({"type": "accessed", "id": c["id"], "file": name, "confidence": "low (atime heuristic)"})
            finally:
                os.close(fd)
        for lp in log_paths:
            try:
                with open(lp, "r", errors="replace") as fh:
                    for n, line in enumerate(fh, 1):
                        for mk, c in markers.items():
                            if mk in line:
                                alerts.append({"type": "seen-in-log", "id": c["id"], "kind": c["kind"], "log": lp, "line": n})
            except OSError:
                alerts.append({"type": "log-unreadable", "log": lp})
        if listener_log and os.path.exists(listener_log):
            with open(listener_log) as fh:
                for line in fh:
                    try:
                        hit = json.loads(line)
                    except ValueError:
                        continue
                    if hit.get("canary_id") in {c["id"] for c in reg["canaries"]}:
                        alerts.append({"type": "callback-hit", "id": hit["canary_id"], "at": hit.get("at"),
                                       "remote": hit.get("remote")})
        return alerts
    finally:
        os.close(dirfd)


def listen(port: int, log_path: str, host: str = "127.0.0.1", max_requests: Optional[int] = None):
    """Tiny local listener: GET /c/<canary id> appends a JSON line to log_path. Binds loopback only by default."""
    state = {"n": 0}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = self.path.strip("/").split("/")
            cid = parts[1] if len(parts) >= 2 and parts[0] == "c" else None
            if cid and all(ch in "0123456789abcdef" for ch in cid) and len(cid) == 8:
                rec = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "canary_id": cid, "remote": self.client_address[0],
                       "ua": self.headers.get("User-Agent", "")[:200]}
                with open(log_path, "a") as fh:
                    fh.write(json.dumps(rec) + "\n")
            self.send_response(204)
            self.end_headers()
            state["n"] += 1

        def log_message(self, *a):
            pass

    srv = HTTPServer((host, port), H)
    try:
        while max_requests is None or state["n"] < max_requests:
            srv.handle_request()
    finally:
        srv.server_close()
    return srv
