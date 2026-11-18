"""Small, dependency-free helpers used across the portable AJC."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import random
import re
import socket
import stat
import sys
import time
from pathlib import Path

_IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")


def now() -> float:
    return time.time()


def iso(ts: float = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else now()))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def token_hex(n: int = 24) -> str:
    return os.urandom(n).hex()


def valid_ip(value: str) -> bool:
    value = (value or "").strip()
    if not value or len(value) > 64 or not _IP_RE.match(value):
        return False
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except OSError:
        return False


def norm_ip(value: str) -> str:
    value = (value or "").strip()
    if not valid_ip(value):
        return ""
    try:
        if ":" in value:
            return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, value))
        return socket.inet_ntop(socket.AF_INET, socket.inet_pton(socket.AF_INET, value))
    except OSError:
        return ""


def is_private_ip(ip: str) -> bool:
    ip = norm_ip(ip)
    if not ip:
        return False
    if ip.startswith(("10.", "127.", "169.254.", "192.168.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except Exception:
            return False
    if ":" in ip:
        return ip in ("::1",) or ip.lower().startswith(("fc", "fd", "fe80"))
    return False


def parse_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on", "enable", "enabled")


def clamp(value, lo, hi):
    try:
        value = float(value)
    except Exception:
        value = lo
    return max(lo, min(hi, value))


def safe_int(value, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def human_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f PB" % n


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def atomic_write_text(path, text: str, mode: int = 0o600) -> None:
    path = Path(path)
    _ensure_parent(path)
    tmp = path.with_name(path.name + ".tmp." + token_hex(4))
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def atomic_write_json(path, data, mode: int = 0o600) -> None:
    atomic_write_text(path, json.dumps(data, indent=1, sort_keys=False), mode=mode)


def append_line(path, line: str, mode: int = 0o600) -> None:
    path = Path(path)
    _ensure_parent(path)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")
        fh.flush()
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def tail_lines(path, limit: int = 50):
    limit = max(1, min(5000, int(limit)))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        return [l.rstrip("\n") for l in lines[-limit:]]
    except Exception:
        return []


def stable_seed(*parts) -> int:
    h = hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8", "replace")).digest()
    return int.from_bytes(h[:8], "big")


def hmac_token(secret: str, *parts, length: int = 16) -> str:
    msg = "\x1f".join(str(p) for p in parts).encode("utf-8", "replace")
    return hmac.new(str(secret).encode("utf-8"), msg, hashlib.sha256).hexdigest()[:length]


def jitter(base_ms: int, spread_ms: int = None) -> float:
    base_ms = max(0, int(base_ms))
    spread_ms = max(0, int(spread_ms if spread_ms is not None else base_ms // 2))
    return (base_ms + random.randint(0, spread_ms)) / 1000.0


def ensure_dir(path, mode: int = 0o700) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, mode)
    except OSError:
        pass
    return p


def which(cmd: str):
    from shutil import which as _which
    return _which(cmd)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def port_available(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        s.close()


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def truncate(text: str, n: int = 300) -> str:
    text = str(text or "").replace("\n", " ")
    return text if len(text) <= n else text[: n - 1] + "…"
