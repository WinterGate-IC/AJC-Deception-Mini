from __future__ import annotations

import copy
import os
from pathlib import Path

from . import util

VERSION = "1.0.0"
APP = "ajc-mini"

DEFAULTS = {
    "version": VERSION,
    "bind": "127.0.0.1",
    "port": 8791,
    "token": "",
    "canary_secret": "",
    "allow_private": False,
    "trust_proxy": False,
    "trusted_ips": [],
    "max_body": 32768,
    "deception": {"level": 3, "tarpit_max_ms": 900, "session_ttl": 1800,
                  "maze_depth": 16},
    "retention": {"max_ips": 20000, "max_decisions": 1000, "max_profiles": 3000},
    "log_level": "INFO",
}


def default_data_dir(local=False):
    env = os.environ.get("AJC_MINI_DATA")
    if env:
        return str(Path(env).expanduser())
    if local:
        return str((Path.cwd() / "ajc-mini-data").resolve())
    if util.is_root() and os.access("/var/lib", os.W_OK):
        return "/var/lib/ajc-mini"
    return str(Path.home() / ".local" / "share" / APP)


class Config:
    def __init__(self, data_dir=None, local=False, **overrides):
        self.data_dir = Path(data_dir or default_data_dir(local)).expanduser().resolve()
        self.path = self.data_dir / "config.json"
        self.data = copy.deepcopy(DEFAULTS)
        if self.path.exists():
            disk = util.read_json(self.path, {})
            if isinstance(disk, dict):
                self.data = _merge(self.data, disk)
        if overrides:
            self.data = _merge(self.data, overrides)
        self.data["data_dir"] = str(self.data_dir)
        if not self.data.get("token"):
            self.data["token"] = util.token_hex(24)
        if not self.data.get("canary_secret"):
            self.data["canary_secret"] = util.token_hex(32)
        util.ensure_dir(self.data_dir, 0o700)
        for sub in ("logs", "notices", "reports"):
            util.ensure_dir(self.data_dir / sub, 0o700)
        self.save()

    def get(self, dotted, default=None):
        cur = self.data
        for part in str(dotted).split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set(self, dotted, value):
        cur = self.data
        parts = str(dotted).split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value

    def save(self):
        util.atomic_write_json(self.path, self.data, mode=0o600)


def _merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out
