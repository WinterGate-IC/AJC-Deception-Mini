from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

from . import layers, profiles, util

MIN = (3, 9)


def run(cfg, store=None):
    checks = []

    def add(name, ok, detail="", warn=False):
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:240], "warn": warn})

    add("python", sys.version_info[:2] >= MIN, "%d.%d" % sys.version_info[:2])
    add("layers", len(layers.LAYERS) >= 8, "%d deception layers" % len(layers.LAYERS))
    add("chain", bool(profiles.CHAIN), profiles.CHAIN)
    try:
        util.ensure_dir(cfg.data_dir, 0o700)
        p = Path(cfg.data_dir) / ".w"
        p.write_text("ok")
        p.unlink()
        add("data_dir", True, cfg.data_dir)
    except Exception as exc:
        add("data_dir", False, exc)
    try:
        add("config_mode", oct(os.stat(cfg.path).st_mode & 0o777) in ("0o600", "0o400"),
            oct(os.stat(cfg.path).st_mode & 0o777))
    except Exception as exc:
        add("config_mode", False, exc)
    add("token", len(str(cfg.get("token") or "")) >= 32, "%d chars" % len(str(cfg.get("token") or "")))
    add("canary", len(str(cfg.get("canary_secret") or "")) >= 32,
        "%d chars" % len(str(cfg.get("canary_secret") or "")))
    if store:
        e = store.verify_evidence()
        add("evidence", e["ok"], "%d records, %d bad" % (e["records"], len(e["bad"])))
    free = shutil.disk_usage(str(cfg.data_dir)).free
    add("disk", free > 20 * 1024 * 1024, util.human_bytes(free), warn=free < 50 * 1024 * 1024)
    bad = [c for c in checks if not c["ok"] and not c["warn"]]
    return {"ts": time.time(), "ok": not bad, "checks": checks,
            "failed": len(bad), "warnings": len([c for c in checks if not c["ok"] and c["warn"]])}


def report(r):
    for c in r["checks"]:
        print("  [%s] %-14s %s" % ("OK" if c["ok"] else ("WARN" if c["warn"] else "FAIL"),
                                   c["name"], c["detail"]))
    print("\n  %s — %d failed" % ("PASS" if r["ok"] else "FAIL", r["failed"]))
