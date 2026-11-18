#!/usr/bin/env python3
"""AJC Deception Mini installer — Python-only, no third-party packages."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ajc_mini import config as config_mod, util  # noqa: E402

APP = "ajc-mini"
DEFAULT_PREFIX = "/opt/ajc-mini"
VERSION = config_mod.VERSION


class UI:
    def __init__(self, yes=False, dry=False, quiet=False):
        self.yes = yes
        self.dry = dry
        self.quiet = quiet
        self.tty = sys.stdin.isatty() and sys.stdout.isatty()

    def say(self, s=""):
        if not self.quiet:
            print(s)

    def step(self, n, s):
        self.say("\n[%s] %s" % (n, s))

    def ok(self, s):
        self.say("    ✓ " + s)

    def warn(self, s):
        self.say("    ! " + s)

    def err(self, s):
        print("    ✗ " + s, file=sys.stderr)

    def ask(self, prompt, default=""):
        if self.yes or not self.tty:
            return default
        try:
            v = input("    %s [%s]: " % (prompt, default)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        return v or default

    def confirm(self, prompt, default=False):
        if self.yes or not self.tty:
            return bool(default)
        try:
            v = input("    %s [%s]: " % (prompt, "Y/n" if default else "y/N")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return bool(default)
        return default if not v else v in ("y", "yes")

    def run(self, cmd, check=False, timeout=300):
        if self.dry:
            self.say("    $ " + " ".join(cmd))
            return 0
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if p.returncode and check:
                self.warn(p.stderr.strip()[:300])
            return p.returncode
        except Exception as exc:
            if check:
                self.warn(str(exc)[:200])
            return 1


def args_parse(argv=None):
    p = argparse.ArgumentParser(prog="installer.py")
    p.add_argument("--prefix", default=DEFAULT_PREFIX)
    p.add_argument("--data-dir")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8791)
    p.add_argument("--token")
    p.add_argument("--trusted", default="")
    p.add_argument("--service-user", default="")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--no-service", action="store_true")
    p.add_argument("--uninstall", action="store_true")
    p.add_argument("--purge", action="store_true")
    p.add_argument("--doctor", action="store_true")
    return p.parse_args(argv)


def copy_tree(ui, prefix):
    if ui.dry:
        ui.say("    $ copy code → %s" % prefix)
        return
    prefix.mkdir(parents=True, exist_ok=True)
    for name in ("ajc_mini", "tests", "bin"):
        s, d = ROOT / name, prefix / name
        if not s.exists():
            continue
        if d.exists():
            shutil.rmtree(d)
        shutil.copytree(s, d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("README.md", "SECURITY.md", "INSTALL.md", "installer.py"):
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, prefix / name)
    launcher = prefix / "bin" / "ajc-mini"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    util.atomic_write_text(launcher, """#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PY=${AJC_PYTHON:-python3}
exec env PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}" "$PY" -m ajc_mini "$@"
""", mode=0o755)
    ui.ok("code: %s" % prefix)


def write_config(ui, a, data_dir):
    if not ui.dry:
        data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "config.json"
    old = util.read_json(path, {}) or {}
    token = a.token or old.get("token") or util.token_hex(24)
    secret = old.get("canary_secret") or util.token_hex(32)
    cfg = {
        "version": VERSION, "bind": a.bind, "port": a.port,
        "token": token, "canary_secret": secret,
        "trusted_ips": [x.strip() for x in a.trusted.split(",") if x.strip()],
        "deception": {"level": 3, "tarpit_max_ms": 900, "session_ttl": 1800, "maze_depth": 16},
        "retention": {"max_ips": 20000, "max_decisions": 1000, "max_profiles": 3000},
        "data_dir": str(data_dir),
    }
    if not ui.dry:
        util.atomic_write_json(path, cfg, mode=0o600)
        ui.ok("config: %s" % path)
    return cfg, token


def service(ui, a, det, prefix, data_dir):
    if a.no_service:
        ui.say("    service skipped")
        return False
    if not det["systemd"]:
        ui.say("    systemd not detected; run %s/bin/ajc-mini serve" % prefix)
        return False
    if not ui.confirm("Install and start a systemd service?", True):
        return False
    if not det["root"]:
        ui.warn("service install needs root")
        return False
    user = a.service_user or getpass.getuser()
    unit = """[Unit]
Description=AJC Deception Mini — labyrinth, mirage, fake success
After=network-online.target

[Service]
Type=simple
Environment=PYTHONPATH=%s
Environment=AJC_MINI_DATA=%s
ExecStart=%s/bin/ajc-mini serve --bind %s --port %d
Restart=always
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=%s
MemoryMax=192M
TasksMax=96%s

[Install]
WantedBy=multi-user.target
""" % (prefix, data_dir, prefix, a.bind, a.port, data_dir, ("\nUser=%s" % user) if user else "")
    path = Path("/etc/systemd/system/%s.service" % APP)
    if ui.dry:
        ui.say("    $ write %s" % path)
        return True
    try:
        util.atomic_write_text(path, unit, mode=0o644)
        ui.run(["systemctl", "daemon-reload"])
        ui.run(["systemctl", "enable", "--now", APP])
        ui.ok("service enabled")
        return True
    except Exception as exc:
        ui.warn("service failed: %s" % exc)
        return False


def uninstall(ui, a, prefix, data_dir):
    ui.run(["systemctl", "stop", APP])
    ui.run(["systemctl", "disable", APP])
    unit = Path("/etc/systemd/system/%s.service" % APP)
    if unit.exists() and not ui.dry:
        unit.unlink()
    ui.run(["systemctl", "daemon-reload"])
    if prefix.exists() and not ui.dry:
        shutil.rmtree(prefix, ignore_errors=True)
    ui.ok("code removed")
    if a.purge:
        if not ui.dry:
            shutil.rmtree(data_dir, ignore_errors=True)
        ui.ok("data removed")
    else:
        ui.say("    data kept: %s" % data_dir)
    return 0


def main(argv=None):
    a = args_parse(argv)
    ui = UI(a.yes, a.dry_run, a.quiet)
    data_dir = Path(a.data_dir).expanduser().resolve() if a.data_dir else Path(config_mod.default_data_dir()).resolve()
    prefix = Path(a.prefix).expanduser().resolve()
    if os.geteuid() != 0 and str(prefix).startswith("/opt/"):
        prefix = Path.home() / ".local" / "share" / APP
    if os.geteuid() != 0 and str(data_dir).startswith("/var/lib/"):
        data_dir = Path.home() / ".local" / "share" / (APP + "-data")

    if a.uninstall:
        return uninstall(ui, a, prefix, data_dir)
    if a.doctor:
        from ajc_mini import doctor, storage
        cfg = config_mod.Config(data_dir=str(data_dir))
        doctor.report(doctor.run(cfg, storage.Store(data_dir)))
        return 0

    ui.say("AJC DECEPTION MINI — installer v%s" % VERSION)
    ui.step(1, "Detect")
    det = {"root": util.is_root(), "systemd": bool(util.which("systemctl")) and Path("/run/systemd/system").exists(),
           "caddy": bool(util.which("caddy")), "nginx": bool(util.which("nginx"))}
    ui.say("    python: %s" % sys.version.split()[0])
    ui.say("    root: %s · systemd: %s · caddy: %s" % (det["root"], det["systemd"], det["caddy"]))
    if sys.version_info[:2] < (3, 9):
        ui.err("Python 3.9+ required")
        return 2
    ui.step(2, "Paths")
    ui.say("    code: %s" % prefix)
    ui.say("    data: %s" % data_dir)
    ui.step(3, "Install")
    copy_tree(ui, prefix)
    cfg, token = write_config(ui, a, data_dir)
    ui.step(4, "Service")
    svc = service(ui, a, det, prefix, data_dir)
    ui.step(5, "Verify")
    if ui.dry:
        ui.say("    dry run complete; nothing changed")
        return 0
    from ajc_mini import doctor, storage
    cfg_obj = config_mod.Config(data_dir=str(data_dir))
    r = doctor.run(cfg_obj, storage.Store(data_dir))
    doctor.report(r)
    print("\n  Installed.")
    print("  console: http://%s:%d/mini/?token=%s" % (a.bind, a.port, token))
    print("  health:  http://%s:%d/health" % (a.bind, a.port))
    print("  data:    %s" % data_dir)
    if not svc:
        print("  run:     %s/bin/ajc-mini serve" % prefix)
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
