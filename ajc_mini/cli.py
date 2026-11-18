from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import tempfile
from pathlib import Path

from . import config as cfgmod, doctor, engine as engmod, evidence, layers, profiles, storage, util

BANNER = "AJC DECEPTION MINI — labyrinth · data mirage · fake success"


def _open(a):
    cfg = cfgmod.Config(data_dir=a.data, local=a.local)
    if a.bind:
        cfg.set("bind", a.bind)
    if a.port:
        cfg.set("port", int(a.port))
    cfg.save()
    store = storage.Store(cfg.data_dir)
    return cfg, store, engmod.Engine(cfg, store)


def cmd_init(a):
    cfg, store, eng = _open(a)
    print(json.dumps({"ok": True, "data_dir": str(cfg.data_dir), "token": cfg.get("token"),
                      "layers": len(layers.LAYERS), "chain": profiles.CHAIN}, indent=1))
    return 0


def cmd_serve(a):
    cfg, store, eng = _open(a)
    from . import server
    httpd = server.serve(cfg, store, eng, bind=cfg.get("bind"), port=int(cfg.get("port")))
    stop = threading.Event()

    def _sig(*_):
        stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGTERM, _sig)
        signal.signal(signal.SIGINT, _sig)
    except Exception:
        pass
    print(BANNER)
    print("listening: http://%s:%d" % (cfg.get("bind"), int(cfg.get("port"))))
    print("console:   http://%s:%d/mini/?token=%s" % (cfg.get("bind"), int(cfg.get("port")), cfg.get("token")))
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
    return 0


def _events():
    return [
        {"ip": "198.51.100.20", "type": "recon_scan", "severity": "low", "method": "GET", "endpoint": "/"},
        {"ip": "203.0.113.44", "type": "sqli", "severity": "high", "method": "POST",
         "endpoint": "/api?id=1", "payload": "1 UNION SELECT password FROM users"},
        {"ip": "203.0.113.45", "type": "path_traversal", "severity": "high", "method": "GET",
         "endpoint": "/f?p=../../etc/shadow", "payload": "../../etc/shadow"},
        {"ip": "192.0.2.30", "type": "recon_scan", "severity": "medium",
         "method": "GET", "endpoint": "/.git/config", "reverse_engineering": True},
        {"ip": "192.0.2.30", "type": "recon_scan", "severity": "medium",
         "method": "GET", "endpoint": "/mini/engine.py", "reverse_engineering": True},
        {"ip": "192.0.2.30", "type": "recon_scan", "severity": "medium",
         "method": "GET", "endpoint": "/?x=AJC-CANARY-DEADBEEFDEADBEEF", "canary_replay": True},
    ]


def cmd_demo(a):
    tmp = tempfile.mkdtemp(prefix="ajc-mini-demo-")
    cfg = cfgmod.Config(data_dir=tmp)
    store = storage.Store(cfg.data_dir)
    eng = engmod.Engine(cfg, store)
    print(BANNER + "\n")
    for i, ev in enumerate(_events(), 1):
        d = eng.handle_event(ev, source="demo")
        print("%d. %-15s %-16s → L%d %s" % (i, d["ip"], d["attack_type"],
                                             d["penetration_depth"], d["verdict"]))
        print("   L%d engagement · actions: %s" % (d["engagement_depth"],
                                                   ", ".join(d["actions"])))
        c = d["controls"]
        if c["drop"]:
            print("   DROP (%s)" % c["deny_reason"])
        if c["reverse_engineering"]:
            print("   reverse-engineering probe → deeper maze")
        print()
    print(eng.summary_text())
    return 0


def cmd_event(a):
    cfg, store, eng = _open(a)
    raw = Path(a.file).read_text() if a.file else (a.json or sys.stdin.read())
    ev = json.loads(raw or "{}")
    print(json.dumps(eng.handle_event(ev, source="cli"), indent=1, default=str))
    return 0


def cmd_status(a):
    cfg, store, eng = _open(a)
    print(json.dumps(eng.status(), indent=1, default=str) if a.json else eng.summary_text())
    return 0


def cmd_layers(a):
    print(profiles.combo_text())
    return 0


def cmd_evidence(a):
    cfg, store, eng = _open(a)
    print(json.dumps(store.verify_evidence(), indent=1))
    return 0


def cmd_doctor(a):
    cfg, store, eng = _open(a)
    r = doctor.run(cfg, store)
    doctor.report(r)
    return 0 if r["ok"] else 1


def parser():
    p = argparse.ArgumentParser(prog="ajc-mini")
    p.add_argument("--data")
    p.add_argument("--local", action="store_true")
    p.add_argument("--bind")
    p.add_argument("--port", type=int)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("init").set_defaults(func=cmd_init)
    sub.add_parser("serve").set_defaults(func=cmd_serve)
    sub.add_parser("demo").set_defaults(func=cmd_demo)
    sp = sub.add_parser("event"); sp.add_argument("--json"); sp.add_argument("--file"); sp.set_defaults(func=cmd_event)
    sp = sub.add_parser("status"); sp.add_argument("--json", action="store_true"); sp.set_defaults(func=cmd_status)
    sub.add_parser("layers").set_defaults(func=cmd_layers)
    sub.add_parser("evidence").set_defaults(func=cmd_evidence)
    sub.add_parser("doctor").set_defaults(func=cmd_doctor)
    sub.add_parser("version").set_defaults(func=lambda a: (print(cfgmod.VERSION), 0)[1])
    return p


def main(argv=None):
    p = parser()
    a = p.parse_args(argv)
    if not getattr(a, "func", None):
        p.print_help()
        return 0
    try:
        return int(a.func(a) or 0)
    except KeyboardInterrupt:
        return 130
