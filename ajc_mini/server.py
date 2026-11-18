"""HTTP decoy surface + a tiny token-protected status API."""
from __future__ import annotations

import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import deception, layers, profiles, tarpit, util

STATE = {"cfg": None, "store": None, "eng": None, "sessions": None,
         "log": None, "active": 0, "lock": threading.Lock(), "max": 64}


def _auth(h):
    tok = str(STATE["cfg"].get("token") or "")
    if not tok:
        return True
    got = h.headers.get("X-AJC-Token") or ""
    if not got:
        got = (parse_qs(urlparse(h.path).query).get("token") or [""])[0]
    return bool(got) and hmac.compare_digest(got, tok)


def _client(h):
    if STATE["cfg"].get("trust_proxy"):
        xff = h.headers.get("X-Forwarded-For") or ""
        if xff:
            return util.norm_ip(xff.split(",")[0].strip()) or h.client_address[0]
    return util.norm_ip(h.client_address[0]) or h.client_address[0]


def _json(h, code, obj):
    body = json.dumps(obj, indent=1).encode()
    h.send_response(code)
    h.send_header("Content-Type", "application/json; charset=utf-8")
    h.send_header("Cache-Control", "no-store")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ajc-mini"

    def log_message(self, fmt, *args):
        try:
            util.append_line(STATE["log"], "%s %s %s" % (util.iso(), self.address_string(), fmt % args))
        except Exception:
            pass

    def version_string(self):
        return "ajc-mini"

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except Exception:
            n = 0
        if n < 0 or n > util.safe_int(STATE["cfg"].get("max_body"), 32768):
            return b""
        try:
            return self.rfile.read(n) if n else b""
        except Exception:
            return b""

    def _drop(self, rst=False):
        try:
            if rst:
                tarpit.rst_socket(self.connection)
            else:
                self.close_connection = True
                try:
                    self.connection.shutdown(2)
                except OSError:
                    pass
                self.connection.close()
        except Exception:
            pass

    def do_GET(self):
        self._go()

    def do_HEAD(self):
        self._go()

    def do_POST(self):
        self._go()

    def do_PUT(self):
        self._go()

    def do_DELETE(self):
        self._go()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _go(self):
        with STATE["lock"]:
            if STATE["active"] >= STATE["max"]:
                _json(self, 503, {"ok": False, "error": "busy"})
                return
            STATE["active"] += 1
        try:
            self._route()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            try:
                util.append_line(STATE["log"], "%s ERROR %s" % (util.iso(), str(exc)[:200]))
            except Exception:
                pass
            try:
                _json(self, 500, {"ok": False, "error": "internal"})
            except Exception:
                pass
        finally:
            with STATE["lock"]:
                STATE["active"] = max(0, STATE["active"] - 1)

    def _route(self):
        cfg, store, eng = STATE["cfg"], STATE["store"], STATE["eng"]
        path = urlparse(self.path or "/").path or "/"
        ip = _client(self)
        if path == "/health":
            _json(self, 200, {"ok": True, "service": "ajc-mini",
                              "layers": len(layers.LAYERS), "ts": int(util.now())})
            return
        if path in ("/mini", "/mini/") or path.startswith("/mini/api/"):
            self._api(path)
            return
        local = util.is_private_ip(ip) and not bool(cfg.get("allow_private"))
        trusted = ip in set(cfg.get("trusted_ips") or []) | {"127.0.0.1", "::1"}
        if not local and not trusted and store.is_denied(ip):
            self._drop(rst=True)
            return
        body = self._body().decode("utf-8", "replace")
        sess = STATE["sessions"].get(ip, cfg.get("canary_secret"))
        info = deception.classify(self.command, path, dict(self.headers), body)
        d = eng.handle_event({"ip": ip, "type": info["attack_type"],
                              "severity": info["severity"], "method": self.command,
                              "endpoint": path, "payload": body[:3000],
                              "path": path, "headers": dict(self.headers),
                              "body": body, "reverse_engineering": info["source_probe"],
                              "canary_replay": info["canary_replay"]})
        c = d.get("controls") or {}
        if c.get("drop") and not local and not trusted:
            self._drop(rst=True)
            return
        if c.get("ghost") and not local and not trusted:
            time.sleep(min(1.2, 0.3 + sess.boost * 0.03))
            self._drop(rst=True)
            return
        resp = deception.serve(sess, cfg.get("canary_secret"), self.command, path,
                               dict(self.headers), body,
                               base_depth=util.safe_int(d.get("penetration_depth"), 1),
                               deception_level=util.safe_int(c.get("deception"), 3),
                               tarpit_max_ms=util.safe_int(cfg.get("deception.tarpit_max_ms"), 900),
                               max_maze=util.safe_int(cfg.get("deception.maze_depth"), 16))
        delay = min(float(resp.get("delay") or 0), float(cfg.get("deception.tarpit_max_ms") or 900) / 1000)
        if c.get("tarpit_delay"):
            delay = max(delay, min(float(c["tarpit_delay"]), 0.9))
        if delay:
            time.sleep(delay)
        if resp.get("drop"):
            self._drop(rst=True)
            return
        raw = str(resp.get("body") or "").encode("utf-8", "replace")
        self.send_response(int(resp.get("status") or 200))
        for k, v in (resp.get("headers") or {}).items():
            self.send_header(k, str(v))
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _api(self, path):
        if not _auth(self):
            _json(self, 401, {"ok": False, "error": "token required"})
            return
        if path in ("/mini", "/mini/"):
            _json(self, 200, STATE["eng"].status())
            return
        if path == "/mini/api/status":
            _json(self, 200, STATE["eng"].status())
            return
        if path == "/mini/api/layers":
            _json(self, 200, {"layers": [layers.LAYER_BY_NUM[n] for n in sorted(layers.LAYER_BY_NUM)],
                              "chain": profiles.CHAIN, "receipt": profiles.RECEIPT})
            return
        if path == "/mini/api/verify":
            _json(self, 200, {"evidence": STATE["store"].verify_evidence(),
                              "layers": len(layers.LAYERS)})
            return
        if path == "/mini/api/event" and self.command == "POST":
            try:
                ev = json.loads(self._body().decode() or "{}")
            except Exception:
                _json(self, 400, {"ok": False, "error": "bad json"})
                return
            ev.setdefault("ip", _client(self))
            _json(self, 200, STATE["eng"].handle_event(ev, source="api"))
            return
        # Unknown /mini/* falls through to the decoy surface.
        sess = STATE["sessions"].get(_client(self), STATE["cfg"].get("canary_secret"))
        resp = deception.serve(sess, STATE["cfg"].get("canary_secret"), self.command,
                               path, dict(self.headers), "", base_depth=1,
                               deception_level=3,
                               tarpit_max_ms=util.safe_int(STATE["cfg"].get("deception.tarpit_max_ms"), 900),
                               max_maze=16)
        raw = str(resp.get("body") or "").encode("utf-8", "replace")
        self.send_response(int(resp.get("status") or 200))
        for k, v in (resp.get("headers") or {}).items():
            self.send_header(k, str(v))
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)


def serve(config, store, engine, bind=None, port=None):
    from .deception import SessionStore
    bind = bind or config.get("bind") or "127.0.0.1"
    port = int(port or config.get("port") or 8791)
    STATE.update({"cfg": config, "store": store, "eng": engine,
                  "sessions": SessionStore(util.safe_int(config.get("deception.session_ttl"), 1800)),
                  "log": str(Path(config.data_dir) / "logs" / "access.log")})
    util.ensure_dir(Path(config.data_dir) / "logs", 0o700)
    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True
    httpd.allow_reuse_address = True
    return httpd
