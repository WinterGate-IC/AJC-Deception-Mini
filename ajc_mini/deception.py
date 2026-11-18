"""Portable deception engine: classify, deepen, and answer.

Design notes
------------
* The published code is not the secret.  The secret is per-install (canary
  HMAC), and the response graph is seeded per client, so reading this file does
  not let an attacker predict what a given deployment will serve.
* Reverse-engineering probes are not rejected with a tell-tale 404.  They are
  answered with a plausible *decoy* repository/config and a deeper maze, while
  the session is escalated and recorded.
* All effects stay inside this server: fake data, fake success, tarpits,
  connection drops.  No raw packets, no third-party action.
"""
from __future__ import annotations

import json
import re
import threading
from urllib.parse import unquote
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import labyrinth, mirage, util

SCANNER_UA = (
    "sqlmap", "nikto", "nuclei", "nmap", "masscan", "gobuster", "ffuf",
    "dirsearch", "wpscan", "zgrab", "acunetix", "nessus", "burp", "hydra",
    "python-requests", "go-http-client", "curl/", "wget/", "libwww-perl",
    "httpclient", "okhttp", "scrapy",
)
SQLI_RE = re.compile(r"(?i)(\bunion\b\s+\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|"
                     r"\bsleep\s*\(|\bbenchmark\s*\(|information_schema|"
                     r"xp_cmdshell|\bdrop\s+table\b|\binsert\s+into\b)")
XSS_RE = re.compile(r"(?i)(<script\b|onerror\s*=|onload\s*=|javascript\s*:|"
                    r"<svg/onload|document\.cookie)")
TRAV_RE = re.compile(r"(?i)(\.\./|%2e%2e|/etc/passwd|/etc/shadow|win\.ini|"
                     r"boot\.ini|proc/self/environ)")
CMD_RE = re.compile(r"(?i)(;\s*(cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|"
                    r"python|perl|php)\b|\|\s*(cat|ls|id|whoami|uname|bash|sh)\b|"
                    r"\$\([^)]+\)|`[^`]+`)")
SSRF_RE = re.compile(r"(?i)(169\.254\.169\.254|metadata\.google|metadata\.azure|"
                     r"file://|gopher://|dict://)")
UPLOAD_RE = re.compile(r"(?i)(filename\s*=|multipart/form-data|\.php\b|\.jsp\b|\.asp\b)")
CANARY_RE = re.compile(r"AJC-CANARY-[A-F0-9]{12,}")

SEVERITY = {
    "canary_replay": "critical", "source_probe": "high", "credential_probe": "high",
    "sql_injection": "critical", "command_injection": "critical", "rce": "critical",
    "path_traversal": "high", "xss": "high", "ssrf": "high", "file_upload": "high",
    "scanner": "medium", "brute_force": "high", "recon_scan": "low",
    "web_scan": "medium", "api_abuse": "medium", "rate_abuse": "medium",
    "unknown": "low",
}


@dataclass
class Session:
    ip: str
    seed: int
    created: float = field(default_factory=time.time)
    last: float = field(default_factory=time.time)
    count: int = 0
    boost: int = 0
    attack_types: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    source_probes: int = 0
    canary_hits: int = 0
    maze_tamper: int = 0
    link_hops: int = 0
    terminal: bool = False
    last_verdict: str = ""

    def touch(self):
        self.count += 1
        self.last = time.time()

    def effective_depth(self, base: int) -> int:
        return min(70, max(1, int(base) + self.boost + self.count // 12 +
                           self.source_probes * 3 + self.canary_hits * 5 +
                           self.link_hops // 2))


class SessionStore:
    def __init__(self, ttl: int = 1800):
        self.ttl = max(60, int(ttl))
        self._lock = threading.RLock()
        self._sessions: Dict[str, Session] = {}

    def get(self, ip: str, secret: str) -> Session:
        with self._lock:
            now = time.time()
            for key in [k for k, v in self._sessions.items() if now - v.last > self.ttl]:
                self._sessions.pop(key, None)
            s = self._sessions.get(ip)
            if s is None:
                s = Session(ip=ip, seed=util.stable_seed("session", secret, ip, now))
                self._sessions[ip] = s
            return s

    def drop(self, ip: str) -> None:
        with self._lock:
            self._sessions.pop(ip, None)


def classify(method: str, path: str, headers: Dict[str, str], body: str) -> dict:
    def _deep(value):
        value = str(value or "")
        for _ in range(3):
            value = unquote(value)
        return value.replace("\x00", "").replace("\\", "/")

    method = (method or "GET").upper()
    path = _deep(path or "/")
    body = _deep(body or "")[:20000]
    blob = path + "\n" + body
    ua = str((headers or {}).get("user-agent", "")).lower()
    types = []
    reasons = []

    if CANARY_RE.search(blob) or CANARY_RE.search(str(headers)):
        types.append("canary_replay")
        reasons.append("decoy canary replayed")
    if labyrinth.source_probe(path) or labyrinth.source_probe(body[:500]):
        types.append("source_probe")
        reasons.append("reverse-engineering probe")
    if re.search(r"(?i)(\.env|credentials|id_rsa|\.aws|\.ssh|secret|passwd|shadow)", path):
        types.append("credential_probe")
        reasons.append("credential path probe")
    if SQLI_RE.search(blob):
        types.append("sql_injection")
        reasons.append("SQL meta-characters and keywords")
    if XSS_RE.search(blob):
        types.append("xss")
        reasons.append("script injection syntax")
    if TRAV_RE.search(blob):
        types.append("path_traversal")
        reasons.append("directory traversal sequence")
    if CMD_RE.search(blob):
        types.append("command_injection")
        reasons.append("shell metacharacter pattern")
    if SSRF_RE.search(blob):
        types.append("ssrf")
        reasons.append("internal metadata address")
    if UPLOAD_RE.search(str(headers) + "\n" + body) and method in ("POST", "PUT", "PATCH"):
        types.append("file_upload")
        reasons.append("file upload shape")
    if any(s in ua for s in SCANNER_UA):
        types.append("scanner")
        reasons.append("automation user-agent")
    if path.lower().startswith(("/.git", "/.svn", "/.hg")):
        types.append("source_probe")
        reasons.append("VCS metadata probe")
    if re.search(r"(?i)/(wp-admin|wp-login|phpmyadmin|actuator|solr|jenkins|"
                 r"console|manager|\.git|swagger|graphql)", path):
        types.append("web_scan")
        reasons.append("known management surface")
    if path.count("/") > 6 or len(path) > 300:
        types.append("recon_scan")
        reasons.append("path enumeration shape")
    if not types:
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            types.append("api_abuse")
            reasons.append("state-changing request to decoy surface")
        else:
            types.append("recon_scan")
            reasons.append("unclassified decoy access")

    # highest severity first
    ordered = sorted(set(types), key=lambda t: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(SEVERITY.get(t), 4), t))
    primary = ordered[0]
    if primary in ("sql_injection", "xss", "path_traversal", "command_injection",
                   "file_upload", "ssrf"):
        attack_type = {"sql_injection": "sqli", "command_injection": "rce"}.get(primary, primary)
    elif primary in ("scanner", "web_scan"):
        attack_type = "web_scan"
    elif primary == "source_probe":
        attack_type = "recon_scan"
    elif primary == "canary_replay":
        attack_type = "api_abuse"
    else:
        attack_type = primary
    return {
        "types": ordered, "attack_type": attack_type, "primary": primary,
        "severity": SEVERITY.get(primary, "low"),
        "reasons": reasons, "scanner": any(s in ua for s in SCANNER_UA),
        "source_probe": "source_probe" in types,
        "canary_replay": "canary_replay" in types,
    }


def _legal_footer(ip: str, attack: str) -> str:
    return (
        "\n\n---\n"
        "DEFENSIVE DECEPTION NOTICE · %s\n"
        "This host is a monitored deception environment. The request from %s "
        "was classified as %s. No real data is served here. Activity is logged "
        "with a tamper-evident hash chain. All responses are synthetic.\n"
        % (util.iso(), ip, attack)
    )


def _response(status=200, body="", ctype="text/plain; charset=utf-8",
              extra: Dict[str, str] = None) -> dict:
    headers = {
        "Content-Type": ctype,
        "Cache-Control": "no-store, max-age=0",
        "X-Robots-Tag": "noindex, nofollow",
        "X-Decoy": "true",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    }
    if extra:
        headers.update(extra)
    return {"status": int(status), "headers": headers, "body": body}
def serve(session: Session, secret: str, method: str, path: str,
          headers: Dict[str, str], body: str, base_depth: int = 1,
          deception_level: int = 2, tarpit_max_ms: int = 1200,
          max_maze: int = 12) -> dict:
    """Build one decoy response and return engine-facing metadata."""
    session.touch()
    info = classify(method, path, headers, body)
    session.attack_types[info["attack_type"]] += 1
    session.paths[path] += 1
    if info["source_probe"]:
        session.source_probes += 1
        session.boost = min(40, session.boost + 4)
    if info["canary_replay"]:
        session.canary_hits += 1
        session.boost = min(40, session.boost + 10)
        session.terminal = True
    q = path.split("?", 1)[1] if "?" in path else ""
    if "c=" in q:
        session.link_hops += 1
        from urllib.parse import parse_qs
        vals = parse_qs(q).get("c") or []
        bad = [v for v in vals if not labyrinth.verify_token(secret, session.ip, path, v)]
        if bad:
            session.maze_tamper += len(bad)
            session.boost = min(40, session.boost + 6 * len(bad))
            if session.maze_tamper >= 3:
                session.terminal = True
        if session.link_hops > 8:
            session.boost = min(40, session.boost + 1)

    depth = session.effective_depth(base_depth)
    r = labyrinth.rng_for(secret, session.ip, path, depth)
    delay_ms = 0
    drop = False
    ctype = "text/html; charset=utf-8"

    if session.terminal and (session.canary_hits >= 2 or session.maze_tamper >= 3):
        # Second replay: stop answering.  Recorded before the drop by the caller.
        drop = True
        resp = _response(204, "")
        resp["drop"] = True
        resp["deepen"] = depth
        resp["info"] = info
        return resp

    if info["canary_replay"]:
        body_out = (
            "<!doctype html><html><body><h1>Session integrity failure</h1>"
            "<p>The token presented was issued to a different client. This event "
            "has been recorded.</p><p>%s</p></body></html>"
            % mirage.canary(secret, "replay:" + path, session.ip)
        )
        resp = _response(403, body_out, ctype)
        delay_ms = min(tarpit_max_ms, 250)
    elif info["source_probe"]:
        body_out = labyrinth.trap_page(path, secret, session.ip, min(depth, max_maze))
        resp = _response(200, body_out, "text/plain; charset=utf-8")
        delay_ms = min(tarpit_max_ms, 80)
    elif info["primary"] == "sql_injection":
        resp = _response(200, mirage.fake_sql_dump(secret, "sqli", session.ip,
                                                   util.stable_seed(secret, session.ip, "sql")),
                         "text/plain; charset=utf-8")
    elif info["primary"] == "path_traversal":
        if "shadow" in path.lower():
            out = mirage.fake_shadow(secret, "trav", session.ip, util.stable_seed(path))
        elif "passwd" in path.lower():
            out = mirage.fake_passwd(secret, "trav", session.ip, util.stable_seed(path))
        else:
            out = mirage.fake_file(path, secret, "trav", session.ip, util.stable_seed(path))
        resp = _response(200, out, "text/plain; charset=utf-8")
    elif info["primary"] in ("command_injection", "rce"):
        resp = _response(200, mirage.fake_shell(secret, "rce", session.ip,
                                                util.stable_seed(secret, session.ip, "shell")),
                         "text/plain; charset=utf-8")
    elif info["primary"] == "xss":
        resp = _response(200, "XSS EXECUTED — DECOY\ncookie: PHPSESSID=fake_%s\n%s"
                         % (util.token_hex(8), _legal_footer(session.ip, "xss")),
                         "text/plain; charset=utf-8",
                         {"Set-Cookie": "PHPSESSID=decoy_%s; Path=/; HttpOnly" % util.token_hex(8)})
    elif info["primary"] == "ssrf":
        resp = _response(200, mirage.fake_cloud_meta(secret, "ssrf", session.ip,
                                                     util.stable_seed(path)),
                         "application/json")
    elif info["primary"] == "file_upload":
        resp = _response(200, mirage.fake_upload(secret, "upload", session.ip,
                                                 util.stable_seed(secret, session.ip, "up")),
                         "text/plain; charset=utf-8")
    elif info["primary"] == "brute_force":
        resp = _response(200, "LOGIN ACCEPTED — DECOY\nrole=admin\n%s"
                         % _legal_footer(session.ip, "brute_force"),
                         "text/plain; charset=utf-8",
                         {"Set-Cookie": "session=decoy_%s; Path=/; HttpOnly" % util.token_hex(12)})
    elif info["primary"] == "credential_probe":
        resp = _response(200, mirage.fake_env(secret, "creds", session.ip,
                                              util.stable_seed(path)),
                         "text/plain; charset=utf-8")
    elif path.startswith("/api") or path.endswith((".json", "/graphql")):
        resp = _response(200, labyrinth.api(path, secret, session.ip, min(depth, max_maze)),
                         "application/json")
    elif path.startswith(("/uploads", "/files", "/backup")) or path.endswith("/"):
        resp = _response(200, labyrinth.file_listing(path, secret, session.ip, min(depth, max_maze)),
                         "text/plain; charset=utf-8")
    else:
        title = "Operations Console" if deception_level >= 2 else "Service"
        resp = _response(200, labyrinth.page(path, secret, session.ip, min(depth, max_maze), title),
                         ctype)

    if info["severity"] in ("high", "critical") or info["scanner"]:
        if tarpit_max_ms > 0:
            delay_ms = delay_ms or min(tarpit_max_ms, 120 + min(depth, 40) * 18)
    if session.boost >= 8:
        delay_ms = max(delay_ms, min(tarpit_max_ms, 200))
    if deception_level >= 2 and resp["status"] != 403:
        resp["headers"]["X-AJC-Notice"] = "defensive deception environment; no real data"
    if info["scanner"] or session.source_probes:
        resp["headers"]["X-Maze-Hops"] = str(session.link_hops)
        resp["headers"]["X-Decoy-Depth"] = str(depth)

    resp["delay"] = delay_ms / 1000.0
    resp["drop"] = drop
    resp["deepen"] = depth
    resp["info"] = info
    resp["session"] = {"count": session.count, "boost": session.boost,
                       "source_probes": session.source_probes,
                       "canary_hits": session.canary_hits,
                       "maze_tamper": session.maze_tamper}
    return resp


def analyze_request(method: str, path: str, headers: Dict[str, str], body: str) -> dict:
    """Public classifier used by the engine/ingest API."""
    return classify(method, path, headers, body)
