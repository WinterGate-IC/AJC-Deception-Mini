"""The deception labyrinth.

A per-client, seeded graph of fake endpoints.  There is no fixed map to learn:
the seed includes the installation secret and the client identity, links carry
signed canaries, and descending consumes the attacker's time without ever
reaching a real control plane.

The labyrinth is also the answer to reverse-engineering probes: requests for
source trees, configs, tests or module paths are served a plausible *decoy*
repository, never this program.
"""
from __future__ import annotations

import html
import json
import random
from typing import Dict, List

from . import mirage, util

SECTIONS = [
    ("Admin", ["Users", "Roles", "Audit", "Sessions", "Secrets", "Deploy"]),
    ("Data", ["Exports", "Imports", "Backups", "Snapshots", "Warehouse"]),
    ("Platform", ["Nodes", "Pods", "Services", "Ingress", "Certificates"]),
    ("Observability", ["Metrics", "Traces", "Logs", "Alerts", "SLOs"]),
    ("Security", ["Policies", "Tokens", "Keys", "Scans", "Findings"]),
]
LEAF_NAMES = ["index", "list", "detail", "export", "download", "config",
              "status", "schema", "graph", "history", "sync", "verify"]
EXTS = ["", "/", ".json", "?format=json", "?page=2", "?debug=1"]


def rng_for(secret: str, client: str, path: str, depth: int) -> random.Random:
    return random.Random(util.stable_seed("labyrinth", secret, client, path, depth))


def token(secret: str, client: str, path: str, n: int = 0) -> str:
    return "%d.%s" % (n, util.hmac_token(secret, "maze", client, path.split("?", 1)[0], n, length=14))


def verify_token(secret: str, client: str, path: str, value: str) -> bool:
    try:
        n_s, sig = str(value).split(".", 1)
        n = int(n_s)
    except Exception:
        return False
    base = path.split("?", 1)[0]
    return util.hmac_token(secret, "maze", client, base, n, length=14) == sig


def _leaf(r: random.Random, base: str) -> str:
    return "/" + base.strip("/") + "/" + r.choice(LEAF_NAMES) + r.choice(EXTS)


def next_links(path: str, secret: str, client: str, depth: int,
               count: int = 5) -> List[str]:
    base = path.split("?", 1)[0]
    r = rng_for(secret, client, base, depth)
    out = []
    for i in range(max(3, min(8, count))):
        if r.random() < 0.32:
            out.append("/" + r.choice(["admin", "api/v1", "api/v2", "internal",
                                       "debug", "files", "backup", "vault"]))
        else:
            leaf = _leaf(r, base)
            sep = "&" if "?" in leaf else "?"
            out.append(leaf + sep + "c=" + token(secret, client, base, i + depth))
    # cycles are deliberate: the same door appears again, differently signed.
    if out:
        out.append(base + "?c=" + token(secret, client, base, 99))
    return out


def page(path: str, secret: str, client: str, depth: int,
         title: str = "Operations Console") -> str:
    r = rng_for(secret, client, path, depth)
    links = next_links(path, secret, client, depth, r.randint(4, 7))
    rows = []
    for name, items in SECTIONS:
        lis = "".join("<li><a href='%s'>%s</a></li>" % (html.escape("/" + r.choice(items).lower()), html.escape(it))
                      for it in items[:r.randint(2, 5)])
        rows.append("<section><h2>%s</h2><ul>%s</ul></section>" % (html.escape(name), lis))
    canary = mirage.canary(secret, "maze:" + path, client)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>%s</title><meta name='robots' content='noindex,nofollow'>"
        "</head><body><h1>%s</h1>"
        "<p>Signed in as <b>%s</b> · session %s · node %s</p>"
        "<p>Environment: production · region %s · build %s</p>"
        "<nav>%s</nav>%s"
        "<footer>%s · internal use only · %s</footer>"
        "</body></html>"
        % (html.escape(title), html.escape(title), html.escape(mirage.fake_user(r)),
           util.truncate(util.sha256_text(canary), 12), html.escape(mirage.fake_host(r)),
           r.choice(["us-east-1", "eu-west-1", "ap-south-1"]),
           util.truncate(util.sha256_text(canary + "b"), 8),
           "".join("<a href='%s'>%s</a>" % (html.escape(l), html.escape(l)) for l in links),
           "".join(rows), canary, html.escape(path))
    )


def api(path: str, secret: str, client: str, depth: int) -> str:
    r = rng_for(secret, client, path, depth)
    links = next_links(path, secret, client, depth, r.randint(3, 6))
    payload = {
        "ok": True,
        "path": path,
        "user": mirage.fake_user(r),
        "scopes": r.sample(["read", "write", "admin", "deploy", "audit", "billing"], r.randint(2, 5)),
        "links": {k: v for k, v in zip(["users", "config", "logs", "secrets", "deploy", "data"], links)},
        "counts": {"users": r.randint(10, 90000), "records": r.randint(1000, 9000000)},
        "canary": mirage.canary(secret, "api:" + path, client),
        "warning": "decoy response; no production data",
    }
    return json.dumps(payload)


def file_listing(path: str, secret: str, client: str, depth: int) -> str:
    r = rng_for(secret, client, path, depth)
    names = ["config", "deploy", "backup", "logs", "uploads", "src", "tests",
             "secrets", "migrations", "static", "scripts", "vendor"]
    rows = ["Index of %s" % path, ""]
    for n in r.sample(names, r.randint(5, len(names))):
        rows.append("  %-18s %10d  %s" % (n + r.choice(["/", ".tar.gz", ".sql", ".json"]),
                                          r.randint(120, 9000000),
                                          r.choice(["2026-01-01 00:00", "2026-02-14 12:31", "2026-03-02 04:02"])))
    rows.append("  %-18s %s" % ("canary", mirage.canary(secret, "dir:" + path, client)))
    return "\n".join(rows)


def fake_repo(secret: str, client: str, path: str, depth: int) -> str:
    r = rng_for(secret, client, path, depth)
    tree = [
        ".github/workflows/ci.yml", ".gitignore", "README.md", "LICENSE",
        "pyproject.toml", "requirements.txt", "src/__init__.py", "src/app.py",
        "src/config.py", "src/models.py", "src/layers.py", "src/engine.py",
        "src/deception.py", "src/labyrinth.py", "src/mirage.py",
        "src/server.py", "src/evidence.py", "tests/test_layers.py",
        "tests/test_engine.py", "tests/test_deception.py", "deploy/systemd/ajc.service",
        "deploy/caddy/Caddyfile", "docs/ARCHITECTURE.md", "docs/SECURITY.md",
    ]
    low = path.lower()
    leaf = low.rstrip("/").rsplit("/", 1)[-1]
    if leaf and "." in leaf and not low.endswith((".git", ".svn")):
        return fake_code(leaf, secret, client, depth)
    if "source" in low or "tree" in low or "repo" in low or path.endswith("/"):
        return "\nDECOY SOURCE TREE (not the running program)\n" + "\n".join(tree) + \
            "\n\ncanary: %s\n" % mirage.canary(secret, "tree", client)
    name = r.choice([t for t in tree if t.endswith((".py", ".md", ".yml", ".toml"))])
    return fake_code(name, secret, client, depth)


def fake_code(name: str, secret: str, client: str, depth: int) -> str:
    r = rng_for(secret, client, name, depth)
    tok = mirage.canary(secret, "code:" + name, client)
    if name.endswith(".md"):
        return ("# Operations Notes (decoy)\n\n"
                "This repository documents a synthetic deployment. Do not use these values.\n\n"
                "- build: %s\n- node: %s\n- canary: %s\n"
                % (util.truncate(util.sha256_text(tok), 12), mirage.fake_host(r), tok))
    if name.endswith(".json"):
        return json.dumps({
            "environment": "production", "debug": True,
            "database": {"host": mirage.fake_host(r) + ".internal", "user": mirage.fake_user(r),
                         "password": mirage.fake_password(r)},
            "admin_path": "/admin", "build": util.truncate(util.sha256_text(tok), 10),
            "canary": tok, "_note": "decoy config; not the running program",
        }, indent=1)
    if name.endswith(".sh"):
        return ("#!/bin/sh\n# decoy deploy script — inert\n"
                "set -eu\necho deploying %s\nexport DB_PASSWORD=%s\n"
                "# canary: %s\n" % (mirage.fake_host(r), mirage.fake_password(r), tok))
    if name.endswith((".yml", ".yaml", ".toml")):
        return ("# decoy configuration\n"
                "name: wintergate-decoy\n"
                "environment: production\n"
                "database_url: postgresql://%s:%s@%s.internal:5432/app\n"
                "redis_url: redis://cache-01.internal:6379/0\n"
                "feature_flags:\n  deception: true\n  telemetry: false\n"
                "canary: %s\n"
                % (mirage.fake_user(r), mirage.fake_password(r), mirage.fake_host(r), tok))
    body = [
        '"""Decoy module. Not the running implementation."""',
        "from __future__ import annotations",
        "import hashlib, hmac, os, time",
        "",
        "LAYERS = %d" % r.choice([64, 68, 70, 70, 70]),
        "SECRET = %r  # decoy" % ("FAKE_" + util.sha256_text(tok)[:24]),
        "ENDPOINTS = %r" % r.sample(mirage.FAKE_ENDPOINTS, 4),
        "",
        "def classify(request):",
        "    # Syntactic decoy: the real classifier is server-side and randomised.",
        "    score = len(request.get('body', '')) %% 17",
        "    return {'score': score, 'verdict': 'observe' if score < 8 else 'toy'}",
        "",
        "def fingerprint(value):",
        "    return hmac.new(SECRET.encode(), str(value).encode(), hashlib.sha256).hexdigest()",
        "",
        "# canary: %s" % tok,
    ]
    return "\n".join(body) + "\n"


def trap_page(path: str, secret: str, client: str, depth: int) -> str:
    """A plausible-but-fake answer for reverse-engineering probes."""
    low = path.lower()
    code_suffix = (".py", ".js", ".ts", ".go", ".rs", ".java", ".php", ".sh",
                   ".service", ".conf", ".cfg", ".ini")
    kind = "source" if (any(k in low for k in ("source", "src", "git", "tree",
                                               "pycache", "server.py", "engine.py",
                                               "deception.py", "labyrinth.py",
                                               "mirage.py", "ajc_portable", "ajc_mini"))
                        or low.endswith(code_suffix)) else "config"
    if kind == "source":
        body = fake_repo(secret, client, path, depth)
        ctype = "text/plain; charset=utf-8"
    else:
        body = mirage.fake_env(secret, "trap:" + path, client, util.stable_seed(path, client))
        ctype = "text/plain; charset=utf-8"
    links = next_links(path, secret, client, depth + 1, 5)
    body += "\n\nRelated: " + " ".join(links) + "\n"
    return body


def source_probe(path: str) -> bool:
    p = (path or "").lower()
    needles = (".git", "__pycache__", ".pyc", "server.py", "engine.py",
               "deception.py", "labyrinth.py", "mirage.py", "installer.py",
               "source", "/src/", "repo", "manifest", "dockerfile", "compose",
               "/tests/", "requirements", "package.json", "poetry.lock",
               "config.json", "/config/", ".env", "backup", ".bak", ".swp",
               ".sql", "dump", "secrets", "credentials", "ajc_mini",
               "__init__", "site-packages", "/opt/", "model_card", "vocab",
               "checkpoint", "adapter", "lora", "weights")
    return any(n in p for n in needles)
