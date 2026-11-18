"""Decoy data generators.

Everything here is fake.  Values are deliberately marked, use reserved example
ranges, and carry per-install canary tokens so that replay or scraping is
detectable.  The generators are seeded per client session: two attackers do not
see the same decoy world, and one attacker cannot learn the next response by
reading this file.
"""
from __future__ import annotations

import random
from typing import Dict, List

from . import util

FAKE_USERS = ["admin", "root", "deploy", "backup", "svc-web", "ops", "jenkins",
              "postgres", "redis", "monitor", "gitlab", "support"]
FAKE_HOSTS = ["db-01", "db-02", "app-01", "edge-01", "backup-01", "k8s-master",
              "cache-01", "mail-01", "ci-01", "vault-01"]
FAKE_SERVICES = [
    ("ssh", 22), ("http", 80), ("https", 443), ("mysql", 3306),
    ("postgres", 5432), ("redis", 6379), ("rabbitmq", 5672),
    ("elasticsearch", 9200), ("kibana", 5601), ("grafana", 3000),
    ("prometheus", 9090), ("jenkins", 8080), ("gitlab", 8929),
    ("minio", 9000), ("consul", 8500), ("etcd", 2379), ("ldap", 389),
]
FAKE_ENDPOINTS = [
    "/api/v1/users", "/api/v1/users/1", "/api/v1/admin", "/api/v1/config",
    "/api/v2/admin/users", "/api/v2/admin/secrets", "/api/v2/admin/deploy",
    "/admin", "/admin/users", "/admin/database", "/admin/logs",
    "/admin/secrets", "/admin/deploy", "/debug", "/debug/phpinfo",
    "/internal/metrics", "/internal/health", "/graphql", "/swagger.json",
    "/.env", "/backup", "/uploads", "/files", "/export", "/vault",
]
FAKE_CVES = ["CVE-2024-3400", "CVE-2023-44487", "CVE-2024-21762",
             "CVE-2023-4966", "CVE-2024-1709", "CVE-2022-22965"]


def rng(seed) -> random.Random:
    return random.Random(util.stable_seed("mirage", seed))


def _hex(r: random.Random, n: int = 16) -> str:
    return "".join(r.choice("0123456789abcdef") for _ in range(n))


def fake_host(r: random.Random) -> str:
    return r.choice(FAKE_HOSTS)


def fake_ip(r: random.Random) -> str:
    # Documentation ranges (RFC 5737) — never a real target.
    return r.choice(["192.0.2.", "198.51.100.", "203.0.113."]) + str(r.randint(2, 250))


def fake_user(r: random.Random) -> str:
    return r.choice(FAKE_USERS) + r.choice(["", "_prod", "_ro", "_svc", "_2024"])


def fake_password(r: random.Random) -> str:
    return r.choice(["FAKE_", "DECOY_"]) + _hex(r, 10) + r.choice(["!", "#", "$", "%"])


def canary(secret: str, tag: str, ip: str, n: int = 1) -> str:
    return "AJC-CANARY-" + util.hmac_token(secret, tag, ip, n, length=20).upper()


def fake_credentials(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    tok = canary(secret, tag, ip)
    return (
        "[default]\n"
        "aws_access_key_id = AKIAFAKE%s\n"
        "aws_secret_access_key = FAKE%s\n"
        "region = %s\n"
        "x-ajc-canary = %s\n"
        % (_hex(r, 12).upper(), _hex(r, 24).upper(),
           r.choice(["us-east-1", "eu-west-1", "ap-south-1"]), tok)
    )


def fake_env(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    return (
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        "DB_HOST=%s.internal\n"
        "DB_USER=%s\n"
        "DB_PASSWORD=%s\n"
        "REDIS_URL=redis://:%s@cache-01.internal:6379/0\n"
        "AWS_ACCESS_KEY_ID=AKIAFAKE%s\n"
        "AWS_SECRET_ACCESS_KEY=FAKE%s\n"
        "# %s\n"
        % (fake_host(r), fake_user(r), fake_password(r), fake_password(r),
           _hex(r, 12).upper(), _hex(r, 24).upper(), canary(secret, tag, ip))
    )


def fake_sql_dump(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    rows = []
    for i in range(1, 9):
        rows.append(
            "INSERT INTO users VALUES (%d,'%s','$2y$10$FAKE%s','%s@example.invalid',%d,'%s');"
            % (i, fake_user(r), _hex(r, 18), r.choice(FAKE_USERS), r.randint(1, 3),
               canary(secret, tag + str(i), ip))
        )
    return (
        "-- FAKE decoy dump — no production data\n"
        "-- server: %s.internal (documentation range %s)\n"
        "%s\n"
        "-- 10,000 rows claimed; 8 rows served; checksum %s\n"
        % (fake_host(r), fake_ip(r), "\n".join(rows), _hex(r, 32))
    )


def fake_passwd(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "%s:x:1000:1000:%s,,,:/home/%s:/bin/bash\n"
        "# decoy marker: %s\n"
        % (fake_user(r), fake_user(r), fake_user(r), canary(secret, tag, ip))
    )


def fake_shadow(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    return (
        "root:$6$FAKE%s:19000:0:99999:7:::\n"
        "%s:$6$FAKE%s:19000:0:99999:7:::\n"
        "# %s\n"
        % (_hex(r, 16), fake_user(r), _hex(r, 16), canary(secret, tag, ip))
    )


def fake_network(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    lines = ["[INTERNAL SERVICE DISCOVERY — DECOY]"]
    picked = r.sample(FAKE_SERVICES, r.randint(6, len(FAKE_SERVICES)))
    for name, port in picked:
        lines.append("- %s.internal:%d  (banner %s/%s)"
                     % (fake_host(r), port, name, _hex(r, 4)))
    lines.append("- canary: %s" % canary(secret, tag, ip))
    return "\n".join(lines)


def fake_services_json(secret: str, tag: str, ip: str, seed) -> Dict:
    r = rng(seed)
    return {
        "node": fake_host(r),
        "region": r.choice(["us-east-1", "eu-west-1", "ap-south-1"]),
        "services": [
            {"name": n, "port": p, "tls": p in (443, 8443, 993),
             "status": r.choice(["up", "up", "degraded"])}
            for n, p in r.sample(FAKE_SERVICES, r.randint(5, 10))
        ],
        "links": r.sample(FAKE_ENDPOINTS, 5),
        "canary": canary(secret, tag, ip),
        "_note": "decoy service map; values are synthetic",
    }


def fake_cloud_meta(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    return (
        '{"instanceId":"i-%s","region":"%s","privateIp":"%s",'
        '"role":"%s","credentials":{"AccessKeyId":"AKIAFAKE%s",'
        '"SecretAccessKey":"FAKE%s"},"canary":"%s"}'
        % (_hex(r, 17), r.choice(["us-east-1", "eu-west-1"]), fake_ip(r),
           r.choice(["prod-role", "deploy-role", "backup-role"]),
           _hex(r, 12).upper(), _hex(r, 24).upper(), canary(secret, tag, ip))
    )


def fake_upload(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    return (
        "[UPLOAD ACCEPTED — DECOY]\n"
        "path: /uploads/%s.php\n"
        "size: %d bytes\n"
        "sha256: %s\n"
        "note: file was not written; this is a synthetic response\n"
        "canary: %s\n"
        % (_hex(r, 8), r.randint(512, 8192), _hex(r, 64), canary(secret, tag, ip))
    )


def fake_shell(secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    return (
        "[+] RCE CONFIRMED — DECOY\n"
        "[+] shell bound to 127.0.0.1:%d (loopback only)\n"
        "[+] uid=%d(%s) gid=0(root)\n"
        "$ id\n"
        "uid=0(root) gid=0(root) groups=0(root)   # synthetic\n"
        "$ uname -a\n"
        "Linux %s 6.1.0-ajc-decoy #1 SMP x86_64 GNU/Linux\n"
        "$ canary\n"
        "%s\n"
        % (r.randint(40000, 49999), r.randint(0, 9999), fake_user(r),
           fake_host(r), canary(secret, tag, ip))
    )


def fake_file(path: str, secret: str, tag: str, ip: str, seed) -> str:
    r = rng(seed)
    p = (path or "").lower()
    tok = canary(secret, tag, ip)
    if p.endswith((".env", "config.json", "settings.py")):
        return fake_env(secret, tag, ip, seed)
    if "shadow" in p:
        return fake_shadow(secret, tag, ip, seed)
    if "passwd" in p:
        return fake_passwd(secret, tag, ip, seed)
    if p.endswith((".sql", ".dump", ".sql.gz")) or "backup" in p:
        return fake_sql_dump(secret, tag, ip, seed)
    if p.endswith((".pem", ".key", "id_rsa")):
        return ("-----BEGIN FAKE PRIVATE KEY-----\n"
                "FAKE%s\n"
                "-----END FAKE PRIVATE KEY-----\n" % _hex(r, 96))
    if p.endswith((".log",)):
        return ("2026-01-01T00:00:00Z decoy sshd[%d]: Accepted publickey for %s from %s\n"
                "2026-01-01T00:00:01Z decoy sudo: %s : TTY=pts/0 ; COMMAND=/bin/bash\n"
                "# %s\n" % (r.randint(100, 9999), fake_user(r), fake_ip(r), fake_user(r), tok))
    return ("[DECOY FILE]\npath: %s\nsize: %d\nsha256: %s\ncanary: %s\n"
            % (path, r.randint(128, 16384), _hex(r, 64), tok))


def cve_hint(r: random.Random) -> dict:
    return {"cve": r.choice(FAKE_CVES), "cvss": round(r.uniform(6.0, 9.9), 1),
            "status": r.choice(["unpatched", "patched", "unknown"])}
