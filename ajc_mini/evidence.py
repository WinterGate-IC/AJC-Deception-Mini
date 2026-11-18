"""L67 receipt: hash-chained evidence, notices and reports.

The default is an append-only text log with a SHA-256 chain.  An optional
SQLite mirror is available for operators who prefer a database; it is not
required by any other module.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import util

NOTICE = """WINTERGATEIC NOTICE — {iso} (UTC)
Automated active-defense record for IP {ip}.
Category: {category} ({attack}) at L{depth}.
Threat volume: {volume:.2f} Gbps · packets engaged: {packets} · confidence {confidence:.0f}%.
Verdict: {verdict} — {meaning}

Framing: this engagement was a DEFENSIVE ACTION against an active threat.
{ip} probed/scanned/attempted intrusion against this deployment before any
countermeasure was deployed. All actions were confined to this deployment and
the attacker's own engagement, were proportionate to the threat, and are
preserved in the tamper-evident evidence log (L67) with a SHA-256 chain.

No further action. Engagement terminated automatically when the threat subsided.

Actions: {actions}
Signals: {signals}
"""


def notice_text(ip: str, attack: str = "unknown", depth: int = 1,
                verdict: str = "observe", meaning: str = "",
                volume_gbps: float = 0.0, packets: int = 0,
                confidence: float = 0.0, actions="", signals="",
                category: str = "") -> str:
    return NOTICE.format(
        iso=util.iso(), ip=ip, category=category or "defensive countermeasure",
        attack=attack, depth=int(depth), volume=float(volume_gbps or 0),
        packets=int(packets or 0), confidence=float(confidence or 0),
        verdict=verdict, meaning=meaning, actions=actions or "-",
        signals=signals or "-",
    )


def write_notice(store, ip: str, **kw) -> Path:
    return store.write_notice(ip, notice_text(ip, **kw))


def record(store, ip: str, attack: str, depth: int, verdict: str,
           actions, signals, severity: str = "low", extra: dict = None) -> dict:
    rec = {
        "kind": "engagement",
        "ip": ip,
        "attack": attack,
        "severity": severity,
        "depth": int(depth),
        "verdict": verdict,
        "actions": list(actions),
        "signals": list(signals),
    }
    if extra:
        rec.update(extra)
    return store.append_evidence(rec)


def report(store, days: int = 7, limit: int = 5000) -> str:
    cutoff = util.now() - max(1, int(days)) * 86400
    rows = []
    for line in util.tail_lines(store.evidence_path, limit):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if float(rec.get("ts") or 0) >= cutoff:
            rows.append(rec)
    counts = {}
    verdicts = {}
    for r in rows:
        counts[r.get("attack", "?")] = counts.get(r.get("attack", "?"), 0) + 1
        verdicts[r.get("verdict", "?")] = verdicts.get(r.get("verdict", "?"), 0) + 1
    lines = ["# AJC Portable — evidence report",
             "",
             "Period: last %d days · records: %d · generated: %s" % (days, len(rows), util.iso()),
             "", "## Attack types", ""]
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append("- %s: %d" % (k, v))
    lines += ["", "## Verdicts", ""]
    for k, v in sorted(verdicts.items(), key=lambda kv: -kv[1]):
        lines.append("- %s: %d" % (k, v))
    lines += ["", "## Integrity", ""]
    v = store.verify_evidence()
    lines.append("- chain: %s (%d records, %d bad)" % ("OK" if v["ok"] else "FAIL",
                                                        v["records"], len(v["bad"])))
    return "\n".join(lines) + "\n"


class SQLiteEvidence:
    """Optional append-only SQLite mirror with the same hash chain."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=5)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ts REAL NOT NULL, prev TEXT, hash TEXT NOT NULL, body TEXT NOT NULL)"
        )
        self.conn.commit()

    def append(self, rec: dict) -> dict:
        cur = self.conn.execute("SELECT hash FROM evidence ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev = row[0] if row else ""
        body = dict(rec)
        body.pop("hash", None)
        body["prev"] = prev
        body["ts"] = body.get("ts") or util.now()
        h = util.sha256_text(util.dumps(body))
        self.conn.execute("INSERT INTO evidence(ts,prev,hash,body) VALUES(?,?,?,?)",
                          (body["ts"], prev, h, util.dumps(body)))
        self.conn.commit()
        body["hash"] = h
        return body

    def verify(self) -> dict:
        prev = ""
        bad = []
        count = 0
        for rid, got, raw in self.conn.execute("SELECT id,hash,body FROM evidence ORDER BY id"):
            rec = json.loads(raw)
            if rec.get("prev") != prev:
                bad.append({"id": rid, "reason": "prev"})
            body = dict(rec)
            body.pop("prev", None)
            if util.sha256_text(util.dumps(body)) != got:
                bad.append({"id": rid, "reason": "hash"})
            prev = got
            count += 1
        return {"ok": not bad, "records": count, "bad": bad[:20]}

    def close(self):
        self.conn.close()
