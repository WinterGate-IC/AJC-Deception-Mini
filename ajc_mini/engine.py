"""Mini decision engine: depth, verdict, deception plan, receipt."""
from __future__ import annotations

import hashlib
import time

from . import deception, depth, evidence, profiles, util, verdict as verdict_mod

ALIASES = {"sql_injection": "sqli", "command_injection": "command_injection",
           "cmd_injection": "command_injection", "traversal": "path_traversal",
           "lfi": "path_traversal", "rfi": "path_traversal", "recon": "recon_scan",
           "scanner": "web_scan", "credential_probe": "recon_scan",
           "source_probe": "recon_scan", "canary_replay": "api_abuse"}


def _atype(v):
    v = str(v or "recon_scan").strip().lower().replace(" ", "_")
    return ALIASES.get(v, v)


def _net(ip):
    if ":" in ip:
        return ip.rsplit(":", 2)[0] + "::/64"
    p = ip.split(".")
    return ".".join(p[:3]) + ".0/24" if len(p) == 4 else ip


class Engine:
    def __init__(self, config, store):
        self.config = config
        self.store = store
        store.update_memory(self._seed)

    def _seed(self, mem):
        mem.setdefault("decisions", [])
        mem.setdefault("profiles", {})
        mem.setdefault("lessons", [])
        mem.setdefault("stats", {})
        return mem

    def _trusted(self):
        raw = self.config.get("trusted_ips") or []
        if isinstance(raw, str):
            raw = [x.strip() for x in raw.split(",") if x.strip()]
        return set(raw) | {"127.0.0.1", "::1"}

    def handle_event(self, event, source="api"):
        ip = util.norm_ip(event.get("ip") or event.get("remote") or "")
        if not ip:
            return {"ok": False, "error": "invalid ip"}
        info = {}
        if not event.get("type"):
            info = deception.classify(event.get("method", "GET"),
                                      event.get("path", event.get("endpoint", "/")),
                                      event.get("headers") or {},
                                      event.get("body") or event.get("payload") or "")
        atype = _atype(event.get("type") or info.get("attack_type") or "recon_scan")
        severity = str(event.get("severity") or info.get("severity") or "low").lower()
        if severity not in ("low", "medium", "high", "critical"):
            severity = "low"
        payload = str(event.get("payload") or event.get("body") or "")[:8000]
        method = str(event.get("method") or "GET")[:12]
        endpoint = str(event.get("endpoint") or event.get("path") or "/")[:240]
        volume = float(event.get("volume_gbps") or 0)
        reverse = bool(event.get("reverse_engineering") or info.get("source_probe"))
        canary = bool(event.get("canary_replay") or info.get("canary_replay"))
        local = util.is_private_ip(ip) and not bool(self.config.get("allow_private"))
        trusted = ip in self._trusted()
        out = {}

        def _mut(state):
            now = util.now()
            ips = state.setdefault("ips", {})
            rec = ips.get(ip)
            if rec is None:
                rec = {"first_seen": now, "hits": [], "max_depth": 0,
                       "penetration_depth": 0, "total_attempts": 0,
                       "total_volume_gbps": 0.0, "attack_types": {},
                       "methods": {}, "engagements": 0, "campaigns": []}
                ips[ip] = rec
            rec["last_seen"] = now
            rec["total_attempts"] = util.safe_int(rec.get("total_attempts")) + 1
            rec["engagements"] = util.safe_int(rec.get("engagements")) + 1
            rec["total_volume_gbps"] = float(rec.get("total_volume_gbps") or 0) + volume
            rec.setdefault("attack_types", {})[atype] = util.safe_int(rec["attack_types"].get(atype)) + 1
            rec.setdefault("methods", {})[method] = util.safe_int(rec["methods"].get(method)) + 1
            recent = [h for h in rec.get("hits") or [] if now - float(h.get("ts", 0)) < 3600]
            d = depth.compute(severity=severity, event_type=atype,
                              layers_bypassed=len(recent),
                              attempts=rec["total_attempts"], volume_gbps=volume,
                              prev_depth=util.safe_int(rec.get("max_depth")))
            pen, eng = d["penetration"], d["engagement"]
            rec["penetration_depth"] = max(util.safe_int(rec.get("penetration_depth")), pen)
            rec["max_depth"] = max(util.safe_int(rec.get("max_depth")), eng)
            rec["hits"] = (rec.get("hits") or [])[-49:] + [{
                "ts": now, "type": atype, "severity": severity,
                "depth": pen, "engagement_depth": eng, "method": method,
                "endpoint": endpoint}]
            rec["attack_type"] = max(rec["attack_types"].items(), key=lambda kv: kv[1])[0]
            offender = {ip: {"engagements": rec["engagements"],
                             "peak_depth": rec["max_depth"],
                             "last_seen": rec["last_seen"]}}
            camp = self._campaign(state, rec, ip, atype, method, now)
            v = verdict_mod.assess(ip, rec, offender,
                                   campaigns_ips={ip} if camp else set(), now=now)
            actions = [r["portable_action"] for r in profiles.plan(eng, reverse)]
            deny = False
            reason = ""
            if not local and not trusted:
                if canary:
                    deny, reason = True, "canary replay"
                elif v["verdict"] == "obliterate" or eng >= 51:
                    deny, reason = True, "terminal boundary L51"
                elif v["verdict"] == "terminate":
                    deny, reason = True, "verdict terminate"
            if deny:
                state.setdefault("deny", {})[ip] = {"until": now + 86400, "reason": reason}
                rec["denied"] = True
            counters = state.setdefault("counters", {})
            counters["events"] = util.safe_int(counters.get("events")) + 1
            for a in actions:
                counters["action_" + a] = util.safe_int(counters.get("action_" + a)) + 1
            if reverse:
                counters["reverse_engineering"] = util.safe_int(counters.get("reverse_engineering")) + 1
            if canary:
                counters["canary_replay"] = util.safe_int(counters.get("canary_replay")) + 1
            controls = {
                "drop": bool(deny), "rst": eng >= 31, "ghost": eng >= 34,
                "tarpit": len(actions) > 3, "tarpit_delay": 0.0,
                "deception": 3 if (reverse or canary or eng >= 41) else 2,
                "reverse_engineering": reverse, "canary_replay": canary,
                "deny_reason": reason,
            }
            if controls["tarpit"]:
                controls["tarpit_delay"] = min(
                    float(self.config.get("deception.tarpit_max_ms") or 900),
                    120 + min(eng, 40) * 16) / 1000.0
            out.update({"ok": True, "ip": ip, "attack_type": atype,
                        "severity": severity, "method": method, "endpoint": endpoint,
                        "penetration_depth": pen, "engagement_depth": eng,
                        "verdict": v["verdict"], "verdict_detail": v,
                        "actions": actions, "controls": controls,
                        "campaign": camp, "ts": now})
            rec["last_verdict"] = v["verdict"]
            state["last_event"] = {"ip": ip, "type": atype, "depth": pen,
                                   "verdict": v["verdict"], "ts": now}
            return state

        self.store.update_state(_mut)
        self._remember(out, reverse, canary)
        self._receipt(out)
        self.store.append_event({"ts": out["ts"], "ip": ip, "type": atype,
                                 "depth": out["penetration_depth"],
                                 "verdict": out["verdict"], "source": source})
        return out

    def _campaign(self, state, rec, ip, atype, method, now):
        camps = state.setdefault("campaigns", {})
        key = "%s|%s" % (atype, _net(ip))
        c = camps.setdefault(key, {"id": key, "type": atype, "ips": [],
                                   "events": 0, "first": now, "methods": {}})
        c["last"] = now
        c["events"] = util.safe_int(c.get("events")) + 1
        c["methods"][method] = util.safe_int(c["methods"].get(method)) + 1
        if ip not in c["ips"]:
            c["ips"] = (c["ips"] + [ip])[-500:]
        if len(camps) > 2000:
            for k in sorted(camps, key=lambda k: camps[k].get("last", 0))[:500]:
                camps.pop(k, None)
        return key if len(c["ips"]) >= 2 else ""

    def _remember(self, d, reverse, canary):
        def _mut(mem):
            dec = mem.setdefault("decisions", [])
            dec.append({"ts": d["ts"], "ip": d["ip"], "verdict": d["verdict"],
                        "depth": d["penetration_depth"], "engagement": d["engagement_depth"],
                        "attack_type": d["attack_type"], "actions": d["actions"]})
            mem["decisions"] = dec[-1000:]
            p = mem.setdefault("profiles", {}).setdefault(d["ip"], {
                "first_seen": d["ts"], "engagements": 0, "total_attempts": 0,
                "max_depth": 0, "attack_types": {}, "source_probes": 0,
                "canary_hits": 0})
            p["last_seen"] = d["ts"]
            p["engagements"] += 1
            p["total_attempts"] += 1
            p["max_depth"] = max(p["max_depth"], d["engagement_depth"])
            p["attack_types"][d["attack_type"]] = util.safe_int(p["attack_types"].get(d["attack_type"])) + 1
            p["last_verdict"] = d["verdict"]
            if reverse:
                p["source_probes"] = util.safe_int(p.get("source_probes")) + 1
            if canary:
                p["canary_hits"] = util.safe_int(p.get("canary_hits")) + 1
            if reverse or canary or d["verdict"] in ("terminate", "obliterate"):
                lessons = mem.setdefault("lessons", [])
                lessons.append({"ts": d["ts"], "ip": d["ip"],
                                "kind": "reverse_engineering" if reverse else
                                        "canary_replay" if canary else "terminal",
                                "text": "%s at L%d → %s" % (d["attack_type"],
                                                            d["engagement_depth"], d["verdict"])})
                mem["lessons"] = lessons[-500:]
            s = mem.setdefault("stats", {})
            s["events"] = util.safe_int(s.get("events")) + 1
            s["last_verdict"] = d["verdict"]
            return mem
        self.store.update_memory(_mut)

    def _receipt(self, d):
        if not (d["penetration_depth"] >= 41 or d["verdict"] in ("terminate", "obliterate")
                or d["controls"].get("reverse_engineering") or d["controls"].get("canary_replay")):
            return
        try:
            rec = evidence.record(self.store, d["ip"], d["attack_type"],
                                  d["penetration_depth"], d["verdict"], d["actions"],
                                  d["controls"].get("deny_reason") or d["severity"])
            state = self.store.load_state()
            ipr = (state.get("ips") or {}).get(d["ip"]) or {}
            if (d["controls"].get("canary_replay") or d["controls"].get("reverse_engineering")
                    or util.now() - float(ipr.get("last_notice") or 0) > 21600):
                evidence.write_notice(self.store, d["ip"], attack=d["attack_type"],
                                      depth=d["penetration_depth"], verdict=d["verdict"],
                                      meaning=d["verdict_detail"].get("meaning", ""),
                                      actions=", ".join(d["actions"]))
                def _mark(st):
                    st.setdefault("ips", {}).setdefault(d["ip"], {})["last_notice"] = util.now()
                    return st
                self.store.update_state(_mark)
            return rec
        except Exception:
            return None

    def status(self):
        st = self.store.stats()
        state = self.store.load_state()
        mem = self.store.load_memory()
        top = sorted((state.get("ips") or {}).items(),
                     key=lambda kv: -util.safe_int(kv[1].get("total_attempts")))[:8]
        return {"ts": util.now(), "variant": "mini", "profile": "deception",
                "layers": len(profiles.ACTIVE), "stats": st,
                "last_event": state.get("last_event"),
                "evidence": self.store.verify_evidence(),
                "top": [{"ip": ip, "attempts": util.safe_int(r.get("total_attempts")),
                         "depth": util.safe_int(r.get("max_depth")),
                         "verdict": r.get("last_verdict")} for ip, r in top],
                "memory": {"decisions": len(mem.get("decisions") or []),
                           "profiles": len(mem.get("profiles") or {}),
                           "lessons": len(mem.get("lessons") or [])}}

    def summary_text(self):
        s = self.status()
        lines = ["AJC Deception Mini · %d layers · evidence %s (%d records)" % (
            s["layers"], "OK" if s["evidence"]["ok"] else "FAIL",
            s["evidence"]["records"]),
            "Events: %d · attempts: %d · denied: %d" % (
                util.safe_int(s["stats"].get("counters", {}).get("events")),
                s["stats"].get("total_attempts", 0), s["stats"].get("denied", 0))]
        if s["top"]:
            t = s["top"][0]
            lines.append("Top: %s · %d attempts · L%d · %s" % (
                t["ip"], t["attempts"], t["depth"], t["verdict"]))
        if s["last_event"]:
            e = s["last_event"]
            lines.append("Last: %s %s → L%s %s" % (e["ip"], e["type"], e["depth"], e["verdict"]))
        return "\n".join(lines)

    def tick(self):
        removed = self.store.prune(self.config.get("retention") or {})
        return {"pruned": removed, "ok": True}
