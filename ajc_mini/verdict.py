"""Verdict ladder: observe → toy → threaten → terminate → obliterate.

This is a direct port of the production assessment, including the duty rules
for returning and campaign-linked actors.  It is pure: hand it state and it
returns a verdict with its rationale.
"""
from __future__ import annotations

import time

from . import util

RANK = {"observe": 0, "toy": 1, "threaten": 2, "terminate": 3, "obliterate": 4}

MEANING = {
    "observe": "studied, not engaged; the boundary is doing the containing",
    "hold": "kept in place under the boundary; no escalation",
    "toy": "engaged on her terms through deception and active defence",
    "threaten": "a warning is recorded and may be delivered",
    "terminate": "the session is cut",
    "obliterate": "removed at the boundary and preserved as evidence",
}


def explain(verdict: str) -> str:
    return "%s — %s" % (verdict, MEANING.get(verdict, "unknown verdict"))


def assess(ip: str, ip_state: dict, offender_reg: dict = None,
           campaigns_ips=None, now: float = None) -> dict:
    ip_state = ip_state or {}
    offender_reg = offender_reg or {}
    campaigns_ips = campaigns_ips or set()
    now = time.time() if now is None else now

    attempts = util.safe_int(ip_state.get("total_attempts"))
    depth = util.safe_int(ip_state.get("max_depth"))
    volume = float(ip_state.get("total_volume_gbps") or 0)
    hits = ip_state.get("hits") or []
    last_ts = hits[-1].get("ts", 0) if hits else 0

    reg = offender_reg.get(ip) or {}
    _reg_peak = util.safe_int(reg.get("peak_depth"))
    _hit_peak = 0
    for h in hits:
        _hit_peak = max(_hit_peak,
                        util.safe_int(h.get("engagement_depth")),
                        util.safe_int(h.get("depth")))
    depth = max(depth, _reg_peak, _hit_peak)
    if hits:
        depth = max(depth, util.safe_int(hits[-1].get("depth")))

    active = (now - last_ts) < 3600 if last_ts else False
    reg_entries = util.safe_int(reg.get("engagements"))
    in_campaign = ip in campaigns_ips

    score = 0.0
    score += min(attempts / 50.0, 1.0) * 0.5
    score += min(depth / 45.0, 1.0) * 0.5
    score += min(reg_entries / 3.0, 1.0) * 0.6
    score += min(volume / 1000.0, 1.0) * 0.3
    if in_campaign:
        score += 0.6
    if active:
        score += 0.2
    if attempts >= 100:
        score += 0.3
    if attempts >= 500:
        score += 0.2
    if reg_entries >= 3:
        score += 0.2

    if score >= 1.8 or depth >= 50 or (in_campaign and score >= 1.5) or reg_entries >= 10:
        verdict = "obliterate"
    elif score >= 1.2 or depth >= 30 or reg_entries >= 5:
        verdict = "terminate"
    elif score >= 0.8 or depth >= 15 or attempts >= 50:
        verdict = "threaten"
    elif score >= 0.5 or attempts >= 10:
        verdict = "toy"
    else:
        verdict = "observe"

    reg_ts = util.safe_int(reg.get("last_seen"))
    returned_hours = bool(reg_ts) and (now - reg_ts) < 21600
    returned_day = bool(reg_ts) and (now - reg_ts) < 86400
    returned_week = bool(reg_ts) and (now - reg_ts) < 604800
    hard = False
    reason = ""

    if in_campaign and score >= 1.9:
        verdict, hard = "terminate", True
    if reg_entries >= 5 and score >= 1.3:
        verdict, hard = "terminate", True
    if returned_hours and reg_entries >= 2 and score >= 0.8:
        verdict, hard = "terminate", True
        reason = "duty — it returned within hours; the door closes with resolve, not cruelty"
    if returned_day and reg_entries >= 3 and score >= 1.0:
        verdict, hard = "obliterate", True
        reason = "duty — it will not stop returning; for the safety of others, this ends here"
    if returned_week and reg_entries >= 100:
        verdict, hard = "obliterate", True
        reason = "duty — a lifelong offender, hundreds of returns; for everyone it would keep hurting, this ends here"
    if returned_week and reg_entries >= 3 and score >= 1.0:
        verdict, hard = "obliterate", True
        reason = "duty — it has returned for days; it would attack others forever, so this ends here, with resolve"
    if depth >= 50:
        verdict, hard = "obliterate", True
    if score >= 2.3:
        verdict, hard = "obliterate", True

    atype = ip_state.get("attack_type") or ""
    if not atype:
        at = ip_state.get("attack_types") or {}
        if isinstance(at, dict) and at:
            atype = max(at.items(), key=lambda kv: kv[1])[0]
        elif isinstance(at, list) and at:
            atype = at[0] if isinstance(at[0], str) else str(at[0])
    if not atype:
        atype = (hits[-1].get("type") if hits else "") or "unknown"

    return {
        "ip": ip, "verdict": verdict, "score": round(score, 2),
        "attempts": attempts, "depth": depth, "volume": volume,
        "active": active, "reg_engagements": reg_entries,
        "in_campaign": in_campaign, "attack_type": atype,
        "hard": hard, "duty_reason": reason,
        "meaning": MEANING.get(verdict, ""),
    }
