"""Depth calculation — a faithful port of the production formula.

Two numbers, never one:

* ``penetration`` — how deep the attacker's own hit actually recorded.
* ``engagement`` — how hard the defensive stack escalates in response.

Conflating them is what makes a dashboard lie.  The portable build keeps them
separate and labels them everywhere.
"""
from __future__ import annotations

import math

from . import util

BYPASS_WEIGHTS = {
    "critical": 32, "high": 26, "medium": 16, "low": 8,
}

TYPE_DEPTH_BONUS = {
    "jndi_injection": 10, "ssrf": 9, "dns_exfil": 8, "c2_beacon": 10,
    "sqli": 9, "xss": 8, "command_injection": 10, "file_upload": 9,
    "path_traversal": 8, "bots_detected": 7, "syn_flood": 6, "rate_abuse": 6,
    "recon_scan": 7, "brute_force": 8, "ddos_amplification": 11,
    "ddos_volumetric": 12, "ddos_protocol": 10, "ddos_multi_vector": 14,
    "reflection_attack": 11, "state_exhaustion": 9, "fragmentation": 8,
    "slowloris": 7, "http_flood": 9, "dns_amplification": 11,
    "ntp_amplification": 11, "memcached_amplification": 12,
    "connection_flood": 9, "tls_renegotiation": 8, "zero_day_ddos": 15,
    "coordinated_botnet": 12, "pulse_wave": 10, "rce": 12, "lfi": 10,
    "rfi": 10, "file_inclusion": 10, "deserialization": 11, "jwt_attack": 9,
    "oauth_abuse": 9, "graphql_introspection": 8, "api_abuse": 8,
    "ssrf_blind": 9, "ssh_handshake": 3, "ssh_probe": 5, "ssh_scan": 6,
    "mysql_scan": 5, "rdp_scan": 6, "ftp_scan": 5, "smtp_scan": 5,
    "dns_scan": 4, "web_scan": 6, "tls_clienthello_probe": 4,
}

KNOWN_PAYLOAD_TYPES = {"sqli", "xss", "jndi_injection", "command_injection"}


def compute(severity: str = "low", event_type: str = "recon_scan",
            layers_bypassed: int = 0, attempts: int = 0, volume_gbps: float = 0.0,
            prev_depth: int = 0, zero_day_hits: int = 0,
            known_payload: bool = False, squeeze: int = 0,
            defense_bonus: int = 0, intel_bonus: int = 0) -> dict:
    severity = str(severity or "low").lower()
    event_type = str(event_type or "recon_scan").lower()
    base_depth = BYPASS_WEIGHTS.get(severity, 1)
    depth_bonus = TYPE_DEPTH_BONUS.get(event_type, 0)
    bypass_bonus = min(max(0, util.safe_int(layers_bypassed)) * 2, 14)

    volume_factor = 0
    if volume_gbps and volume_gbps > 0:
        volume_factor = min(int(math.log2(max(float(volume_gbps), 1)) * 0.7), 12)

    penetration = min(base_depth + depth_bonus + bypass_bonus, 70)
    persist_bonus = min(max(0, util.safe_int(attempts)) // 8, 30)
    engagement = min(penetration + volume_factor + persist_bonus, 70)

    squeeze = max(0, util.safe_int(squeeze))
    if prev_depth >= 22:
        squeeze = max(squeeze - 2, 0)
    penetration = max(penetration - squeeze, 1)

    pen_reduce = min(max(penetration - 1, 0), 2 + max(0, util.safe_int(defense_bonus)) // 30000)
    penetration = max(penetration - pen_reduce, 1)
    intel_reduce = min(max(penetration - 1, 0), 2 + max(0, util.safe_int(intel_bonus)) // 40000)
    penetration = max(penetration - intel_reduce, 1)

    if event_type in KNOWN_PAYLOAD_TYPES and known_payload:
        penetration = max(penetration - 1, 1)

    if prev_depth >= 55:
        aggress = 10
    elif prev_depth >= 45:
        aggress = 8
    elif prev_depth >= 35:
        aggress = 6
    elif prev_depth >= 25:
        aggress = 4
    elif prev_depth >= 15:
        aggress = 2
    else:
        aggress = 0
    aggress += min(max(0, util.safe_int(zero_day_hits)) * 2, 6)

    engagement = min(engagement + aggress, 70)
    engagement = min(max(engagement, penetration), 70)

    return {
        "penetration": int(penetration),
        "engagement": int(engagement),
        "base": base_depth,
        "type_bonus": depth_bonus,
        "bypass_bonus": bypass_bonus,
        "volume_factor": volume_factor,
        "persist_bonus": persist_bonus,
        "squeeze": squeeze,
        "aggression": aggress,
        "layer": int(penetration),
    }


def explain(result: dict) -> str:
    return (
        "penetration L%d (base %d + type %d + bypass %d − squeeze %d); "
        "engagement L%d (volume %d + persistence %d + aggression %d)"
        % (
            result["penetration"], result["base"], result["type_bonus"],
            result["bypass_bonus"], result["squeeze"], result["engagement"],
            result["volume_factor"], result["persist_bonus"], result["aggression"],
        )
    )
