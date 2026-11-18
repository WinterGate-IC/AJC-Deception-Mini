"""The deception layers shipped in Mini."""
from __future__ import annotations

LAYERS = [
    (1, "Edge Gateway", "TLS · headers · banner strip", "Parallel", "Block"),
    (4, "Rate Limiter", "Token bucket · per-IP", "Parallel", "429"),
    (31, "Ghost Harassment", "Reset a session mid-flight", "Parallel", "Flood"),
    (34, "Connection Ghosting", "Handshake, then silence", "Sequential", "Vanish"),
    (35, "Data Mirage", "Per-type fake success · decoy data", "Parallel", "Mirage"),
    (41, "Fake Success Inj", "Attack-type 200 OK", "Parallel", "Fool"),
    (43, "Fake Exploit Feedback", "Exploit confirmed — inert", "Sequential", "Troll"),
    (44, "Deception Labyrinth", "Endless signed redirects · fake API", "Parallel", "Maze"),
    (51, "Terminal Boundary", "Deny at the edge", "Sequential", "Obliterate"),
    (67, "Evidence Locker", "Hash-chained receipt", "Async", "Lock"),
]
LAYER_BY_NUM = {n: {"num": n, "name": name, "desc": desc, "mode": mode, "action": action}
                for n, name, desc, mode, action in LAYERS}
