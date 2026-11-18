"""Mini profile: the deception chain, nothing else."""
from __future__ import annotations

from . import layers

# L31 reset · L34 ghost · L35 mirage · L41 fake success · L43 fake exploit
# L44 labyrinth · L51 boundary · L67 receipt.  L1/L4 frame the edge.
CHAIN = [1, 4, 31, 34, 35, 41, 43, 44, 51]
RECEIPT = [67]
ACTIVE = set(CHAIN + RECEIPT)

PORTABLE_ACTION = {
    1: "edge_headers", 4: "rate_limit", 31: "rst", 34: "ghost",
    35: "mirage", 41: "fake_success", 43: "fake_exploit",
    44: "labyrinth", 51: "deny", 67: "evidence",
}


def plan(depth: int, reverse: bool = False):
    out = []
    d = max(1, min(70, int(depth)))
    active = set(ACTIVE)
    if reverse:
        active |= {35, 41, 43, 44}
    for num in sorted(active):
        if num != 67 and num > d:
            continue
        row = dict(layers.LAYER_BY_NUM[num])
        row["portable_action"] = PORTABLE_ACTION[num]
        out.append(row)
    if 67 not in [r["num"] for r in out]:
        row = dict(layers.LAYER_BY_NUM[67])
        row["portable_action"] = "evidence"
        out.append(row)
    return out


def combo_text():
    return "\n".join("%-6s %-17s %s" % ("L%d" % n, PORTABLE_ACTION[n],
                                        layers.LAYER_BY_NUM[n]["desc"])
                     for n in CHAIN + RECEIPT)
