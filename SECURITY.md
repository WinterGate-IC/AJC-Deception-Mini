# Security model

## The honest boundary

The code is public. Anyone can read the classifier, the maze generator and the
fake-data maps. The defence does **not** depend on hiding them:

- the per-install canary secret is not published;
- the maze is seeded per client;
- decoy values rotate per session;
- a probe path is answered with a *fake* repository, not the running code;
- the receipt is tamper-evident.

A local operator with the source can study the logic. That is acceptable: the
goal is to make a bypass require a live, adaptive engagement — not a one-time
read.

## Anti-analysis controls

| Control | What it defeats |
| --- | --- |
| Per-install `canary_secret` | precomputed maze maps, shared walkthroughs |
| Per-client seed (secret + IP + path + depth) | replaying one attacker's graph against another |
| HMAC `?c=` link tokens | forged/edited maze links; tamper raises depth |
| Canary replay detection | scraping a decoy `.env`/dump and reusing it |
| Decoy source tree for `.git`/`source`/module paths | source disclosure and clone-the-repo bypass |
| Recursive URL decoding + null/backslash normalisation | encoded traversal and `%252e` probes |
| Behavioural classification | UA-only evasion; classification uses path, body, method and sequence |
| Randomised fake values | fingerprinting the install from scraped data |
| Bounded tarpit/ghost/RST | unbounded resource use against the defender |
| SHA-256 evidence chain | silent deletion or editing of the record |

## Escalation

- A source probe adds +4 to the session's boost.
- A bad `?c=` token adds +6 and counts as tamper.
- A canary replay adds +10 and marks the session terminal.
- Three tamper events, or two canary replays, drop the connection.
- Repeated maze hops keep raising the effective depth until it reaches the
  terminal boundary.

The effective depth feeds the plan, so a reverse-engineering session sees
deeper fake trees, more mazes and eventually a drop.

## Limits

- Not impossible to reverse. The source is readable; the deployment secret is
  not.
- Not attribution. Canaries and behaviour are signals, not proof of identity.
- Not retaliation. No raw packets, no reflection, no third-party action.
- Not a replacement for TLS, authentication, patching or backups.
- The fake data contains clearly fake credentials and canaries. Do not use it
  anywhere real.

## Reporting

Open a private security advisory on the repository with the endpoint, the
classification you received, and the expected behaviour. Do not include live
third-party data.
