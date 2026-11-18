# AJC Deception Mini

A small, standalone deception engine: **data mirage**, **fake success**, **fake
exploit feedback**, and a **per-client deception labyrinth**, plus a hash-chained
receipt. No LLM. No heavy dependencies. Python 3.9+ only.

This is the public, deliberately limited release. It is not the full 70-layer
engine and it does not include the private detection/response stack.

> Defensive deception only. It never emits raw packets and never acts outside
> the service it runs.

---

## What it does

- Serves convincing fake data for SQLi, traversal, `.env`, cloud metadata,
  credential probes, uploads and command-injection attempts.
- Returns fake success and inert exploit feedback so tooling iterates against a
  dead end.
- Generates a per-client labyrinth of admin panels, fake APIs, fake file
  listings and a fake repository tree.
- Uses signed canaries in every decoy surface to detect replay and scraping.
- Answers reverse-engineering probes with a **decoy source tree**, never this
  program.
- Records a SHA-256-chained receipt for escalations, canary replay and
  reverse-engineering attempts.
- Bounded tarpit/ghost/RST on the deployment's own connections.

## Quick start

```sh
python3 installer.py --yes --no-service
./bin/ajc-mini demo
./bin/ajc-mini serve
```

The installer prints a console URL with a per-install token.

Bare minimum:

```sh
python3 installer.py --yes --no-service --prefix ./mini --data-dir ./mini-data
```

Only `python3` is required. Behind a TLS proxy, use Caddy/Nginx; the engine sets
its own defensive headers but does not terminate TLS.

## Why bypassing it is not a simple code read

The source is public on purpose. **Secrecy of the code is not the control.**

1. **Per-install secret.** `canary_secret` is generated on install and signs maze
   links and decoy tokens. Two deployments do not share a graph.
2. **Per-client graph.** The maze seed includes the secret, the client identity,
   the path and the depth. A walkthrough cannot be replayed against another
   client.
3. **Signed links.** `?c=` tokens are HMACs. Tampering is detected and raises the
   session's deception level; three bad tokens terminate it.
4. **Canary replay = terminal.** Every fake `.env`, SQL dump, key and API reply
   carries a unique canary. A canary from another client is not a valid request.
5. **Reverse-engineering probes get a decoy repository.** `/.git`, `source/`,
   `engine.py`, `ajc_mini/`, backups, configs and model paths return a plausible
   fake tree/code with canaries — while the session escalates.
6. **Sequence awareness.** Following the maze mechanically, requesting many
   distinct decoy endpoints, or probing internals increases the depth.
7. **Randomised data.** Fake users, hosts, hashes, passwords and paths rotate per
   session; scraped values are not reusable and do not fingerprint the install.
8. **Bounded effects.** Delays, holds and connection caps are finite, so the
   defence cannot be turned into a self-DoS.
9. **No static handler.** The HTTP process cannot serve its own package, a
   directory listing, or a backup file.

Read [SECURITY.md](SECURITY.md) for the honest limits of these claims.

## Commands

```sh
ajc-mini serve
ajc-mini demo
ajc-mini status [--json]
ajc-mini layers
ajc-mini evidence
ajc-mini doctor
ajc-mini event --json '{"ip":"198.51.100.7","type":"sqli","severity":"high", ...}'
```

## API

- `GET /health` — minimal, no counts.
- `GET /mini/?token=…` — status JSON.
- `POST /mini/api/event` — ingest an event (token).
- `GET /mini/api/layers`, `GET /mini/api/verify`.

Everything else is deception.

## License

MIT.
