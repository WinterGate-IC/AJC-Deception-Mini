# Install

## Requirements

- Python 3.9+.
- ~5 MB disk.
- Optional: Caddy or Nginx for TLS.

No `pip install` is required.

## Interactive

```sh
python3 installer.py
```

## Non-interactive

```sh
python3 installer.py --yes --no-service \
  --prefix /opt/ajc-mini --data-dir /var/lib/ajc-mini --port 8791
```

| Flag | Meaning |
| --- | --- |
| `--prefix`, `--data-dir` | locations |
| `--bind`, `--port`, `--token` | HTTP settings |
| `--trusted` | comma-separated IPs never dropped |
| `--no-service` | no systemd unit |
| `--dry-run` | print, change nothing |
| `--uninstall [--purge]` | remove code; `--purge` removes data |

## Run

```sh
./bin/ajc-mini demo
./bin/ajc-mini serve
curl -s localhost:8791/health
```

The console token is in `config.json` (0600) and printed by the installer.

## Behind Caddy

```caddy
example.invalid {
  header -Server
  header X-Frame-Options DENY
  header X-Content-Type-Options nosniff
  reverse_proxy 127.0.0.1:8791
}
```

Set `trust_proxy=true` only when the proxy is the sole path to the service.
