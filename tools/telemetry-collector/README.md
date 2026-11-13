# Arx improvement-program collector

Arx installations whose owner joined the improvement program (`arx telemetry enable`, or "yes"
during installation or `arx setup`) send an anonymous report every few days. This collector
receives those reports, stores them and emails a daily digest.

It is a single Python file with no dependencies beyond the standard library. It is **not** part of
the Arx package.

## What it receives

Exactly what `arx telemetry show` prints on an installation: the Arx version, the distribution,
kernel and architecture, the operating mode, the health of the watchers, and noise counters.
Arx never sends host names, IP addresses, paths, user names, commands, finding texts, keys or
configuration. See [`docs/telemetry.md`](../../docs/telemetry.md) for the field list.

The collector enforces this again on arrival:

- Each report is sanitized with the same rules as the client. Only numbers, booleans and short
  identifiers survive, and anything that looks like an IP address is dropped. A report without
  the expected schema, a random 32-hex installation id and a version string is rejected.
- Source IPs are never written anywhere. The HTTP access log is silenced.
- Reception time is stored with hour precision.
- One report per installation every 12 hours at most, plus a global per-minute cap.

## Deploy

You need a Linux server with Python 3.10+, a DNS name for it (for example
`telemetry.example.com`), and an SMTP account to send the digest.

```bash
sudo install -d -m 0755 /opt/arx-collector
sudo install -m 0644 collector.py /opt/arx-collector/collector.py
sudo install -m 0600 arx-collector.env.example /etc/arx-collector.env   # then edit it
sudo install -m 0644 arx-collector.service arx-collector-digest.service arx-collector-digest.timer \
     /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now arx-collector.service arx-collector-digest.timer
curl -s http://127.0.0.1:8787/healthz        # {"ok": true}
```

Put HTTPS in front of it. With Caddy, `Caddyfile.example` is enough: Caddy obtains the
certificate on its own. Keep the proxy's access log off.

The Arx client only reports over `https://`, to the URL fixed in `src/arx/telemetry.py`
(`ENDPOINT`). If the collector runs somewhere else, change that constant before the release.

## Settings

All settings are environment variables, normally kept in `/etc/arx-collector.env` (mode 0600):

| Variable | Default | Meaning |
|---|---|---|
| `ARX_COLLECTOR_BIND` | `127.0.0.1` | listen address (keep it local; the proxy faces the Internet) |
| `ARX_COLLECTOR_PORT` | `8787` | listen port |
| `ARX_COLLECTOR_DATA` | `/var/lib/arx-collector` | where `reports/YYYY-MM-DD.jsonl` live |
| `ARX_COLLECTOR_INTERVAL_DAYS` | `7` | cadence proposed to clients (they accept 1–30) |
| `ARX_COLLECTOR_MIN_GAP_H` | `12` | minimum hours between two reports of one installation |
| `ARX_COLLECTOR_MAX_PER_MIN` | `600` | global cap of accepted reports per minute |
| `ARX_COLLECTOR_MAIL_TO` | — | who receives the digest |
| `ARX_COLLECTOR_MAIL_FROM` | `MAIL_TO` | sender address |
| `ARX_COLLECTOR_SMTP_HOST` | — | SMTP server |
| `ARX_COLLECTOR_SMTP_PORT` | `587` | SMTP port |
| `ARX_COLLECTOR_SMTP_TLS` | `starttls` | `starttls`, `ssl` or `none` |
| `ARX_COLLECTOR_SMTP_USER` / `_PASSWORD` | — | SMTP login |

## Daily digest

The timer runs `collector.py digest` every morning at 06:17 UTC. It emails the previous UTC day's
summary to `ARX_COLLECTOR_MAIL_TO`, with that day's raw reports attached as `.jsonl.gz`:

- reports received, distinct installations, and installations active in the last 7 days
- versions, distributions, kernels, architectures, Python, tiers and modes
- watcher health: installations whose exec capture or file watch is not `full`, with
  overflows, drops or failed marks, or without auditd
- noise: high alerts, false positives, unreviewed alerts, mean false positives per day, and
  installations over the 0.1/day target
- stability: `self_down` by restart state, `self_stopped`, `self_tamper`, and self-checks
  that could not run
- alert delivery per channel, and high alerts by kind

Preview a digest without sending it:

```bash
sudo env ARX_COLLECTOR_DATA=/var/lib/arx-collector \
     python3 /opt/arx-collector/collector.py digest --dry-run --date 2026-11-20
sudo env ARX_COLLECTOR_DATA=/var/lib/arx-collector \
     python3 /opt/arx-collector/collector.py summary --days 30
```

## Retention

Reports are kept until you delete them. A simple policy is to keep 13 months:

```bash
find /var/lib/arx-collector/reports -name '*.jsonl' -mtime +400 -delete
```
