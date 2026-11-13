# Collector on a Docker host behind a Cloudflare Tunnel

This kit runs the collector as a container on a host that already publishes its sites through a
Cloudflare Tunnel (`cloudflared`). The collector publishes no port: `cloudflared` reaches it on the
tunnel's Docker network, and Cloudflare provides HTTPS.

| File | Goes to |
|---|---|
| `../collector.py` | `/volume2/docker/services/arx-collector/collector.py` |
| `docker-compose.yml` | `/volume2/docker/services/arx-collector/docker-compose.yml` |
| `env.example` | `/volume2/docker/services/arx-collector/.env` (mode 0600, edited) |
| `arx-collector.cron` | `/etc/cron.d/arx-collector` (root, 0644) |

Adjust the paths if your Docker stack lives elsewhere.

## 1. Files and the data directory

```bash
sudo install -d -m 0755 /volume2/docker/services/arx-collector
sudo install -d -m 0750 -o 10001 -g 10001 /volume2/docker/volumes/arx-collector
cd /volume2/docker/services/arx-collector
sudo install -m 0644 /path/to/collector.py /path/to/docker-compose.yml .
sudo install -m 0600 /path/to/env.example .env
```

The container runs as uid 10001 with a read-only root filesystem, no capabilities, 256 MB of memory
and half a CPU. Only `/volume2/docker/volumes/arx-collector` is writable.

## 2. Settings

Edit `.env`:

- `ARX_COLLECTOR_MAIL_TO`: who receives the daily digest.
- `ARX_COLLECTOR_MAIL_FROM`: an address on a domain your mail provider lets you send from.
- SMTP: with Resend, host `smtp.resend.com`, port `465`, TLS `ssl`, user `resend`, and a Resend API
  key with sending access as the password. A key dedicated to the collector is better than reusing
  another service's.
- Add `ARX_TUNNEL_NETWORK=<network>`: the Docker network `cloudflared` is attached to. Find it with:

```bash
docker inspect cloudflared --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}'
```

If `cloudflared` runs with `network_mode: host`, the container cannot join its network. Then remove
the `networks:` sections from the compose file, add `ports: ["127.0.0.1:8787:8787"]`, and point the
tunnel at `http://localhost:8787`.

## 3. Start it

```bash
cd /volume2/docker/services/arx-collector
docker compose up -d
docker ps --filter name=arx-collector          # "healthy" after about a minute
docker exec arx-collector python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8787/healthz').read())"
```

## 4. Publish it through the tunnel

Add a public hostname for the collector, for example `telemetry.example.com`, with service
`http://arx-collector:8787`:

- **Tunnel managed from the dashboard** (`cloudflared tunnel run --token …`): Cloudflare Zero Trust →
  Networks → Tunnels → your tunnel → Public Hostname → Add. Cloudflare creates the DNS record.
- **Tunnel managed by a `config.yml`**: add the ingress rule above the final catch-all, run
  `cloudflared tunnel route dns <tunnel> telemetry.example.com`, and restart `cloudflared`.

Check that no security rule challenges the endpoint: servers send these reports, not browsers. If
Bot Fight Mode or a WAF rule is on, add a skip rule for the collector's hostname and `/v1/report`.

```bash
curl -s https://telemetry.example.com/healthz      # {"ok": true}
```

## 5. Daily digest and retention

```bash
sudo install -m 0644 arx-collector.cron /etc/cron.d/arx-collector
docker exec arx-collector python /app/collector.py digest --dry-run    # preview
docker exec arx-collector python /app/collector.py digest              # send one now
```

The cron file sends the previous UTC day's digest at 06:17 and, once a month, deletes reports older
than 13 months.

## Verified

This kit was run end to end on a replica: a real Arx report posted over the tunnel's network was
stored with hour precision and no address; a repeated report was refused (429), a malformed one
rejected (400), and other paths answered 404. The container was healthy, ran as uid 10001 on a
read-only filesystem, and the digest arrived by SMTP with the day's reports attached.
