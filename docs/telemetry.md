# Arx improvement program

Arx can send an anonymous usage report every few days, **only if the owner of the server says
yes**. The reports tell us which systems Arx runs on, whether its watchers work there, and how much
noise it makes, so we can fix what breaks on real servers.

Nothing is sent by default. A server whose owner never answered sends nothing.

## Joining and leaving

You are asked once:

- by the installer (`install.sh`), only when it runs in a terminal;
- in step 8 of `sudo arx setup`.

The default answer is **no**. Without a terminal (automation, pipes, cloud-init), nobody is asked
and nothing is sent.

```bash
sudo arx telemetry            # whether you joined, where reports go, when the last one left
sudo arx telemetry show       # the exact report that would be sent now, as JSON
sudo arx telemetry enable     # join
sudo arx telemetry disable    # leave: nothing else is sent, and the installation id is deleted
sudo arx telemetry send       # send one now (only if you joined)
```

Two environment variables switch it off whatever the configuration says: `ARX_TELEMETRY=off` and
`DO_NOT_TRACK=1`. Set them in the service's environment (`systemctl edit arx`) to be sure.

## What a report contains

Exactly what `arx telemetry show` prints. Every field is a number, a true/false value or a short
identifier from a fixed list:

| Field | Meaning |
|---|---|
| `schema` | report format version (1) |
| `install_id` | random 32-hex id, created when you join and deleted when you leave. It is not derived from the machine |
| `arx` | Arx version |
| `period_days` | days the report covers (the reporting interval) |
| `os`, `os_version` | distribution id and version from `/etc/os-release` (for example `ubuntu`, `24.04`) |
| `kernel` | kernel major.minor (for example `6.8`) |
| `arch` | CPU architecture (`x86_64`, `aarch64`) |
| `python` | Python major.minor |
| `systemd` | whether systemd is running |
| `lang` | output language (`en`, `es`) |
| `setup.configured` | whether `arx setup` was run |
| `setup.tier` | `core`, `pro` or `business` |
| `setup.llm_providers` | how many model providers are configured (a count; never which keys) |
| `setup.telegram`, `setup.webhook`, `setup.telegram_control` | whether those alert channels are configured (true/false) |
| `setup.mode` | `observe`, `enforce`, or `none` if the guard never ran |
| `setup.baseline_sealed` | whether the baseline is sealed |
| `setup.ip_response` | `block` or `tarpit` |
| `setup.llm_identity_actions` | whether the model may lock a flagged account |
| `watch.process`, `watch.exec_capture`, `watch.files` | mode of each watcher (`netlink`, `full`, `partial`, `degraded`, `unavailable`…) |
| `watch.exec_marks`, `watch.files_marks`, `*_marks_failed` | how many filesystems are watched, and how many could not be (counts, never which) |
| `watch.exec_captured`, `exec_dropped`, `exec_expired`, `exec_overflow`, `exec_late`, `exec_errors`, `files_overflow`, `files_late`, `files_errors`, `netlink_lost` | watcher counters |
| `watch.auditd`, `watch.osquery`, `watch.falco` | whether those sensors are available |
| `noise.days_covered`, `findings_new`, `alerts_high`, `false_positives`, `unreviewed_high`, `automatic_actions`, `accounts_locked_by_model`, `within_target` | the same numbers as `arx metrics --json` |
| `noise.high_by_kind` | high alerts per finding type (for example `new_listen_port: 2`) |
| `health.self_down`, `self_stopped`, `self_tamper`, `self_check_unavailable` | how often Arx failed, was stopped, saw its own files change, or could not check itself |
| `health.restart_state` | failures by systemd restart state (`scheduled`, `recovered`, `exhausted`…) |
| `health.alert_delivery` | per channel type, how many alerts were accepted or failed |
| `counts.*` | how many canaries, vaccines, proposals, blocks, known findings, pending Tier 2 actions, quarantined files and locked accounts exist, and whether the safety brake is tripped |

## What a report never contains

Host names, IP addresses, paths, file names, user or account names, commands, process names,
finding texts, alert texts, keys, tokens, chat ids, webhook URLs, or any part of the configuration.

This is enforced twice. Arx builds the report only from counters and fixed values, and then a final
filter drops any text that is not a short identifier, anything that looks like an IP address, and
the machine's own host name, even if a future bug tried to add one. The collector applies the same
filter again on arrival.

## How it travels and where it goes

- Only over HTTPS, to `https://telemetry.adsyslabs.com/v1/report`, a collector operated by ASL
  (Advanced Systems Laboratories), the maker of Arx.
- Requests reach the collector through Cloudflare, which provides the HTTPS front. The collector
  does not record source IP addresses, and stores the reception time rounded to the hour.
- The first report leaves one day after you join; then every 7 days. The collector can propose
  another interval between 1 and 30 days. It cannot change what is sent: that only changes with a
  new Arx version, and `arx telemetry show` always shows it.
- If a report cannot be sent, Arx tries again at most every 6 hours. It never retries in a loop, and
  sending runs apart from the defense: a slow or unreachable collector never delays it.
- Reports are used only to improve Arx. They are kept for up to 13 months.

The collector is part of this repository: [`tools/telemetry-collector`](../tools/telemetry-collector).
