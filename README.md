<h1>Arx</h1>

**Autonomous defensive security for Linux servers.** Arx learns what *normal* looks like
on your machine, notices what doesn't belong, and contains it on its own, using only
actions it can undo. Anything irreversible waits for you.

![Arx containing a port scan, an SSH brute force and a reverse shell](docs/assets/arx-demo.gif)

<sub>Real output of [`lab/demo.sh`](lab/demo.sh), with long waits shortened. Arx's CLI
currently speaks Spanish, so the captions explain each step.</sub>

> **Status:** v0.0.2, early public testing. **Arx Core is free and available now.** The paid
> tiers open after Core completes its public testing phase, **Pro first, Business last**.
> Founding pricing (half price, first 500 purchases of each plan) is reserved for that
> opening: [get notified](https://github.com/mperez90/Arx/discussions/1).
> © ASL — Advanced Systems Laboratories.

---

## Why

Classic tooling raises an alert and waits for a human, and the breach happens in the gap
between detection and response. Arx closes that gap on a single server with no SOC behind
it: it answers first, with reversible actions, and leaves the hard decisions to you.

## Try it without risk

Arx starts in **observe mode**. Without `--enforce` it blocks nothing and never touches a
process; it only reports what it would have done.

```bash
curl -fsSLO https://raw.githubusercontent.com/mperez90/Arx/f1-core-mvp/packaging/install.sh
less install.sh          # a root installer for a security tool: read it first
sudo sh install.sh       # Debian/Ubuntu; verifies the package's SHA-256

sudo arx setup           # authorization word; LLM keys and alerts are optional
sudo arx recon           # map this server
sudo arx learn           # learn what's normal; repeat over a few days
sudo arx learn --seal    # close the baseline
sudo arx guard           # watch, in observe mode (Ctrl-C to stop)
```

When you trust what it reports, switch on the automatic responses with
`sudo arx guard --enforce`, or run it 24/7 under systemd with
`sudo arx service install --enforce`. On other distros, download `arx.pyz` from
[Releases](https://github.com/mperez90/Arx/releases) and run it with Python 3.10 or newer.

**What observe mode does change on your system:** its config and state (`/etc/arx`,
`/var/lib/arx`), a backup of your critical files in its vault when you seal the baseline,
its own `inet arx` nftables table (a passive SYN tracker and empty block sets), and auditd
watch rules if auditd is installed.

## What it does against real attacks

Don't take the table's word for it. `bash lab/docker-lab.sh` runs these attacks with real
tools in two isolated, throwaway containers, and `bash lab/demo.sh` is the short version
shown above. Both only need Docker.

| Attack | Arx's response | Verified by |
|---|---|---|
| Port scan (`nmap -sS`) | Blocks the source IP | Lab |
| SSH brute force | Blocks the source IP | Lab |
| New listening port | Blocks the port | Lab |
| Dropper running from `/tmp` | Suspends the process | Lab |
| Reverse shell from `bash`, `sh`, `nc` or `socat` | Cuts the channel and suspends only that process | Lab |
| New SUID binary | Critical alert; the decision is yours | Lab |
| Persistence planted in cron | On your word: restores from the vault and quarantines the planted file | Lab |
| Decoy (canary) file read | High-severity alert | Lab |
| Authentication log truncated | High-severity alert | Unit tests |

Levels that need a real VM (weak credentials, ransomware-style destruction) have not been
run yet. The full test plan and its results are in [`lab/README.md`](lab/README.md).

## The doctrine: relentless, but reversible

| Tier | What happens | Authority |
|------|---------|-----------|
| **0** | Record evidence and alert | Automatic, always |
| **1** | Block an IP, a port or a reverse-shell channel; suspend a suspicious process | Automatic with `--enforce`; each action undoes itself after 60 minutes |
| **2** | Restore critical files, quarantine what was planted | **You**, with your authorization word |

Guardrails against self-inflicted damage:

- It never acts on your SSH port, PID 1, itself, the host's own IPs or an SSH session it has
  seen persist across checks.
- A new binary in a system directory is only logged. A new binary elsewhere can be
  suspended, and only with `--enforce`.
- After 5 automatic actions in an hour it stops acting and only observes.
- If a threat comes back after its block expires, Arx doesn't re-block in a loop. It asks you.

Losing contact with our servers doesn't disarm Arx. Licensing fails open, degrading at
worst to the free tier.

## Known limits

Read these before you rely on it.

- **It sweeps, it isn't instantaneous.** Checks run every 30 seconds by default, so a fast
  attacker has that long. Scan tracking runs in the kernel; most other checks do not.
- **Reverse shells written in Python, Perl or PHP aren't caught yet.** Those interpreters
  are common in legitimate servers, so this detection is limited to shells and `nc`/`socat`.
  A legitimate long-lived `nc` client would be flagged; mark its IP out of bounds in setup.
- **Containment expires by design.** After 60 minutes a suspended process resumes and its
  channel reopens. If the threat is still there, it is escalated to you, not re-blocked.
- **An attacker can exhaust the safety brake.** Five actions in an hour trips it on purpose
  or by accident, and from then on Arx only observes and alerts.
- **Blocks need a firewall tool.** Without `ufw` or `nftables` it reports that it can't
  block, and cutting a reverse-shell channel requires `nftables` specifically.
- **False-positive rates on real servers haven't been measured.** That's what this testing
  phase is for, and why observe mode comes first.
- **Linux only, and the CLI is in Spanish for now.** The package targets Debian and Ubuntu.

## How it's built

Two layers, on purpose. A **fast, deterministic** layer of sensors and rules contains
threats, with no network and no model involved. An optional **slow** layer, a model using
**your own API keys**, reads new findings and explains them. It's off the hot path, receives
telemetry marked as untrusted with secrets redacted, and can't execute anything. Everything
in the table above works without any API key.

Python standard library only, no pip dependencies. It uses osquery, auditd and Falco if you
already have them, and falls back to `/proc` if you don't. The lifecycle is four words:

```
setup  →  recon  →  learn  →  guard
```

## Removing it

```bash
sudo arx canaries list       # note any decoys you planted, then delete them
sudo arx service uninstall
sudo apt remove arx
sudo nft delete table inet arx
sudo rm -rf /etc/arx /var/lib/arx    # also deletes its evidence and vault
```

Its auditd watch rules, if any, disappear on reboot.

## Editions

| Edition | For | Availability |
|---------|-----|--------------|
| **Core** | The full defense above, on your own servers | **Free, available now** |
| **Pro** | Managed threat intelligence, advanced detections, curated self-testing of your own host | Planned, after Core's testing phase |
| **Business** | Fleet console, hosts that defend each other, compliance reports, authorized assessment of your own fleet | Planned, after Pro |

**Core is defensive only. Paid tiers add authorized assessment of your own assets, with
scope enforced in code and human approval per exercise.** Arx never attacks third parties.
That rules out hack-back, including against whoever is attacking you.

## License

Core is **source-available, not open source**: it's licensed under the Business Source
License 1.1, and you may use, modify and self-host it to defend systems you own or operate,
including inside a business, free of charge. Each version becomes Apache 2.0 four years
after its release. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Core stays free. If it defended your machine, you can fuel the roadmap with the **Sponsor**
button (pay what you want, one-time or monthly).

---

*Arx — the citadel keeps itself.*
