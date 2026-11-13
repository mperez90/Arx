# Arx Core manual

Version 0.0.9rc2 · [Versión en español](manual.es.md) · `man arx` once installed

Arx is used from the terminal. It has no web interface, on purpose: an agent that defends a server
should not add another login page to it. This manual walks through every command, in the order you
will meet them, and ends with a reference you can come back to.

## Contents

1. [Before you start](#1-before-you-start)
2. [Installing](#2-installing)
3. [The terminal](#3-the-terminal)
4. [First run: setup, recon, learn, guard](#4-first-run-setup-recon-learn-guard)
5. [Running 24/7 with systemd](#5-running-247-with-systemd)
6. [Day to day](#6-day-to-day)
7. [When an alert arrives](#7-when-an-alert-arrives)
8. [Alerts and control from your phone](#8-alerts-and-control-from-your-phone)
9. [How Arx responds](#9-how-arx-responds)
10. [Tools: canaries, scan, forensics, vaccines, proposals, metrics](#10-tools)
11. [The improvement program](#11-the-improvement-program)
12. [Licenses and editions](#12-licenses-and-editions)
13. [Upgrading and removing](#13-upgrading-and-removing)
14. [Files and environment variables](#14-files-and-environment-variables)
15. [Troubleshooting](#15-troubleshooting)
16. [Command reference](#16-command-reference)

---

## 1. Before you start

**What you need**

| | |
|---|---|
| System | Debian or Ubuntu (tested on Ubuntu 22.04 and 24.04 and Debian 13). Other Linux distributions can run `arx.pyz`, without proof of origin for software |
| Python | 3.10 or newer (standard library only, nothing from pip) |
| Privileges | root. Arx blocks IPs, freezes processes and restores files, which needs root. Without it, commands work on a private copy in `~/.arx` and protect nothing |
| systemd | needed to run 24/7, to confine programs and to report Arx's own failures |
| nftables | recommended (installed with the package unless you skip recommended packages). Blocks and cutting reverse shells use it |
| auditd | installed automatically with the package. Identity-file, canary and denied-read alerts come from it |
| cgroup v2 | needed to confine a program without network. Without it Arx suspends instead |

**Conventions in this manual**

- Commands are shown with `sudo`. If you are already root, drop it.
- `<id>` is a value you replace: a finding id, an account, a path.
- Output shown here is in English. Arx also speaks Spanish (see [3.2](#32-language)).

**Observe first.** Arx starts in observe mode: it reports what it would have done and changes
nothing outside its own files. Switch to protect mode (`--enforce`) once you trust what it reports.

---

## 2. Installing

### 2.1 With the installer (recommended)

```bash
curl -fsSLO https://raw.githubusercontent.com/mperez90/Arx/f1-core-mvp/packaging/install.sh
less install.sh          # a root installer for a security tool: read it first
sudo sh install.sh
```

The installer:

1. checks that it runs as root on a system with `dpkg`;
2. downloads the latest release's `arx_all.deb` and its `SHA256SUMS`, and refuses to install if
   the checksum does not match;
3. installs the package and lets `apt` bring its dependencies (`python3`, `auditd`, and `nftables`
   as a recommendation);
4. makes sure `auditd` is running, or tells you why it is not (inside a container the kernel does
   not let it start);
5. asks once whether you want to join the [improvement program](#11-the-improvement-program). The
   default is no, and without a terminal it does not ask;
6. prints the next steps.

Installer variables:

| Variable | Use |
|---|---|
| `ARX_DEB_URL` | download the package from another URL (its `SHA256SUMS` must sit next to it) |
| `ARX_DEB_PATH` | install a local `.deb` (offline or testing). Skips the download and the checksum |

### 2.2 With the package

```bash
sudo apt install ./arx_all.deb
```

`apt` resolves the dependencies. With `dpkg -i`, run `sudo apt-get install -f` afterwards.

### 2.3 Without a package (other distributions)

Download `arx.pyz` from [Releases](https://github.com/mperez90/Arx/releases) and run it:

```bash
sudo python3 arx.pyz --version
sudo python3 arx.pyz setup
```

Every command in this manual works the same way with `python3 arx.pyz` in place of `arx`.
Without dpkg nothing counts as proven, so every new program is contained under `--enforce`.

### 2.4 Verifying the release

Each release carries signed build provenance:

```bash
gh attestation verify arx.pyz -R mperez90/Arx
gh attestation verify arx_all.deb -R mperez90/Arx
```

### 2.5 What gets installed

| Path | What |
|---|---|
| `/usr/bin/arx` | the command |
| `/usr/lib/arx/arx.pyz` | the program (a Python zip application) |
| `/usr/share/man/man1/arx.1.gz` | `man arx` |
| `/etc/arx/` | configuration and secrets, created by `arx setup` (root only) |
| `/var/lib/arx/` | state: baseline, incidents, vault, quarantine, reports (root only) |

Installing changes nothing else until you run `arx setup` and seal a baseline.

---

## 3. The terminal

### 3.1 Colors

When Arx writes to a terminal it colors three things, so you can scan its output quickly:

| Color | What | Example |
|---|---|---|
| **blue** | user and account names | `account 'deploy' locked` |
| **yellow** | commands you can run | `Accept one with:  arx accept <id>` |
| **green** | paths | `opened /etc/shadow` |

Colors exist only in Arx's own output, only on a terminal. Arx does not touch your shell's
configuration or prompt. When output goes to a pipe, a file or the journal, and in Telegram messages
and webhooks, the text is plain.

| Setting | Effect |
|---|---|
| `NO_COLOR=1` | no colors ([no-color.org](https://no-color.org)) |
| `ARX_COLOR=never` | no colors |
| `ARX_COLOR=always` | colors even through a pipe (for example `ARX_COLOR=always arx status \| less -R`) |
| `TERM=dumb` | no colors |

A command is colored only as far as it really goes: in "run `arx learn` several times", only
`arx learn` is yellow. A user is colored when the context is unambiguous ("account 'x'",
"user: x", "uid=0(root)"), or after "as" or "by" only if the account exists on this host.

### 3.2 Language

Arx speaks English and Spanish. The language is chosen in this order:

1. `ARX_LANG` (`en` or `es`);
2. the language chosen in `arx setup` (saved in the configuration, so the service uses it too);
3. the system locale (`LC_ALL`, `LC_MESSAGES`, `LANG`);
4. English.

```bash
ARX_LANG=es arx status
```

Telegram commands work in both languages whatever the output language (`/status` or `/estado`).

### 3.3 The Arx console: `arx shell`

`arx shell` opens an interactive console for Arx:

```
$ sudo arx shell
Arx 0.0.9rc2 console · «help» lists the commands · «exit» or Ctrl+D to leave
root@web01:/etc arx› status
…
root@web01:/etc arx› accept
…
root@web01:/etc arx› exit
```

- In the prompt, `user@host` is blue, the current directory is green, and what you type is yellow.
  Command output uses the same colors as everywhere else. When you leave, your terminal is exactly
  as it was. (With macOS's libedit the prompt itself stays plain; Linux servers use GNU readline.)
- Type Arx commands without the `arx` in front (`status`, `accept <id>`). Typing it is also fine.
- **Tab** completes commands, actions (`license a` → `activate`), options (`metrics --` →
  `--days`, `--json`) and paths (after `cd`, `scan`, or anything starting with `/`, `~` or `.`).
- History is kept in `~/.arx_history` (mode 0600, 1000 lines). Up and down arrows browse it.
- A mistake, a `--help` or a crash in a command never closes the console. Ctrl+C stops the running
  command (for example `guard`) and returns to the prompt.

Console commands:

| Command | What |
|---|---|
| `help` or `?` | list Arx commands with a one-line description |
| `cd <dir>` | change directory (useful before `scan` with relative paths) |
| `pwd` | print the current directory |
| `history` | show the history |
| `clear` | clear the screen |
| `exit`, `quit`, Ctrl+D | leave |

Without a terminal the console reads commands from its input, one per line, with no prompt and no
colors. Lines starting with `#` are ignored:

```bash
printf 'status\nmetrics --json\n' | sudo arx shell
```

### 3.4 Help

```bash
arx --help              # every command
arx <command> --help    # the options of one command
man arx                 # the reference page
arx --version
```

---

## 4. First run: setup, recon, learn, guard

Arx's life cycle is four steps:

```
setup  →  recon  →  learn  →  guard
```

### 4.1 `arx setup`: configuration

```bash
sudo arx setup
```

The wizard first asks for the language (`en`/`es`), then goes through eight steps. Enter keeps the
value in brackets:

1. **Model providers** (optional). API keys for OpenAI, Anthropic and Kimi, and the model for each.
   Keys are typed without echo and saved in `/etc/arx/secrets.json` (0600). The order is the
   fallback order. Without any provider, Arx defends exactly the same; decisions that would use the
   model wait for you instead.
2. **Authorization word** (required). It protects every irreversible action (Tier 2). It is asked
   twice and only its scrypt hash is stored. Arx never shows it, and it never travels through a
   chat. If you lose it, run `arx setup` again.
3. **Scope.** What Arx defends, and what it must never touch: ports, paths, processes or accounts,
   comma-separated. Your SSH port is always protected.
4. **Learning and engine.** The baseline window in days (7 by default) and the maximum model queries
   per day (48). The model is consulted only when something new appears.
5. **License** (`core`, `pro`, `business`). Core is free and needs no key. See
   [12](#12-licenses-and-editions).
6. **Alerts** (optional). A Telegram bot token, your chat id, whether to control Arx from that chat
   (with an authenticator app), a webhook URL, and from which severity to alert (`crit`, `high`,
   `med`). See [8](#8-alerts-and-control-from-your-phone).
7. **Automatic response.** On a port scan: `block` cuts the IP, `tarpit` throttles it (better if
   the IP may be shared). With a model configured: whether it may lock an account it confirms as a
   threat (see [9.2](#92-the-one-exception)).
8. **Improvement program** (optional, default no). See [11](#11-the-improvement-program).

When the input is not a terminal and runs out, the remaining questions take their defaults. That
lets you script it.

Show the current configuration, with secrets redacted:

```bash
sudo arx setup --show
```

Model keys can also come from the environment instead of the file: `ARX_OPENAI_API_KEY`,
`ARX_ANTHROPIC_API_KEY`, `ARX_KIMI_API_KEY`.

### 4.2 `arx recon`: map the server

```bash
sudo arx recon
```

A deep, read-only look at the host: hardware, operating system, packages, services and listening
ports, users, sudo, SUID binaries, cron, containers, network and scope. It prints the attack
surface and a defense plan tailored to the host, and saves the inventory as JSON in
`/var/lib/arx/`.

| Option | Effect |
|---|---|
| `--json <path>` | save the inventory somewhere else |
| `--no-save` | only print, write nothing |

### 4.3 `arx learn`: learn what is normal

```bash
sudo arx learn            # one snapshot
sudo arx learn --status   # what has been learned so far
sudo arx learn --seal     # close the baseline
```

Each run takes a snapshot of the host's behavior and merges it into the baseline:

- **sets**: executables by real path, listening ports, services, logged-in users;
- **gauges**: load, memory, disk, connections (minimum, maximum, mean).

Repeat it at different times over a few days (the window from setup, 7 days by default) so the
baseline sees backups, cron jobs and peak hours. To take several snapshots in one run:

```bash
sudo arx learn --samples 12 --interval 300    # 12 snapshots, 5 minutes apart
```

**Boot integrity.** The first snapshot fingerprints critical files (`authorized_keys`, `sudoers`,
`passwd`, cron, systemd units, `ld.so.preload`, the set of SUID binaries). If they change while
Arx is learning, it tells you, so it does not learn an intruder as normal.

**Sealing** (`--seal`) ends learning. It also:

- backs up the critical files into Arx's vault, so they can be restored later;
- loads Arx's `inet arx` nftables table with a passive scan tracker and empty block sets;
- records the SUID binaries present.

A sealed baseline is what `arx guard` compares against. You can learn again and seal again at any
time; `arx accept` adds single changes without relearning.

### 4.4 `arx guard`: on guard

```bash
sudo arx guard               # observe mode, every 30 seconds, until Ctrl+C
sudo arx guard --enforce     # protect mode: automatic Tier 1 actions
```

| Option | Effect |
|---|---|
| `--enforce` | apply automatic, reversible Tier 1 actions. Without it, Arx only reports |
| `--interval <s>` | seconds between sweeps (30 by default) |
| `--once` | one sweep and exit (for cron or tests) |
| `--verbose` | print every finding on every sweep, not only new ones |
| `--chat` | talk to the configured model from the console (`exit` to leave). It cannot act |

On start it prints its tier, active sensors, mode and alert channels. Then:

- each sweep compares the host with the sealed baseline and runs the sensors;
- as root, processes are watched in real time through the kernel (each `exec`), and sensitive
  files through fanotify;
- new findings are printed with what Arx did. Tier 2 actions wait for your word;
- with a model configured, new findings are explained in plain language.

`arx guard` in a terminal is good for trying Arx. To leave it running, use systemd.

---

## 5. Running 24/7 with systemd

```bash
sudo arx service install              # observe mode
sudo arx service install --enforce    # protect mode
sudo arx service status
sudo arx service uninstall
```

`install` writes and starts:

| Unit | What |
|---|---|
| `arx.service` | the guardian (`arx guard`), hardened, restarted on failure |
| `arx-firewall.service` | puts Arx's containment back in the kernel early at boot (`arx service restore`) |
| `arx-down.service` | reports Arx's real restart state when it fails |
| `arx-revive.timer` | every 15 minutes, starts Arx again if it is down after a failure |
| `arx-maintenance.slice` | apt and dpkg checks run here, outside the guardian's memory |

Without systemd or root, `install` does not pretend: it writes the unit to the state directory and
prints the exact commands to install it.

To switch between observe and protect mode, install again with or without `--enforce`, or use
`/mode` from Telegram.

Useful commands:

```bash
systemctl status arx
journalctl -u arx -f                  # live output of the guardian
journalctl -u arx --since today
```

If someone stops Arx, or edits its unit or its files, you are told through your alert channels.

The other `service` actions (`restore`, `stopped`, `down`, `refresh-maintenance`) are run by systemd
and the package. You do not need to run them by hand.

---

## 6. Day to day

### 6.1 `arx status`

```bash
sudo arx status
sudo arx status --json     # the same, for scripts
```

```
▸ Arx: status
  configured     yes
  providers      anthropic
  auth word      configured
  baseline       sealed (14 samples)
  license        core  (no license (Core))
  service        active
  canaries       5 active, 0 triggered
  T1 blocks      1 active
  mode           protect (--enforce)
  process watch  netlink · exec identity: full
  capture stats  1520 captured · 0 dropped · 0 overflow(s)
  sensitive files full
  alerts         telegram
  vaccines       0 applied
  improvement    not joined (arx telemetry)
  observation    2 services being learned · 9 watched
  findings       12 known  ·  accept legitimate changes: arx accept
  Tier 2 pending 0
  recent incidents:
    …
```

| Line | Meaning |
|---|---|
| `configured`, `providers`, `auth word` | whether setup ran, which model providers, whether the word exists |
| `baseline` | `learning` or `sealed`, and the number of snapshots |
| `license` | effective tier and why |
| `service` | systemd state of `arx.service` |
| `canaries` | decoys planted and triggered |
| `T1 blocks` | automatic blocks in force. `⚠ SAFETY BRAKE active` means Arx stopped acting automatically for now (see [9.3](#93-guardrails)) |
| `mode` | `observe`, `protect (--enforce)`, or `has not run yet` |
| `process watch`, `capture stats` | the kernel process watcher and short-lived process capture. `dropped` or `overflow` above 0 mean events were lost |
| `sensitive files` | the fanotify watch on shadow, keys and credentials: `full`, `partial`, `degraded` or `unavailable` |
| `alerts` | configured channels |
| `improvement` | whether this server joined the improvement program |
| `observation` | services whose behavior is being learned, and services already watched |
| `findings` | known findings; `arx accept` lists the ones you can accept |
| `Tier 2 pending` | actions waiting for your word (`arx authorize`) |
| `locked accts` | accounts Arx locked (`arx unlock`) |
| `recent incidents` | the last five |

### 6.2 `arx accept`: "this is normal"

```bash
sudo arx accept                # findings you can accept
sudo arx accept <id>           # accept one
```

Accepting adds the change to the baseline, stops flagging it and lifts what contained it right away
(a confined program gets its network back, a blocked port reopens). It is what you run after you
install something on purpose.

For a program that a service started:

| Option | Accepts |
|---|---|
| (none) | that exact program for that service |
| `--dir` | its whole directory for that service |
| `--children` | that program and what it starts |

An updated package that "cannot be trusted" is accepted for that exact version only.

### 6.3 `arx authorize`: Tier 2 actions

```bash
sudo arx authorize             # pending actions, with what each will do
sudo arx authorize <id>        # asks for your authorization word, then acts
```

Tier 2 actions are the ones that cannot simply undo themselves: restore a critical file from the
vault, quarantine a planted file, lock an account and close its sessions, end a process that came
back, remove a SUID bit. Arx proposes them; only you, with your word, carry them out. A wrong word
changes nothing.

### 6.4 `arx unblock`: lift a block early

```bash
sudo arx unblock               # temporary blocks in force and when they expire
sudo arx unblock <ip|id>       # lift one now (asks for your word)
```

Tier 1 blocks lift on their own after 60 minutes. Use this for a false positive you do not want to
wait for. To stop it coming back, `arx accept <id>`.

### 6.5 `arx unlock`: locked accounts

```bash
sudo arx unlock                # accounts Arx locked, since when and why
sudo arx unlock <account>      # unlock (asks for your word)
```

A locked account has password and SSH-key access closed. It never unlocks on its own. Unlocking
restores its previous state. Closed sessions cannot be reopened. If the login was legitimate, run
`arx accept` afterwards so it is not flagged again.

### 6.6 `arx restore`: quarantine

```bash
sudo arx restore               # quarantined files, origin, date and hash
sudo arx restore <id>          # put one back (asks for your word)
```

Quarantined files are kept as evidence (0600, root only) in `/var/lib/arx/vault/`.

---

## 7. When an alert arrives

Every alert names a finding id. The full guide is [docs/runbook.md](runbook.md). In short:

1. **Keep the evidence first:** `sudo arx forensics`.
2. **See what Arx did:** `sudo arx status`.
3. **Decide:**

| The alert says | Arx already | You decide |
|---|---|---|
| A new program, port or service that can't prove where it came from | Confined it or blocked the port; it keeps running | Yours: `sudo arx accept <id>`. Not yours: stop and remove it |
| An update "cannot be trusted" | Confined the service; it keeps serving | Legitimate: `sudo arx accept <id>`. Otherwise roll the package back |
| A service "tried to reach … outside its usual behavior" | Cut that connection | New legitimate destination: `sudo arx accept <id>` |
| A service "started …, which it never ran" | Isolated that process without network | Expected: `sudo arx accept <id>` |
| sshd "before authenticating anyone, ran …" | Froze and isolated that process | Treat it as a compromise. Only if you configured that command: `sudo arx accept <id>` |
| A web server or database "started a shell" | Froze that process | Look for a webshell, then `sudo arx accept <id>` |
| Login from an unknown origin | Closed that account (on your word or the model's) | `sudo arx unlock <account>` only once you know it was legitimate |
| Planted cron job, SUID bit, second root account, changed critical file | Alerted and asked for your word | `sudo arx authorize <id>`, or `sudo arx accept <id>` if it was you |
| A denied attempt to open a sensitive file | Alerted (from auditd), with user, program and process | Find out why that service tried |
| A canary was read or changed | High-severity alert, with the program if auditd saw it | Treat it as an intruder |
| Arx stopped, or its unit or files changed | Told you through your channels | If it was not you, assume someone with root: work from another machine |

---

## 8. Alerts and control from your phone

### 8.1 Channels

Configured in step 6 of `arx setup`:

- **Telegram**: create a bot just for Arx with @BotFather (`/newbot`), paste its token, then send
  the bot any message: Arx detects your chat id. Only that chat can talk to Arx.
- **Webhook**: Arx POSTs JSON `{"source": "arx", "host": "<host>", "text": "<alert>"}` to the URL
  (Slack, Discord, n8n…).

Alerts are sent from the severity you chose (`high` by default). Secrets are redacted from every
message. Arx only makes outbound connections and opens no port.

```bash
sudo arx notify test           # sends a test message through every channel
```

`ok` means the channel accepted the message, not that someone read it. Once a day Arx also sends a
summary of what is waiting for your decision and how much noise it made. To turn that summary off,
set `"daily_report": false` inside `"notify"` in `/etc/arx/config.json`.

### 8.2 Telegram commands

| Command | What |
|---|---|
| `/status` (`/estado`) | status |
| `/findings` (`/hallazgos`) | recent findings |
| `/pending` (`/pendientes`) | Tier 2 actions waiting |
| `/report` (`/informe`) | the last 7 days: alerts, false positives, automatic actions, containment, quarantine |
| `/mute <hours>` (`/callar`) | silence non-critical alerts |
| `/authorize <id> <code>` (`/autorizar`) | authorize a Tier 2 action |
| `/unlock <account> <code>` (`/desbloquear`) | unlock an account |
| `/accept <id> <code>` (`/aceptar`) | accept a finding |
| `/mode observe\|protect <code>` (`/modo observar\|proteger`) | switch mode |
| `/help` (`/ayuda`) | the list |

`<code>` is the 6-digit one-time code from your authenticator app (Google Authenticator, Aegis,
1Password…). The key is shown once in `arx setup` when you enable chat control. Your authorization
word never travels through the chat. Any other text goes to the model, if there is one; the model
cannot act.

---

## 9. How Arx responds

### 9.1 Tiers

| Tier | What happens | Authority |
|---|---|---|
| **0** | Record evidence and alert | Automatic, always |
| **1** | Block an IP, a port or a reverse-shell channel; suspend a suspicious process; confine a program of unproven origin | Automatic with `--enforce`. Each action undoes itself after 60 minutes, except confinement, which waits for you |
| **2** | Restore critical files, quarantine what was planted, lock an account and close its sessions, end a process that came back, remove a SUID bit | You, with your authorization word |

New software is judged by proof, not by its path. A program from a package in a signed repository,
intact, is only logged. One that cannot prove it is confined: it keeps running, without network.
Only signs of harm suspend it: a temporary or hidden path, a static-analysis hit, being started by a
web server, or coming from an unknown login.

### 9.2 The one exception

With a model configured and `--enforce`, if the model confirms as a threat, or as a serious
suspicion (70% or more), a login the rules already flagged, Arx closes that account's access without
waiting and tells you with the full context. The model cannot choose who: its verdict counts only on
a login already flagged in the same batch, and code validates the rest. It never applies to root,
system accounts or the last account that can administer the host, without a live session Arx can
verify, or more than twice an hour. Turn it off in `arx setup`.

### 9.3 Guardrails

- Arx never acts on your SSH port, PID 1, itself, the host's own IPs, or an authenticated SSH
  session it has seen persist.
- After 5 automatic actions in an hour it stops acting and only observes (the safety brake).
  Critical findings keep a small reserve.
- An account cannot be locked if that would leave nobody able to administer the server.
- A threat that returns after its block expires is escalated to you, not re-blocked in a loop.
- Losing contact with our servers never disarms Arx: licensing fails open, at worst to Core.

---

## 10. Tools

### 10.1 `arx canaries`: decoys

```bash
sudo arx canaries plant                          # in each user's home and /root
sudo arx canaries plant --in /srv/data --in /opt/app
sudo arx canaries list
sudo arx canaries check                          # check them now
```

Decoys are files an intruder would want to open (`.aws_credentials`, `id_rsa_backup`, `db_dump.sql`,
`.env.prod`, `wallet.dat`), believable and inert, each with a unique token. Nobody legitimate opens
them, so any access is a strong signal. With auditd, the alert names the program that opened it;
without it, reads are noticed through access times. Decoys are also how Arx notices ransomware.

### 10.2 `arx scan`: is this file malicious?

```bash
sudo arx scan /tmp/suspicious.sh
```

Static analysis only: the file is never run. Arx looks at its type, hash, size, entropy, strings and
its own rules, and answers `clean`, `suspicious` or `malicious` with the rules that matched. Exit
code 0 means clean. "Clean" only means no rule matched. On large files it reads the start and the
end, and says so.

### 10.3 `arx forensics`: sealed report

```bash
sudo arx forensics                               # full report, saved and sealed
sudo arx forensics --since 2026-11-20T00:00:00   # only incidents since then (UTC)
sudo arx forensics --verify /var/lib/arx/forensics/forensic-<id>.json
sudo arx forensics --indicators                  # only public IPs, hashes and attack types
```

The report gathers the timeline of incidents, active containment, pending actions, quarantined
evidence and host context, and is saved in `/var/lib/arx/forensics/`. It is sealed with a hash chain
and an HMAC with a key local to the host, so later edits are detected. `--indicators` contains
nothing about your host and is safe to share. The seal does not cover edits made to the log before
the report, and root on the same host can re-sign one.

### 10.4 `arx vaccines`

```bash
sudo arx vaccines              # applied and rejected
sudo arx vaccines update       # check now
sudo arx vaccines remove <id>
```

Signed updates with what other Arx hosts learned. Each one is validated on your host before it
applies, and in Core a vaccine is data, never code. The channel is not open yet.

### 10.5 `arx proposals`

```bash
sudo arx proposals                 # what Arx suggests
sudo arx proposals apply <id>      # asks for your word
sudo arx proposals revert <id>     # undo an applied one
```

Two kinds: normalizing what has been seen for days without anyone objecting (never high severity),
and closing what an attack showed was open (today, SSH settings). Nothing applies on its own, and an
SSH change is never offered if it could lock you out.

### 10.6 `arx metrics`: how much noise

```bash
sudo arx metrics
sudo arx metrics --days 30
sudo arx metrics --json        # numbers only, no paths, names or IPs: safe to share
```

The target is fewer than 0.1 high false positives per host per day. An alert counts as a false
positive only when you mark it (`arx accept`, `arx unlock`). What nobody reviewed is shown as
"unreviewed".

---

## 11. The improvement program

Arx can send an anonymous usage report every few days, **only if you say yes**. Nothing is sent by
default.

```bash
sudo arx telemetry             # whether you joined and when the last report left
sudo arx telemetry show        # exactly what would be sent, as JSON
sudo arx telemetry enable      # join
sudo arx telemetry disable     # leave and delete the installation id
sudo arx telemetry send        # send one now (only if you joined)
```

You are asked once by the installer (only in a terminal) and in step 8 of `arx setup`. A report
holds numbers and fixed values: Arx version, distribution, kernel, architecture, mode, watcher health
and noise counters. Never host names, IPs, paths, users, commands, finding texts or secrets. The
installation id is random, and it is deleted when you leave. `ARX_TELEMETRY=off` or `DO_NOT_TRACK=1`
switch it off whatever the configuration says.

The full list of fields, and where reports go: [docs/telemetry.md](telemetry.md).

---

## 12. Licenses and editions

Core is free and needs no key. Pro and Business open after Core's testing phase.

```bash
sudo arx license status                # tier, key (redacted), expiry, last check
sudo arx license activate <KEY>        # activate a Pro/Business key on this server
sudo arx license deactivate            # release the activation (before reinstalling the server)
```

The license is checked again every 24 hours. Without a connection Arx keeps its tier for a while
and, at worst, falls back to Core: the defense never stops.

**Fleet (Business):**

```bash
sudo arx fleet enroll --console <URL> --token <TOKEN>
sudo arx fleet status
sudo arx fleet sync            # heartbeat and incidents now
```

---

## 13. Upgrading and removing

### 13.1 Upgrading

```bash
sudo apt install ./arx_all.deb     # or run install.sh again
```

The new package stops Arx before replacing its files and starts it again afterwards, only if it was
running. If the start fails, the package stays half-configured; fix the cause and run
`sudo dpkg --configure -a`. If the stop fails, the upgrade is aborted and the old version keeps
running.

### 13.2 Removing

Before removing:

```bash
sudo arx canaries list       # note the decoys you planted, then delete them
sudo arx unlock              # unlock any account you left locked
sudo arx proposals           # undo any applied change: arx proposals revert <id>
```

Then:

```bash
sudo apt remove arx          # removes the program, keeps /etc/arx and /var/lib/arx
sudo apt purge arx           # also deletes the configuration and state (evidence and vault)
```

Removing gives the network back to everything Arx confined and takes its units, drop-ins and
nftables table with it. Its auditd rules disappear on reboot. auditd itself stays installed; remove
it with `sudo apt autoremove` if nothing else needs it.

---

## 14. Files and environment variables

### 14.1 Files

| Path | What |
|---|---|
| `/etc/arx/config.json` | configuration (0600) |
| `/etc/arx/secrets.json` | model keys, bot token, local keys (0600) |
| `/var/lib/arx/baseline.json` | the baseline |
| `/var/lib/arx/incidents.jsonl` | every incident, one JSON per line |
| `/var/lib/arx/findings.json` | known findings and their ids |
| `/var/lib/arx/watch.json` | watcher state, as `arx status` shows it |
| `/var/lib/arx/forensics/` | sealed reports |
| `/var/lib/arx/vault/` | backups of critical files and quarantined evidence |
| `/var/lib/arx/telemetry.json` | improvement program state (only after you join) |
| `/var/lib/arx/audit-tail.json` | where Arx is reading the auditd log |
| `~/.arx_history` | `arx shell` history |
| `/etc/systemd/system/arx*.service`, `arx-revive.timer`, `arx-maintenance.slice` | the units |

Without root, configuration and state go to `~/.arx/` and `~/.arx/state/`.

### 14.2 Environment variables

| Variable | Effect |
|---|---|
| `ARX_LANG` | output language (`en`, `es`) |
| `ARX_COLOR` | `always` or `never` (default: colors only on a terminal) |
| `NO_COLOR` | no colors |
| `ARX_TELEMETRY` | `off` switches the improvement program off |
| `DO_NOT_TRACK` | `1` switches the improvement program off |
| `ARX_OPENAI_API_KEY`, `ARX_ANTHROPIC_API_KEY`, `ARX_KIMI_API_KEY` | model keys without writing them to disk |
| `ARX_CONFIG_DIR`, `ARX_STATE_DIR` | other configuration and state directories |
| `ARX_DEB_URL`, `ARX_DEB_PATH` | installer only (see [2.1](#21-with-the-installer-recommended)) |

---

## 15. Troubleshooting

**`arx status` says "configured no" but I ran setup.** You ran it without `sudo`. Without root the
configuration goes to `~/.arx`. Run `sudo arx setup` again.

**The service does not start.** `journalctl -u arx -n 50` shows why. "No sealed baseline" means
running `sudo arx learn` and `sudo arx learn --seal` first.

**No alerts arrive.** `sudo arx notify test`. If Telegram says `ok` but nothing arrives, check the
chat id in `sudo arx setup --show`. Below the severity you chose, findings are not sent.

**"auditd is installed but not running".** In a container the kernel does not let it start. On a
machine: `systemctl status auditd`. Without it, identity-file, canary and denied-read alerts stay
off; everything else works.

**`sensitive files partial` or `degraded` in `arx status`.** Some filesystems could not be watched,
or the kernel does not offer fanotify permission events (some container kernels). Arx says so
instead of claiming coverage it does not have.

**My own app in `/opt` lost its network.** It cannot prove where it came from, so `--enforce`
confined it. It keeps running. `sudo arx accept <id>` gives it back its network.

**Something is blocked and I don't want to wait 60 minutes.** `sudo arx unblock <ip|id>`, then
`sudo arx accept <id>` so it is not blocked again.

**`⚠ SAFETY BRAKE active`.** Five automatic actions in an hour. Arx only alerts for now. Review
`sudo arx status` and the incidents; it re-arms by itself.

**I see no colors.** Output is not a terminal, or `NO_COLOR`/`ARX_COLOR=never` is set, or
`TERM=dumb`. Force them with `ARX_COLOR=always`.

**Colors look wrong in my terminal theme.** Arx uses the terminal's own blue, yellow and green, so
your theme decides the exact shade. Turn them off with `NO_COLOR=1`.

**Only `ufw`, no nftables.** Blocks then do not cut connections already open, and cutting a reverse
shell needs nftables: `sudo apt install nftables`.

**Arx inside a container.** Run it on the host. Inside a container that shares the host's cgroup
tree, behavior watching does not work. LXC containers work like a machine.

**I lost my authorization word.** Run `sudo arx setup` again and set a new one.

---

## 16. Command reference

| Command | Options | What |
|---|---|---|
| `arx setup` | `--show` | configuration wizard; `--show` prints it with secrets redacted |
| `arx recon` | `--json <path>`, `--no-save` | map the server |
| `arx learn` | `--samples <n>`, `--interval <s>`, `--seal`, `--status` | learn the baseline |
| `arx guard` | `--enforce`, `--interval <s>`, `--once`, `--verbose`, `--chat` | watch, detect, respond |
| `arx service` | `install [--enforce] [--exec <path>]`, `uninstall`, `status` | run 24/7 with systemd |
| `arx status` | `--json` | how things stand |
| `arx accept` | `[<id>] [--dir \| --children]` | accept a legitimate change |
| `arx authorize` | `[<id>]` | approve a Tier 2 action (word) |
| `arx unblock` | `[<ip\|id>]` | lift a block early (word) |
| `arx unlock` | `[<account>]` | unlock an account (word) |
| `arx restore` | `[<id>]` | put a quarantined file back (word) |
| `arx canaries` | `plant [--in <dir>]…`, `list`, `check` | decoys |
| `arx scan` | `<path>` | static analysis, never runs the file |
| `arx forensics` | `--since <iso>`, `--verify <path>`, `--indicators` | sealed report |
| `arx vaccines` | `list`, `update`, `remove <id>` | signed vaccines |
| `arx proposals` | `list`, `apply <id>`, `revert <id>` | what Arx suggests (word) |
| `arx metrics` | `--days <n>`, `--json` | noise on this host |
| `arx notify` | `test` | test the alert channels |
| `arx telemetry` | `status`, `show`, `enable`, `disable`, `send` | improvement program |
| `arx license` | `activate <KEY>`, `status`, `deactivate` | license |
| `arx fleet` | `enroll --console <URL> --token <TOKEN>`, `status`, `sync` | fleet console (Business) |
| `arx shell` | | interactive console |

**Exit codes.** 0 when the command did what was asked; 1 when it could not, or the answer is
negative (a wrong word, a file that is not clean, nothing sent); 2 for a usage error.
