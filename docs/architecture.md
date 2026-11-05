# Arx: architecture

## 1. Two layers

**Fast layer (deterministic).** Sensors + rules in periodic sweeps (30 s by default), with no
model in the hot path: system state, integrity, a scan trail in the kernel (nftables) and, if
installed, auditd and Falco (eBPF). It produces normalized events.

**Slow layer (reasoning).** The Arx engine (its own LLM client, with the customer's keys) works
**outside the hot path** and **only when the fast layer finds something new**: it receives the
full dossier (findings, response applied, host context, recent history), correlates, writes up
the why in plain language and proposes the next step. It groups what's new into windows and
respects a daily budget: a quiet server spends no tokens. Telemetry reaches it marked as
untrusted data (a defense against prompt injection). It never blocks detection.

Rule: if the fast layer can decide alone and the action is reversible, it acts now; reasoning
explains and refines afterwards. It's never a requirement for containing.

It has one power, and a bounded one: with `--enforce`, its verdict on a login the fast layer
already flagged can close that account (see Tier 2). It doesn't choose who, and code validates
its answer.

## 2. Tiered response

| Tier | Examples | Authority |
|------|----------|-----------|
| **0** | log evidence and alert | automatic, always |
| **1** | block an IP, a port or a reverse shell channel; suspend a suspicious process | automatic with `--enforce`, **undoes itself after 60 min** |
| **2** | restore critical files, quarantine what was planted, lock an account and close its sessions, kill a process that came back, remove a SUID bit | **human + word** |

Tiers 0 and 1 are relentless and never tire. What's irreversible belongs to the human, with one
exception: if the model confirms an already flagged login as a threat, that account is closed
without waiting and you're told with the full context. Never on root, system accounts or the
last admin account, never without a verified live session, and no more than twice an hour. A
locked account doesn't unlock on its own: a person decides with `arx unlock`.

A new binary in a system directory is a low-confidence signal and is only logged (Tier 0):
suspending it would freeze all of its processes. A reverse shell channel is cut with a DROP in
nftables, not by destroying the socket: on expiry, the flow resumes.

## 3. Behavior baseline

**Software** (executables by real path, services), **network** (listening ports), **users**
(sessions) and **gauges** (load, memory, disk, connections). Learning comes before blocking
during the window. Boot integrity keeps an intruder from being learned as "normal". Schedules
and network flows aren't modeled yet.

## 4. Isolated tool execution (defensive), *planned*

The agent's own tools (recon, exposure checks) **don't** run with broad capabilities in the main
process: they run in **ephemeral sibling containers with minimal capabilities**, limited to
Arx's own host or segment, and are destroyed when done. Less surface, isolation and auditability.

**Core is defense only.** It includes no offensive tools of any kind.

**Authorized assessment, paid only and on your own assets only** (*planned*): Pro adds a curated
self-pentest of the host itself; Business, an assessment with Kali/Parrot tools over the
customer's enrolled fleet. Always with hard gates: scope enforced by code, human approval per
exercise, dry-run first, kill switch and audit. No packaged C2 or pivoting, and its code doesn't
live in this repository.

**Never against third parties:** no hack-back in any tier, not even against whoever is attacking
you (the attacking IP is often another victim).

## 5. Customer side vs. service side

- **On the customer's host (Core):** engine, wizard, recon, baseline, sensors, response, canaries,
  console chat. Customers bring their **own** model keys → zero inference cost, and their telemetry
  doesn't leave the machine beyond the model they choose.
- **On the service side (higher tiers):** managed intelligence, licensing and the fleet console.

## 6. Config and secrets on the host

Config and the **hash** of the authorization word: root-only, with strict permissions, immutable
after setup. The word is never stored in clear text. A secret redactor is always on: no key or
credential goes out in logs, incidents or to the model.
