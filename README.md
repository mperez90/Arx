<h1>Arx</h1>

**Autonomous defensive security for servers.** Arx lives on your machine, learns what
*normal* looks like, and answers threats in real time — relentless on what can be undone,
and never touching the irreversible without you.

> **Status:** v0.0.1 · **Arx Core is free and available now.** The paid tiers open after
> Core completes its public testing phase — **Pro first, Business last**. Founding pricing
> (half price, first 500 purchases of each plan) is reserved for that opening.
> © ASL — Advanced Systems Laboratories.

---

## The problem

Every internet-facing server is under constant, automated attack. The defenders are
outnumbered and asleep at 3 a.m. Classic tooling *raises an alert* — then waits for a
human. Mean time to respond is measured in hours or days; alerts pile up faster than
anyone can read them; the breach happens in the gap between **detection** and **response**.

## What Arx does

Arx closes that gap. It's a single, self-installing agent that:

- **Maps your server** on day one — hardware, OS, services, users, exposure — and builds
  a defense plan specific to *this* machine.
- **Learns your normal** — a behavioral baseline of the whole system (software, hardware,
  network, users, rhythms), so it recognizes what doesn't belong.
- **Watches and answers 24/7** — fusing real-time system sensors with a model that reasons
  about what it sees, and responds by tiers.

## The doctrine: relentless, but reversible

Arx acts with *steel will* — but only where actions can be undone:

| Tier | Example | Authority |
|------|---------|-----------|
| **0** | isolate a process, snapshot evidence, throttle, tarpit | automatic · always reversible |
| **1** | drop a connection, block a newly-opened port | automatic · high-confidence · auto-expiring |
| **2** | destroy, rotate durable credentials | **you** — gated by a passphrase |

Cutting a server's internet doesn't disarm Arx. Losing contact with *our* servers doesn't
either. It **fails open** — degrading, at worst, to the free tier, **never to "no protection."**

## Capabilities

- Behavioral baseline & anomaly detection across the entire host (UEBA)
- Honeytokens / canaries that scream the moment they're touched
- Sensor fusion — osquery, auditd, eBPF — with graceful fallback when a sensor is absent
- Boot-time integrity: it won't learn an intruder as "normal"
- **Bring your own model keys** → zero inference cost, and your telemetry never leaves the
  box beyond the model you chose (secrets are redacted before they ever reach it)
- **Defensive by design** — Arx ships *no* offensive network tooling, in any tier
- Console-first, wizard onboarding, one self-contained binary, no external dependencies

## A note on how it's built

Two layers, on purpose. A **fast, deterministic** layer (sensors and rules, real-time)
contains threats; a **slow** layer (a model that reasons *off* the hot path) explains and
refines. The reasoning never blocks the defense.

The lifecycle is four words:

```
setup  →  recon  →  learn  →  guard
```

Everything else — the detection heuristics, the response logic, the intelligence that
ranks what matters — is where the real work lives, and it stays in the code.

## Editions

| Edition | For | Availability |
|---------|-----|--------------|
| **Core** | source-available, auditable, complete on the essentials of defense | **Free — available now** |
| **Pro** | managed threat intelligence, advanced detections, authorized self-testing | after Core's public testing phase |
| **Business** | fleet operation, central console, correlation, compliance, MDR | after Pro |

Core is licensed under the Business Source License; see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE). Core is free forever — if it defended your machine, you can fuel the
roadmap via the **Sponsor** button (pay what you want, one-time or monthly).

---

*Arx — the citadel keeps itself.*
