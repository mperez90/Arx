# Arx: tier matrix

**Core** is real, free defense, and it's the only tier available today. **Pro** and **Business**
are **planned**: they open after Core's public testing phase, and this table describes what's
intended, not what you can buy now. Every paid ✅ must exist and be tested before it goes on sale.

| Capability | Core (free) | Pro (1 device) | Business (per device) |
|---|---|---|---|
| Install wizard (console) | ✅ | ✅ | ✅ |
| Initial reconnaissance + inventory | ✅ | ✅ | ✅ |
| Baseline (executables · ports · services · users + gauges) | ✅ | ✅ | ✅ |
| Canaries / honeytokens | ✅ | ✅ | ✅ |
| Sensors (auditd, installed with Arx · osquery · Falco, if installed) | ✅ | ✅ | ✅ |
| Tier 0/1 response (automatic and reversible) | ✅ | ✅ | ✅ |
| Tier 2 response (human + word) | ✅ | ✅ | ✅ |
| Proof of origin for new software; confinement without network for what can't prove it | ✅ | ✅ | ✅ |
| Behavior observation: each service's usual behavior, and a cut for what departs from it | ✅ | ✅ (shared across hosts: planned) | ✅ (shared across hosts: planned) |
| Account lock: closes sessions and access, only a person lifts it | ✅ | ✅ | ✅ |
| The model (your key) can confirm a threat and close that account, with safeguards | ✅ | ✅ | ✅ |
| Control from Telegram, with a one-time code | ✅ | ✅ | ✅ |
| Proposals (normalize, harden SSH): Arx proposes, you approve | ✅ | + autonomous with rollback | + autonomous with rollback |
| Signed vaccines, validated on each host (the channel isn't open yet) | ✅ | ✅ | ✅ |
| Vaccines approved by a consensus of paid hosts, validated again on each host (opens with Pro) | ✅ receives | ✅ receives and votes | ✅ receives and votes |
| Static file analysis (`arx scan`) | ✅ | ✅ | ✅ |
| Sealed forensic report (`arx forensics`) | ✅ | ✅ | ✅ |
| Threat intel | community, through vaccines (the channel isn't open yet) | **managed, real time** | managed + private |
| Advanced TTP detections | basic | ✅ | ✅ |
| Self-pentest of the host itself | — | ✅ (curated) | ✅ |
| Authorized assessment of your own assets (Kali/Parrot) | — | — | ✅ |
| Posture reports | basic | ✅ | compliance (SOC2/ISO) |
| Central console + cross-host correlation | — | — | ✅ |
| Hosts that defend each other | — | — | ✅ |
| SIEM/SOAR integration · RBAC · audit | — | — | ✅ |
| Support | community | standard | SLA (+ optional MDR, under a separate contract) |

**Core is defense only.** The paid tiers add authorized assessment of your own assets, with
scope enforced by code and human approval for each exercise. No packaged C2 or pivoting, and
never against third parties: there's no hack-back in any tier. The code for that assessment
doesn't live in this repository.
