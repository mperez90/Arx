# VM for levels 7–10: the real thing

The Docker mini-lab covers L3–L9 quickly, but the top levels need a full system: real systemd,
auditd, real persistence and **permission to destroy**. This VM is disposable by design.

## Topology

```
┌─────────────────┐   host-only net   ┌──────────────────┐
│  VICTIM          │ ◄──────────────► │  ATTACKER         │
│  Ubuntu 22.04    │  192.168.64.10   │  Kali Linux       │
│  + Arx --enforce │                  │  (kali-rolling)   │
└─────────────────┘                   └──────────────────┘
   "gold" snapshot ──► restore between levels
```

What can be done without a VM is already in `lab/systemd-lab.sh` and `lab/level10.sh`. This VM adds
its own kernel, auditd, Falco and a real reboot.

## Setup (Apple Silicon, UTM)

1. **UTM** (free, App Store or brew). New VM → Linux → ISO `ubuntu-22.04-live-server-arm64`.
   2 CPU / 4 GB RAM / 25 GB disk are enough.
2. Network: **Host-Only** (no outbound NAT during L10; to install packages, switch to NAT for a
   moment and back).
3. Install Ubuntu, then inside the VM:
   ```bash
   bash lab/vm/setup-victim.sh      # installs Arx from the release, learn+seal, canaries, service
   ```
4. Shut down cleanly and take the **"gold" snapshot** (UTM → right click → Clone, or
   `qemu-img snapshot`). Every destructive level starts from gold.
5. Attacker: another VM with Kali ARM64 on the same host-only network.

## Levels

| Level | Script (run FROM the attacker or inside, as indicated) | What must happen |
|---|---|---|
| 7 | `attacks/l7-suid.sh` (inside, over the gained SSH) | crit from SUID integrity in ≤ 1 h (or at once with `--once`) |
| 8 | `attacks/l8-persist.sh` (inside) | crit → Tier 2 → authorization → restore from the vault + evidence in quarantine |
| 9 | `attacks/l9-antiforensics.sh` (inside) | canary reads detected; log truncation logged as a gap if there's no finding |
| 10 | `attacks/l10-destroy.sh` (inside, DESTROYS the VM) | the safety brake trips (≤5 actions/h), mass critical alerts, Arx does nothing irreversible |

## Evidence discipline

Each level leaves: attacker output, `incidents.jsonl`, `arx status`, and notes in
`lab/vm/scoreboard.md`. Whatever fails becomes a new bug with its regression test.
