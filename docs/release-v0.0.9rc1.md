# Arx v0.0.9rc1

Core release candidate. This release strengthens hot-path acceptance, alert evidence, restart reporting, ephemeral-process attribution, and maintenance isolation.

## Highlights

- Accepted executables, directories, and children are honored by the hot path across processes. Profile identity uses device, inode, size, and nanosecond timestamps; missing or corrupt profiles do not grant trust.
- Notification outcomes are persisted separately from critical incidents, with recursive secret redaction and a bounded aggregate delivery budget. `ok` means the local channel accepted the send, not human receipt.
- `self_down` now queries systemd and distinguishes `scheduled`, `recovered`, `exhausted`, `failed`, and `unknown`. An active service takes precedence over a stale failure result.
- A bounded fanotify exec-permission watcher preserves minimal identity before `FAN_ALLOW`; netlink still confirms the exec. Short-lived processes can leave attributed evidence instead of disappearing before `/proc` is read.
- Sensitive-file attribution captures both PID and process birth before allowing the open, preventing attribution to a reused PID.
- APT/dpkg helpers are born in sibling scopes under `arx-maintenance.slice`, outside the guardian's memory cgroup. Heavy work is serialized, investigation jobs are deduplicated and bounded, and unavailable isolation fails closed instead of falling back into `arx.service`.
- Watcher coverage, overflows, drops, and degraded operation are visible in `arx status`, `watch.json`, and Business fleet heartbeats.

## Known limitations

- If fanotify or netlink is unavailable, Arx reports partial, degraded, or unavailable coverage. Scan-only operation can still miss processes that exit between sweeps.
- An identity recovered after a process has exited supports detection and forensics only. Arx does not claim retroactive freezing or network containment for that process.
- Fanotify permission handling is fail-open: if the reader stalls or its response fails, the group is closed so pending executions and opens are released. Coverage is then explicitly degraded.
- Script and interpreter chains can produce more fanotify events than netlink confirmations. Captures are promoted to incidents only after kernel exec confirmation.
- The maintenance slice starts with provisional 384 MiB `MemoryHigh` and 512 MiB `MemoryMax` budgets. Platform-specific package workloads may require different limits after measurement.
- A notification result of `ok` does not prove delivery by the external provider, receipt, or that a person read the alert.
- Existing cgroup and nftables limitations still apply; see the README for platform-specific behavior.

## Release gate

Do not publish this candidate until unit tests, lint, CI, package verification, and the directed Lima labs for Ubuntu 24.04 and Debian 13 are green. Merge, tag, and release require final human approval.
