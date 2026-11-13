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
- Package upgrades no longer replace the zipapp under a running guardian. The new package's `preinst` stops Arx before unpacking, including upgrades from v0.0.8rc5 and earlier, and `postinst` starts it again only if it was running. If that start fails, the package stays half-configured and `dpkg --configure -a` retries it. If the stop fails, the upgrade is aborted with the old version still running.
- While the exec-permission watcher is active, Arx's own subprocesses avoid CPython's `posix_spawn` path and, on Python 3.10 and 3.11, `vfork`. Both hold the interpreter lock until the child execs, and that exec waits for Arx's own fanotify answer. The `posix_spawn` deadlock was observed with CPython 3.13 on Debian 13; the `vfork` one was reproduced with CPython 3.10 on Ubuntu 24.04's kernel.
- A busy, unavailable, or timed-out dpkg/apt query is no longer read as "not from any package" or "apt does not know it", and is never cached. Short read-only queries have their own slot and never wait behind a verification or download. Trust assessments stay pending, and a finding whose origin proof got no answer is postponed for a few sweeps, then decided without the proof, as before.
- Files that dpkg deliberately did not install (its `path-exclude` filters) and missing documentation no longer count as tampering. A missing binary or library, or a symlink where the package installed a regular file, still does.
- A live script is now attributed to the interpreter that runs it, as `/proc` reports, so a web shell's shell is frozen again. A failed exec attempt cannot lend its identity to the next exec of the same process.
- The comparison against a fresh copy of the official package passes only if `dpkg-deb` read it to the end. A helper killed mid-stream yields `unknown`, never `pass`.
- With `auditd` installed, a denied attempt by a service to open a sensitive file (`/etc/shadow`, `sudoers`, host keys, TLS private keys…) is reported, with user, executable and process. Fanotify cannot see these: the kernel checks permissions before the event.
- Arx now follows the auditd log itself (by device, inode and offset, across rotation) instead of `ausearch --checkpoint`. On auditd 4.0 (Debian 13), the checkpoint returned no new events, so Arx's identity-file, honeytoken and denied-open rules were not reported there.
- The hourly SUID walk covers every local filesystem where the bit gives privileges (mounted without `nosuid`), not only the root filesystem. Container layers, snaps, network and FUSE filesystems are left out. When a filesystem enters the walk for the first time, its existing SUID binaries are taken as known and listed for review; any later one is critical.
- A reverse shell that replaced itself with another program while keeping the socket is still suspended: the response follows the process birth, and resuming it requires the same birth.
- If an upgrade fails while unpacking after Arx was stopped, the package's `postrm` starts it again. Measured: at that point the files on disk are still the previous version.
- nftables 1.0.9 lists Arx's sets as `socket cgroupv2 level 0`. That is only how it prints them: matching is done by the rules (`level 2`), and nested cgroups are matched (measured on Ubuntu 24.04). The destructive "migration" of those sets is gone.

## Known limitations

- If fanotify or netlink is unavailable, Arx reports partial, degraded, or unavailable coverage. Scan-only operation can still miss processes that exit between sweeps.
- Network and FUSE filesystems (NFS, CIFS, `fuse.*`) are not marked for exec permission events: a hung remote could otherwise stall every exec on the host. Execs there are still confirmed by netlink, without the identity captured before exit.
- An identity recovered after a process has exited supports detection and forensics only. Arx does not claim retroactive freezing or network containment for that process.
- Fanotify permission handling is fail-open: if the reader stalls or its response fails, the group is closed so pending executions and opens are released. Coverage is then explicitly degraded, and stays degraded until Arx restarts: `arx status` and `watch.json` show it.
- Script and interpreter chains can produce more fanotify events than netlink confirmations. Captures are promoted to incidents only after kernel exec confirmation.
- The maintenance slice is capped at 384 MiB `MemoryHigh` and 512 MiB `MemoryMax`. Measured on Debian 13 with helpers serialized, the largest real helper (`apt-get download` of a kernel package, page cache included) peaked at 52 MiB. On Ubuntu 24.04 the largest measured helper peaked at 42 MiB. Hosts with much larger APT caches have not been measured. A helper that exceeds the cap is killed inside its own scope (Debian 13), or throttled under `MemoryHigh` until its timeout stops the scope (Ubuntu 24.04's kernel); either way the guardian is untouched and that check reports `unknown`.
- A notification result of `ok` does not prove delivery by the external provider, receipt, or that a person read the alert. In this candidate, per-channel results, partial failures, the delivery budget, and redaction were validated against local fake Telegram and webhook endpoints. Delivery through the real Telegram API was validated once on Debian 13 (test alert and stop alert received); real webhook endpoints were not re-validated.
- Denied reads of sensitive files are reported only with `auditd` installed (`Suggests: auditd`), and only when the denial happens on the watched file itself, not at a private parent directory. Attempts from login sessions are ignored, as for successful reads.
- Root can suppress Arx's stop alerts (freeze it, override its unit at runtime, or cut its network first).
- Existing cgroup and nftables limitations still apply; see the README for platform-specific behavior.

## Release gate

Do not publish this candidate until unit tests, lint, CI, package verification, and the directed Lima labs for Ubuntu 24.04 and Debian 13 are green. Merge, tag, and release require final human approval.
