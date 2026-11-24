# Arx v0.0.9

Arx 0.0.9 is the first stable Core release after 0.0.9rc1 and rc2. Critical configuration is now checked
file by file, by what a change means and who made it. Three ways to fool Arx through SSH log lines are fixed
(see Security). Package updates are told apart from tampering, and this was checked on real Ubuntu 24.04 and
Debian 13 servers: the last 12-hour pilot on both raised no false high or critical alert across signed
updates, kernel updates and manual upgrades. On a quiet host Arx now uses about a third of the CPU it used
in rc2.

## Highlights

- **auditd is always installed.** The package now depends on `auditd` instead of only suggesting it,
  so identity-file, honeytoken and denied-open alerts work out of the box. The installer starts it if
  it is not running, and says why when it cannot (inside a container the kernel does not allow it).
- **Colors on the terminal.** User and account names are blue, commands yellow and paths green, only
  in Arx's own output and only on a terminal. The journal, pipes, files, Telegram and webhooks get
  plain text. `NO_COLOR=1` or `ARX_COLOR=never` turn colors off; `ARX_COLOR=always` forces them.
- **`arx shell`.** An interactive console with history and Tab completion. A failing command or a
  `--help` never closes it. Without a terminal it reads commands from standard input.
- **Improvement program (opt-in).** Arx can send an anonymous usage report every few days, only after
  the owner says yes. Nothing is sent by default. Reports contain counters and fixed values, never host
  names, IPs, paths, users, commands or secrets. `arx telemetry show` prints exactly what would be sent.
- **Manual.** A complete terminal manual in English (`docs/manual.md`) and Spanish (`docs/manual.es.md`),
  and a `man arx` page installed with the package.

## Security

Three issues in how Arx read SSH access lines were found in pre-release review and fixed before 0.0.9.
They are present in **0.0.9rc1 and 0.0.9rc2**. **Updating to 0.0.9 is recommended** for anyone running
those. None of them let an attacker into the host; they let an attacker fool or misuse Arx's own detection.

- **A crafted SSH username could forge a login (remote, no account needed).** Arx matched "Accepted …"
  anywhere in a line. A remote user could offer an SSH username such as
  `Accepted publickey for root from 203.0.113.9 port 1`; sshd logs it as an invalid user, and Arx read
  it as a real login — a false alert, and during learning that origin was sealed as a known login. Fix:
  Arx now anchors the whole sshd line and reads logins only from the journal, only from lines a real
  sshd binary wrote.
- **A crafted SSH username could pick which IP Arx blocked (remote, no account needed).** This applies
  only to a server that allows password authentication, so sshd writes "Failed password" lines. Arx took
  the first "from" in such a line. A remote user could offer the username `x from 198.51.100.1 port 1`
  so the brute-force counter was attributed to an address of their choosing; with `--enforce`, Arx (a
  Tier 1 response) would block that address — for example the administrator's. Fix: Arx now uses the
  last "from <ip> port <n>", the one sshd writes, and only counts lines a real sshd binary wrote.
- **A local user could poison the baseline or hide their own access (local, unprivileged).** On a host
  with `/var/log/auth.log`, any local user can write a line through the system logger. Learning read
  that file, so a forged "Accepted … for root from <their ip>" was sealed as a known origin, and later
  real logins from it raised nothing; forged failures could also drive the block above. Fix: learning
  reads only the journal, and only lines a real sshd binary wrote (verified by the kernel-recorded
  executable, which a local process cannot fake); an entry whose writer cannot be verified does not
  count; without journald, no login is learned from any file.

## Fixes

### Installer output

The installer now installs the package in one `apt` step, so `apt` resolves `python3`, `auditd` and the
package together. `apt`'s own output is shown only if something fails. The installer prints one final
message.

### Critical configuration is checked by meaning, file by file

Each critical file is now tracked on its own: its contents, what a change means, its permissions, its
owner and, for a link, its target. Arx no longer reports one hash for a whole group.

- An alert names the file, says what the change means, and shows a diff against the known-good copy.
- An empty `sources.list` and an unsigned repository are no longer reported as the same change.
- Arx's own systemd units and drop-ins are compared with a manifest of their expected content.
- Watched files now also include drop-ins, sockets, timers, `.wants` links, generators,
  `authorized_keys2` and `cron.daily`.
- APT configuration is read the way APT reads it, so a comment marker inside a string cannot hide a
  later hook.
- A new systemd unit or drop-in is reported as high. A new APT repository or APT key stays critical.
- Every integrity alert says who wrote the file, from the sealed state: the executable, its pid and uid
  and, after a login, that login's uid and session.
- A change made by dpkg is accepted without an alert only if every write came from an intact
  `/usr/bin/dpkg` of a signed origin, and the file belongs to a package whose installed version comes
  from a signed repository. A local `.deb`, a tampered dpkg or mixed writers still raise an alert.

### Package checks run only when packages change

While the host is quiet, Arx asks dpkg only when dpkg's state changes. It no longer repeats the full
package inventory on every sweep. If dpkg does not answer, the error is reported and nothing is stored;
a missing answer is never read as "nothing changed".

### Model verdicts

The model's verdict travels in its own structured channel, separate from the analysis written for
people. A verdict line placed inside the analysis is ignored. Validation is unchanged: zero tolerance,
one verdict per finding, only the ids Arx asked about.

If you accept a finding (`arx accept`) while the model is still analysing it, its late verdict no longer
acts. Before, a "threat" verdict could still close the session and block the origin you had just
accepted. An accepted login is remembered for 30 days, so the model cannot overrule you if it comes back.

### A new root or last-admin login is answered on your word

A new login by root, a system account or the last administrator account is not answered by locking the
account. Arx blocks the origin and closes that one session; the account stays open. This is a Tier 2
action, on your word (`arx authorize`). The model never triggers it, not even with `--enforce`.

### Integrity checks reread only what changed

An integrity check reads a file again only when its metadata changes (including its change time, which
`touch -r` cannot restore), when auditd sees a write to it, or once an hour. Setting the clock back does
not hide a write from the cache: Arx compares the identity of the last audit event, not its date.

### Package updates are not mistaken for tampering

Found during the pilot on real Ubuntu 24.04 and Debian 13 servers, when automatic updates ran.

- **An edited configuration file does not make an update untrusted.** Arx read `dpkg --verify` one column
  off, so a configuration file you had edited (for example `/etc/nginx/nginx.conf`) counted as a tampered
  package file. The update was rated untrusted and the service lost its network. Edited configuration
  files are yours; changed programs and libraries still fail the check.
- **A package update does not raise identity alerts.** When sudo was updated, the writes of dpkg and of the
  package's own scripts to `/etc/sudoers` raised high alerts. Now they are one info entry, but only when
  Arx can prove that:
  - dpkg is intact;
  - the package and dpkg come from a signed repository;
  - the file belongs to that package;
  - the write happened inside that package's own transaction;
  - the writer was dpkg, or one of the package's maintainer scripts (proved from the process tree, so
    an `apt upgrade` run by hand counts too).

  A local `.deb`, a `trusted=yes` source, a write outside a transaction, another package's file, or a
  tampered dpkg or tool still raise high.
- **Trust verdicts expire as designed.** A cached verdict was saved again every time it was reused, so it
  never expired. Verdicts now last their 7 days. A verdict made by a check that has since been fixed is
  measured again.
- **A verified update gives the network back.** When the installed version of a package is verified, the
  containment left by older untrusted verdicts for that package is lifted, and the incident stays in the
  log. Containment for another version is lifted only if the whole service restarted after it, because
  until then the untrusted code may still be running in memory.

### Hardening and fixes from the pilot

Found on real Ubuntu 24.04 and Debian 13 hosts during the pilot.

- **Upgrading to a build that watches new config groups no longer re-alerts.** When Arx starts watching
  `rc.local`, shell init files and `ld.so.conf`, the files already there are adopted with a single
  medium notice that names any risky unpackaged ones; they are not reported as new changes.
- **A missing package directory is not a changed program.** On Debian 13 some packages ship an empty
  directory that `dpkg --verify` reports as "missing"; this no longer counts a program (for example
  `sshd-session`) as changed.
- **Egress learning survives a service restart.** A restarted service, whose control group now shows as
  a number, is still attributed to it. What has been learned is removed from the kernel once read, so
  the set does not grow, and every risky file found on an upgrade is named, not only the first ten.
- A call on an identity file that does not exist is not treated as an event.
- Arx's own service is not reported as a "new service" after sealing.
- In observe mode a new destination is still reported within one sweep; a near-full set warns instead of
  silently dropping.
- `arx service install` with the service already running restarts it with the new unit.

## Performance

Measured on the pilot servers (small cloud VPS): Ubuntu 24.04 in enforce mode with one confined
service, Debian 13 in observe mode. CPU is the whole `arx.service`, its helper processes included, averaged
over 12 hours in 10-minute windows.

- **Idle CPU about 0.7 % of one core** (0.74 % on Ubuntu, 0.68 % on Debian), down from 2.2 % before these
  changes. Updates, trust checks and model calls make short peaks: a few 10-minute windows reached 1.4–1.8 %.
- **A quiet sweep starts 2 helper processes, not 17.** Arx asks dpkg only when dpkg's state changes, and
  reuses signed provenance while apt's state does not change. Maintenance helpers dropped from 12 per hour
  to 3.6–4.6.
- **nftables is read only when something changed.** The structure of Arx's table is read without its
  elements, and only again when the nf_tables generation changes. Learned destinations are removed from
  the kernel once read, and read every 15 minutes instead of 5.
- Integrity rereads only what changed, with a full recheck once an hour.
- Memory stayed flat: 37–64 MB resident.

## Upgrading

- **From 0.0.8, rc1 or rc2.** Sealed baselines are migrated. Unchanged files are adopted silently. A
  group that had already changed keeps its group alert until you accept it (`arx accept`).
- The first comparison after upgrading from rc2 or earlier does one extra check.
- When the new build watches config groups the old baseline did not, the files already in them are
  adopted with one medium `integrity_watch_added` notice; any change from then on is reported as usual.
- The package upgrade stops the running guard and starts it again (its pre/post-install steps); the
  service returns in the same mode it was in. Containment that was in place is restored.

## Known limitations

- The improvement program reports to `https://telemetry.adsyslabs.com/v1/report`, a collector run by ASL
  behind Cloudflare. If a report cannot be delivered, Arx tries again at most every 6 hours, without
  affecting the defense.
- Colors use the terminal's own palette; the exact shade depends on its theme.
- **Without journald (non-systemd hosts).** Arx still reads `/var/log/auth.log` to detect brute force
  and log tampering, but never learns a login from a file. A local user who can write to the system log
  can still produce a one-off false login alert there (it is not sealed).
- **Authorship needs a working audit backend.** Attributing a change to who made it relies on auditd's
  file watches, which some virtualized guests do not deliver. Detection works without it; only the
  "who" is missing there.
- **Listening-socket owners are refreshed lazily.** A new port, or a port that changes socket, is seen in
  the same sweep. If a second process inherits or receives an existing listener while its first owner is
  still alive, the owner list Arx shows for that port can be up to 5 minutes old.
- **Idle CPU is about 0.7 % of one core**, not the 0.5 % we aimed for. What remains is the 30-second
  polling design; 0.0.9.1 replaces most of it with events (inotify, dpkg and nftables) and targets under
  0.3 %.
- **A configuration change is seen within one sweep (up to 30 s).** 0.0.9.1 brings this down to seconds.
- **A model analysis can delay the next sweep.** The model is asked in the same loop that sweeps, with a
  3-minute limit, and nothing is lost meanwhile. In 0.0.9.1 the model runs on its own thread.
- **Inside a package's own transaction**, which took a median of 1 s and at most 13 s in our logs, a root
  process without a login session could write one of that package's files with a signed tool and put it
  back before the next sweep, and Arx would report it as info. Any change that stays is still caught by the
  integrity check.
