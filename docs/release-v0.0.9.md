# Arx v0.0.9

TODO: confirmar con arx-98 — summary of the release (one paragraph, after the fixes are final).

## Highlights

TODO: confirmar con arx-98 — the rc2 items below are carried over; check each one against the final 0.0.9 build.

- **auditd is always installed.** The package now depends on `auditd` instead of only suggesting it,
  so identity-file, honeytoken and denied-open alerts work out of the box. The installer starts it if
  it is not running, and says why when it cannot (inside a container the kernel does not allow it).
- **Colors on the terminal.** User and account names are blue, commands yellow and paths green, only
  in Arx's own output and only on a terminal. The journal, pipes, files, Telegram and webhooks get
  plain text. Commands are recognized with the CLI's real grammar, so only the command itself is
  colored. `NO_COLOR=1` or `ARX_COLOR=never` turn colors off; `ARX_COLOR=always` forces them.
- **`arx shell`.** An interactive console with a colored prompt (user blue, directory green, typed
  text yellow), history in `~/.arx_history`, and Tab completion of commands, actions, options and
  paths. A failing command or a `--help` never closes it. Without a terminal it reads commands from
  standard input.
- **Improvement program (opt-in).** Arx can send an anonymous usage report every few days, only after
  the owner says yes in the installer, in `arx setup` (new step 8) or with `arx telemetry enable`.
  Nothing is sent by default. Reports contain counters and fixed values (version, distribution,
  kernel, mode, watcher health, noise), never host names, IPs, paths, users, commands or secrets. A
  final filter drops anything else. `arx telemetry show` prints exactly what would be sent, and
  `ARX_TELEMETRY=off` or `DO_NOT_TRACK=1` override consent. The collector is in
  `tools/telemetry-collector`.
- **Manual.** A complete terminal manual in English (`docs/manual.md`) and Spanish
  (`docs/manual.es.md`), and a `man arx` page installed with the package.
- `arx setup` keeps the default of any question left when its input runs out, instead of failing.
- A systemd-lab check no longer races journald.

## Fixes

TODO: confirmar con arx-98 — the entries below are placeholders. Each one needs its final wording, its
test reference and its evidence before it is published. Do not describe behavior until arx-98 confirms it.

### Installer output

BORRADOR. TODO: confirmar con arx-98 (fuentes: 86a9749). No lab figures.

The installer now installs the package in one `apt` step, so `apt` resolves `python3`, `auditd` and the
package together. `apt`'s own output is shown only if something fails. The installer prints one final
message.

### Critical configuration is checked by meaning, file by file

BORRADOR. TODO: confirmar con arx-98 (fuentes: d7220be + 0e94db4). No lab figures.

Each critical file is now tracked on its own: its contents, what a change means, its permissions, its
owner and, for a link, its target. Arx no longer reports one hash for a whole group.

- An alert names the file, says what the change means, and shows a diff against the known-good copy.
- An empty `sources.list` and an unsigned repository are no longer reported as the same change.
- Arx's own systemd units and drop-ins are compared with a manifest of their expected content. A mismatch
  means someone changed Arx itself.
- Watched files now also include drop-ins, sockets, timers, `.wants` links, generators,
  `authorized_keys2` and `cron.daily`.
- APT configuration is read the way APT reads it, so a comment marker inside a string cannot hide a
  later hook.
- An SSH key's type is read from the key itself. Certificates and `sk-` keys are recognized. An
  unrecognized new line in root's `authorized_keys` is reported as high.
- A new systemd unit or drop-in is reported as high. `OnFailure=`, `Wants=` and `BindPaths=` are
  treated as sensitive.
- A new APT repository or APT key stays critical.
- Reads never follow links and never block on a FIFO. They have size and file-count limits. When a group
  has too many files, only the first ones are watched and the alert says so.
- Restoring a file from an alert (Tier 2) touches only that file.
- Every integrity alert says who wrote the file, from the sealed state: the executable, its pid and uid
  and, after a login, that login's uid and session. An edit made with `sed -i` is attributed to the
  target file, not only to its temporary copy.
- A change made by dpkg is accepted without an alert only if every write came from an intact
  `/usr/bin/dpkg` of a signed origin, and the file belongs to a package whose installed version comes
  from a signed repository. A local `.deb`, a tampered dpkg, mixed writers or missing authorship still
  raise an alert. A `.deb` that only carries the name of a repository package is not accepted as an
  update.

**Upgrading.** Baselines from earlier versions are migrated. Unchanged files are adopted silently. A
changed group is rebuilt from the vault if its copy matches what was sealed and is judged by meaning;
otherwise its group alert stays until you accept it.

### Package checks run only when packages change

BORRADOR. TODO: confirmar con arx-98 (fuentes: 1552c3a + 7d5ead9). No lab figures.

While the host is quiet, Arx asks dpkg only when dpkg's state changes: when a transaction finishes or is
running, or when diversions change. It no longer repeats the full package inventory on every sweep.

- The package inventory is read once per dpkg state. Owner lookups are batched and cached per state.
- If dpkg does not answer (timeout, or it cannot run), the error is reported and nothing is stored. A
  missing answer is never read as "nothing changed" or as "no package owns this file".
- Services with no process, or with a statically linked binary, are retried with growing waits instead
  of on every sweep.
- The libraries of a service are learned again when the processes in its control group change (start or
  restart).
- A test checks that quiet periods trigger a bounded number of dpkg queries.

**Upgrading.** The first comparison after upgrading from 0.0.9rc2 or earlier does an extra check.

### Model verdicts with Kimi

BORRADOR. TODO: confirmar con arx-98 (fuentes: 35d5425). No lab figures.

The model's verdict no longer depends on a final `VERDICTS:` line in its prose. Each provider returns it
in its own structured-output format. If a provider rejects that format or returns no object, Arx asks
once more for the JSON alone. The analysis written for people and the verdict read by the machine are
now separate requests. A verdict line inside the analysis is ignored.

- Validation is unchanged: zero tolerance, the same schema, a reason of at most 300 characters. Only
  the ids Arx asked about are accepted, and one verdict per finding.
- `arx metrics` shows, per provider and route, how many verdicts were requested, valid and missing,
  over the last 60 days. It shows counts only.

### Tier 2 actions offered to root

BORRADOR. TODO: confirmar con arx-98 (fuentes: 4950990). No lab figures.

A new login by root, a system account or the last administrator account is no longer answered by
locking the account. Arx blocks the origin of that access and closes that one session. The account stays
open. This is offered only as a Tier 2 action, on your word (`arx authorize`). The model never triggers
it, not even with `--enforce`.

- The block expires on its own and respects protected IP addresses. `arx unblock` lifts it early.
- Only the session of that connection is closed. Other sessions, from other origins or accounts, and the
  SSH daemon that listens are not touched.
- If the account can be locked when you authorize, Arx locks it.

### Integrity checks reread only what changed

BORRADOR. TODO: confirmar con arx-98 (fuentes: bf72497, e2f1457). No lab figures.

An integrity check reads a file again only when its metadata changes (including its change time, which
`touch -r` cannot restore), when auditd sees a write to it, or once an hour. Sealing and accepting still
read everything.

- Setting the system clock back does not hide a write from the cache. Arx compares the identity of the
  last audit event, not its date.

## Upgrading

TODO: confirmar con arx-98 — what happens to installations from 0.0.8, rc1 and rc2.

## Known limitations

- The improvement program reports to `https://telemetry.adsyslabs.com/v1/report`, a collector run by
  ASL behind Cloudflare. If a report cannot be delivered, Arx tries again at most every 6 hours,
  without affecting the defense.
- Colors use the terminal's own palette; the exact shade depends on its theme.
- TODO: confirmar con arx-98 — limitations of 0.0.9 (replace the rc1/rc2 carry-over once the list is final).
