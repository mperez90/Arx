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

### Alerts about Arx's own service files

TODO: confirmar con arx-98 — ítem interno B73. Behavior after the fix.

### Installer output

TODO: confirmar con arx-98 — ítem interno B75. Behavior after the fix.

### Critical configuration is checked by meaning, file by file

BORRADOR. TODO: confirmar con arx-98 (fuentes: d7220be + 0e94db4; incluye B73 y HZ#1-5). No lab figures.

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

**Upgrading.** Baselines from earlier versions are migrated. Unchanged files are adopted silently. A
changed group is rebuilt from the vault if its copy matches what was sealed and is judged by meaning;
otherwise its group alert stays until you accept it.

### Arx uses almost nothing while the host is quiet

BORRADOR. TODO: confirmar con arx-98 (fuentes: 1552c3a + 7d5ead9). The title claims "almost nothing";
only a bounded dpkg query budget is tested, and no measurement is published here. No lab figures.

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

TODO: confirmar con arx-98 — ítem interno B79. Behavior after the fix.

### Tier 2 actions offered to root

TODO: confirmar con arx-98 — ítem interno root. Behavior after the fix.

## Upgrading

TODO: confirmar con arx-98 — what happens to installations from 0.0.8, rc1 and rc2.

## Known limitations

- The improvement program reports to `https://telemetry.adsyslabs.com/v1/report`, a collector run by
  ASL behind Cloudflare. If a report cannot be delivered, Arx tries again at most every 6 hours,
  without affecting the defense.
- Colors use the terminal's own palette; the exact shade depends on its theme.
- TODO: confirmar con arx-98 — limitations of 0.0.9 (replace the rc1/rc2 carry-over once the list is final).
