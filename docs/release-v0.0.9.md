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

### Alerts for changed files: what changed and who changed it

TODO: confirmar con arx-98 — ítem interno B77. Behavior after the fix.

### CPU, journal and scope load while watching packages

TODO: confirmar con arx-98 — ítem interno B78. Behavior after the fix.

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
