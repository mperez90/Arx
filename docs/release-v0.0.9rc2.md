# Arx v0.0.9rc2

Core release candidate. This release makes Arx easier to use from the terminal, always ships auditd,
and adds an opt-in improvement program. The defense itself is unchanged from v0.0.9rc1.

## Highlights

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

## Upgrading

`apt` installs `auditd` as a new dependency. With `dpkg -i`, run `sudo apt-get install -f` afterwards.
Existing installations keep their settings; they are asked about the improvement program only if
`arx setup` is run again or `arx telemetry` is used.

## Known limitations

- The improvement program reports to `https://telemetry.adsyslabs.com/v1/report`, a collector run by
  ASL behind Cloudflare. If a report cannot be delivered, Arx tries again at most every 6 hours,
  without affecting the defense.
- Colors use the terminal's own palette; the exact shade depends on its theme.
- The limitations of v0.0.9rc1 still apply.
