"""Arx · consola interactiva (`arx shell`).

    usuario@host:/ruta arx› status

El usuario va en azul, la ruta en verde y lo que escribes en amarillo; la salida de cada comando
usa los mismos colores (usuarios, comandos, rutas). Solo dentro de esta consola: al salir, la
terminal queda como estaba y no se toca la configuración del shell.

Se escribe cada comando de Arx sin el «arx» delante (también vale con él). Tab completa
subcomandos, acciones, opciones y rutas; el historial vive en ~/.arx_history (0600).
Sin terminal (`printf 'status\\n' | arx shell`) lee los comandos de la entrada, sin prompt.
"""
from __future__ import annotations

import glob
import os
import shlex
import socket
import sys

from arx import term
from arx.i18n import tr

HISTORY = "~/.arx_history"
HISTORY_MAX = 1000
BUILTINS = ("help", "exit", "quit", "cd", "pwd", "clear", "history")


def _user() -> str:
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except (ImportError, KeyError, AttributeError):
        return os.environ.get("USER") or "?"


def _where() -> str:
    try:
        cwd = os.getcwd()
    except OSError:  # el directorio actual ya no existe
        return "?"
    home = os.path.expanduser("~")
    if home not in ("", "/") and (cwd == home or cwd.startswith(home + os.sep)):
        return "~" + cwd[len(home):]
    return cwd


def prompt(color: bool, readline: bool) -> str:
    """El prompt. Con readline, el color va entre \\001 y \\002 para que no cuente como ancho."""
    who = f"{_user()}@{socket.gethostname().split('.')[0]}"
    where = _where()
    if not color:
        return f"{who}:{where} arx› "

    def esc(code: str) -> str:
        seq = f"\033[{code}m"
        return f"\001{seq}\002" if readline else seq

    return f"{esc(term.BLUE)}{who}{esc('0')}:{esc(term.GREEN)}{where}{esc('0')} arx› {esc(term.YELLOW)}"


def _flags(spec: dict) -> list[str]:
    return sorted(spec.get("flags", ()))


def complete_options(words: list[str], text: str, gram: dict) -> list[str]:
    """Lo que Tab puede poner: subcomandos y órdenes propias, luego acciones y opciones; rutas si toca."""
    if words and words[0] == "arx":
        words = words[1:]
    if not words:
        return sorted(o for o in list(gram) + list(BUILTINS) if o.startswith(text))
    if words[0] == "cd" or text.startswith(("/", "~", ".")) or words[0] == "scan":
        return _paths(text, dirs_only=words[0] == "cd")
    spec = gram.get(words[0])
    if spec is None:
        return []
    for w in words[1:]:
        if w in spec["actions"]:
            spec = spec["actions"][w]
    opts = list(spec["actions"]) + _flags(spec)
    return sorted(o for o in opts if o.startswith(text))


def _paths(text: str, dirs_only: bool) -> list[str]:
    base = os.path.expanduser(text)
    out = []
    for p in sorted(glob.glob(glob.escape(base) + "*")):
        if os.path.isdir(p):
            p += "/"
        elif dirs_only:
            continue
        out.append(text + p[len(base):] if text.startswith("~") else p)
    return out


def _readline(gram: dict):
    try:
        import readline
    except ImportError:
        return None
    path = os.path.expanduser(HISTORY)
    try:
        readline.read_history_file(path)
    except (OSError, ValueError):
        pass
    readline.set_history_length(HISTORY_MAX)
    readline.set_completer_delims(" \t\n")

    def completer(text: str, state: int):
        line = readline.get_line_buffer()[:readline.get_begidx()]
        try:
            options = complete_options(line.split(), text, gram)
        except Exception:
            return None
        # Python no añade el espacio tras una palabra completa; un directorio sigue abierto con su «/»
        options = [o if o.endswith("/") else o + " " for o in options]
        return options[state] if state < len(options) else None

    readline.set_completer(completer)
    if _libedit(readline):  # macOS
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
    return readline


def _libedit(rl) -> bool:
    """libedit (macOS) no respeta los marcadores \\001/\\002 del prompt: con él, el prompt va sin color."""
    return getattr(rl, "backend", "") == "editline" or "libedit" in (rl.__doc__ or "")


def _save_history(rl) -> None:
    if rl is None:
        return
    path = os.path.expanduser(HISTORY)
    try:
        old = os.umask(0o077)
        try:
            rl.write_history_file(path)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
    except OSError:
        pass


def _help(parser) -> None:
    import argparse

    print(tr("Arx commands (type them without «arx»; «<command> --help» for details):"))
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            for choice in a._choices_actions:
                if choice.dest != "shell":
                    print(f"  {choice.dest:<12} {choice.help or ''}")
    print(tr("Console:"))
    print(tr("  cd <dir>     change directory (shown in green in the prompt)"))
    print(tr("  pwd · history · clear · help · exit"))


def execute(argv: list[str]) -> int:
    """Un comando de Arx dentro de la consola: un error o un --help nunca la cierran."""
    from arx import cli, redact

    try:
        return cli.main(argv) or 0
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code)
            return 1
        return e.code or 0
    except KeyboardInterrupt:
        print()
        return 130
    except Exception as e:  # noqa: BLE001 — la consola sigue viva
        print(tr("⚠ the command failed ({name}: {e})", name=type(e).__name__, e=redact.printable(e)))
        return 1


def handle(line: str, parser, rl=None) -> int | None:
    """Una línea. None = salir de la consola; si no, el código del comando."""
    line = line.strip()
    if not line or line.startswith("#"):
        return 0
    try:
        argv = shlex.split(line)
    except ValueError as e:
        print(tr("⚠ cannot read that line: {e}", e=e))
        return 2
    if argv[0] == "arx":
        argv = argv[1:]
        if not argv:
            return 0
    name = argv[0]
    if name in ("exit", "quit"):
        return None
    if name in ("help", "?"):
        _help(parser)
        return 0
    if name == "cd":
        target = os.path.expanduser(argv[1] if len(argv) > 1 else "~")
        try:
            os.chdir(target)
        except OSError as e:
            print(tr("⚠ cd: {e}", e=e.strerror or e))
            return 1
        return 0
    if name == "pwd":
        print(os.getcwd())
        return 0
    if name == "clear":
        sys.stdout.write("\033[H\033[2J")
        sys.stdout.flush()
        return 0
    if name == "history":
        if rl is not None:
            for i in range(1, rl.get_current_history_length() + 1):
                print(f"  {i:>4}  {rl.get_history_item(i)}")
        return 0
    if name == "shell":
        print(tr("You are already in the Arx console."))
        return 0
    return execute(argv)


def run() -> int:
    from arx import __version__, cli

    parser = cli.build_parser()
    gram = term.grammar(parser)
    interactive = sys.stdin.isatty()
    rl = _readline(gram) if interactive else None
    color = interactive and term.enabled() and not (rl is not None and _libedit(rl))
    if interactive:
        print(tr("Arx {v} console · «help» lists the commands · «exit» or Ctrl+D to leave",
                 v=__version__))
    last = 0
    try:
        while True:
            try:
                line = input(prompt(color, rl is not None)) if interactive else sys.stdin.readline()
            except EOFError:
                if color:
                    sys.stdout.write(term.RESET)
                print()
                break
            except KeyboardInterrupt:
                if color:
                    sys.stdout.write(term.RESET)
                print()
                continue
            if color:
                sys.stdout.write(term.RESET)
                sys.stdout.flush()
            if not interactive and line == "":
                break
            code = handle(line, parser, rl)
            if code is None:
                break
            last = code
    finally:
        _save_history(rl)
    return last if not interactive else 0
