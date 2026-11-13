"""Arx · colores de la terminal: usuarios en azul, comandos en amarillo, rutas en verde.

Solo la salida de Arx y solo hacia una terminal: el journal, una tubería, un fichero, Telegram y el
webhook reciben el texto limpio, porque el color se pone al escribir en la terminal y nunca en los
datos. No toca la configuración del shell del operador.

    ARX_COLOR=never|always   fuerza el modo (por defecto: auto, solo si la salida es una terminal)
    NO_COLOR=1               desactiva los colores (https://no-color.org)

Un comando de Arx se reconoce con la gramática real de la CLI (subcomando, acción, opciones y su
número de argumentos), así una frase como «arx learn several times» no se pinta entera. Un usuario
se pinta en un contexto inequívoco («account 'x'», «user: x», «uid=0(root)») o, tras «as/como/by/
por», solo si es una cuenta de este host.
"""
from __future__ import annotations

import io
import os
import re
import sys

BLUE, YELLOW, GREEN = "34", "33", "32"
RESET = "\033[0m"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TOKEN = re.compile(r"\S+")
_PLACEHOLDER = re.compile(r"<[^>\s]+>|\[[^\]\s]+\]|[A-Z][A-Z0-9_|]+")
_FLAG = re.compile(r"--?[A-Za-z][\w-]*(?:=\S+)?")
_ARX = re.compile(r"(?<![\w/.-])(?:sudo )?arx(?= [a-z])")
_SYSTEM = re.compile(r"(?:(?<=:)|(?<=: )|(?<=:  )|(?<=&& )|^)(?:sudo )?(?:systemctl|journalctl|dpkg|apt-get|apt) (?=\S)")
_PATH = re.compile(r"(?<![\w.:/~\\-])~?/[\w.@%+=,~-]+(?:/[\w.@%+=,~-]*)*")
_USER_STRONG = re.compile(r"(?:[Aa]ccount '|[Cc]uenta '|[Uu]ser: |[Uu]suario: |user=|usuario=|uid=\d+\()"
                          r"([a-z_][a-z0-9_.-]*\$?)(?![\w/-])")
_USER_WEAK = re.compile(r"\b(?:as|by|como|por) ([a-z_][a-z0-9_.-]*)(?![\w/-])")
_TRAILING = ".,;:)"


def enabled(stream=None) -> bool:
    force = os.environ.get("ARX_COLOR", "").strip().lower()
    if force in ("never", "no", "off", "0", "false"):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if force in ("always", "yes", "on", "1", "true"):
        return True
    s = sys.stdout if stream is None else stream
    try:
        return bool(s.isatty()) and os.environ.get("TERM") != "dumb"
    except (AttributeError, ValueError, OSError):
        return False


def paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}{RESET}" if text else text


def user(name: str, stream=None) -> str:
    return paint(BLUE, name) if enabled(stream) else name


def command(text: str, stream=None) -> str:
    return paint(YELLOW, text) if enabled(stream) else text


def path(text: str, stream=None) -> str:
    return paint(GREEN, text) if enabled(stream) else text


# ── gramática de la CLI ──────────────────────────────────────────────────────
def grammar(parser) -> dict:
    """{subcomando: {"actions": {acción: spec}, "pos": n, "valued": {…}, "flags": {…}}} desde argparse."""
    import argparse

    def spec(p) -> dict:
        out = {"actions": {}, "pos": 0, "valued": set(), "flags": set()}
        for a in p._actions:
            if isinstance(a, argparse._SubParsersAction):
                out["actions"] = {name: spec(sp) for name, sp in a.choices.items()}
            elif a.option_strings:
                if a.dest != "help":
                    out["flags"].update(o for o in a.option_strings if o.startswith("--"))
                if a.nargs != 0:
                    out["valued"].update(a.option_strings)
            elif a.dest != "help":
                out["pos"] += 1
        return out

    return spec(parser)["actions"]


def _spans(text: str, gram: dict) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e, _ in spans)

    for m in _ARX.finditer(text):
        rest = text[m.end() + 1:]
        sub = _TOKEN.match(rest)
        name = sub.group(0).rstrip(_TRAILING) if sub else ""
        if name not in gram or not free(m.start(), m.end()):
            continue
        spans.append((m.start(), _arx_end(text, m.end() + 1, name, gram), YELLOW))
    for m in _SYSTEM.finditer(text):
        if free(m.start(), m.end()):
            spans.append((m.start(), _system_end(text, m.end()), YELLOW))
    for m in _USER_STRONG.finditer(text):
        if free(m.start(1), m.end(1)):
            spans.append((m.start(1), m.end(1), BLUE))
    for m in _USER_WEAK.finditer(text):
        if free(m.start(1), m.end(1)) and _is_local_user(m.group(1)):
            spans.append((m.start(1), m.end(1), BLUE))
    for m in _PATH.finditer(text):
        a, b = m.start(), m.end()
        while b > a + 1 and text[b - 1] in _TRAILING:
            b -= 1
        if free(a, b):
            spans.append((a, b, GREEN))
    return sorted(spans)


def _arx_end(text: str, i: int, name: str, gram: dict) -> int:
    """`i` apunta al subcomando. Sigue la gramática: acción, opciones (y su valor) y posicionales."""
    m = _TOKEN.match(text, i)
    end = i + len(name)
    if m and m.group(0) != name:  # subcomando con puntuación pegada: «arx setup)»
        return end
    spec, pos, want_value = gram[name], 0, False
    acted = not spec["actions"]
    j = end
    while j < len(text) and text[j] == " " and not text.startswith("  ", j):
        m = _TOKEN.match(text, j + 1)
        if not m:
            break
        tok = m.group(0)
        core = tok.rstrip(_TRAILING) or tok
        if want_value:
            want_value = False
        elif not acted and core in spec["actions"]:
            spec, acted = spec["actions"][core], not spec["actions"][core]["actions"]
            pos = 0
        elif _FLAG.fullmatch(core):
            want_value = core.split("=")[0] in spec["valued"] and "=" not in core
        elif _PLACEHOLDER.fullmatch(core) and (pos < spec["pos"] or not acted):
            pos += 1
        elif acted and pos < spec["pos"]:
            pos += 1
        else:
            break
        end = m.start() + len(core)
        j = m.end()
        if len(core) != len(tok):
            break
    return end


def _system_end(text: str, i: int) -> int:
    end = i
    j = i
    while j < len(text):
        m = _TOKEN.match(text, j)
        if not m or m.group(0) == "&&":
            break
        tok = m.group(0)
        core = tok.rstrip(_TRAILING) or tok
        end = m.start() + len(core)
        if len(core) != len(tok):
            break
        j = m.end()
        if j >= len(text) or text.startswith("  ", j) or text[j] != " ":
            break
        j += 1
    return end


_users: dict[str, bool] = {}


def _is_local_user(name: str) -> bool:
    if name not in _users:
        try:
            import pwd
            pwd.getpwnam(name)
            _users[name] = True
        except (ImportError, KeyError):
            _users[name] = False
    return _users[name]


def highlight(line: str, gram: dict | None = None) -> str:
    """Pinta comandos, usuarios y rutas en el texto que aún no lleva color; respeta el que ya tiene."""
    gram = gram or {}
    out, plain, pos = [], True, 0
    for m in _ANSI.finditer(line):
        seg = line[pos:m.start()]
        out.append(_paint_segment(seg, gram) if plain else seg)
        code = m.group(0)
        out.append(code)
        plain = code in ("\x1b[0m", "\x1b[m", "\x1b[39m")
        pos = m.end()
    seg = line[pos:]
    out.append(_paint_segment(seg, gram) if plain else seg)
    return "".join(out)


def _paint_segment(text: str, gram: dict) -> str:
    if not text.strip():
        return text
    out, last = [], 0
    for a, b, code in _spans(text, gram):
        out.append(text[last:a])
        out.append(paint(code, text[a:b]))
        last = b
    out.append(text[last:])
    return "".join(out)


class Painter(io.TextIOBase):
    """Envuelve stdout: pinta cada línea completa al escribirla en la terminal."""

    def __init__(self, raw, gram: dict):
        self._raw, self._gram, self._buf = raw, gram, ""

    def write(self, s: str) -> int:
        self._buf += s
        if "\n" in self._buf:
            done, self._buf = self._buf.rsplit("\n", 1)
            self._raw.write("\n".join(highlight(line, self._gram) for line in done.split("\n")) + "\n")
        return len(s)

    def flush(self) -> None:
        if self._buf:
            self._raw.write(highlight(self._buf, self._gram))
            self._buf = ""
        self._raw.flush()

    def isatty(self) -> bool:
        return self._raw.isatty()

    def fileno(self) -> int:
        return self._raw.fileno()

    @property
    def encoding(self):
        return getattr(self._raw, "encoding", None) or "utf-8"

    @property
    def errors(self):  # input() solo usa readline si es un str: sin esto, la consola pierde Tab e historial
        return getattr(self._raw, "errors", None) or "strict"

    def __getattr__(self, name):
        return getattr(self._raw, name)


def install(gram: dict) -> bool:
    """Pinta stdout desde aquí si va a una terminal. Idempotente."""
    if isinstance(sys.stdout, Painter):
        sys.stdout._gram = gram
        return True
    if not enabled():
        return False
    sys.stdout = Painter(sys.stdout, gram)
    return True
