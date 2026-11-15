"""Significado de la configuración crítica (B77): qué cambia de verdad, no qué bytes cambian.

Un hash de fichero no distingue un `sources.list` vacío recién creado de un repositorio sin firma: los dos
«cambian apt_sources». Estos analizadores reducen cada fichero a lo que el sistema hará con él (los
repositorios que APT usará, las órdenes que systemd ejecutará, las claves que sshd aceptará) y `classify`
compara ese significado antes y después.

Funciones puras: sin E/S, deterministas y sin excepciones. Lo que controla un atacante entra aquí, así que una
entrada que no se puede entender nunca se da por buena ni se ignora: vuelve como `Parsed(ok=False)` y el
llamador la trata como un cambio que hay que mirar.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from arx.i18n import tr

MAX_TEXT = 1_000_000   # 1 MB de configuración ya es sospechoso por sí mismo
MAX_ITEMS = 5_000      # repos, directivas, claves o líneas por fichero


@dataclass(frozen=True)
class Parsed:
    ok: bool
    canon: tuple | None = None
    reason: str = ""


@dataclass(frozen=True)
class Change:
    sev: str            # crit | high | med | low
    summary: str
    added: tuple = ()
    removed: tuple = ()


def _guard(text) -> str | None:
    """Motivo para no analizar, o None si el texto es analizable."""
    if not isinstance(text, str):
        return "not text"
    if len(text) > MAX_TEXT:
        return "too large"
    if "\x00" in text:
        return "binary content"
    return None


def _safe(fn):
    def wrapper(text, *args, **kwargs) -> Parsed:
        why = _guard(text)
        if why:
            return Parsed(False, None, why)
        try:
            out = fn(text, *args, **kwargs)
        except RecursionError:
            return Parsed(False, None, "too deep")
        except Exception as e:  # noqa: BLE001 - nunca se cae por lo que escribe un atacante
            return Parsed(False, None, f"unparseable ({type(e).__name__})")
        if out.ok and out.canon is not None and len(out.canon) > MAX_ITEMS:
            return Parsed(False, None, "too many items")
        return out
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


def digest(p: Parsed) -> str | None:
    """Huella estable del significado (None si no se pudo analizar)."""
    if not p.ok:
        return None
    return hashlib.sha256(repr(p.canon).encode("utf-8", "backslashreplace")).hexdigest()


# ── APT: fuentes ─────────────────────────────────────────────────────────────
def _norm_uri(uri: str) -> str:
    uri = uri.strip()
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/]*)(.*)$", uri)
    if m:
        uri = f"{m.group(1).lower()}://{m.group(2).lower()}{m.group(3)}"
    return uri.rstrip("/") or uri


def _yes(v: str) -> bool | None:
    v = v.strip().lower()
    if v in ("yes", "true", "1", "with"):
        return True
    if v in ("no", "false", "0", "without"):
        return False
    return None


def _signed_by(v: str) -> str:
    """Rutas o huellas, ordenadas; una clave en línea se reduce a su hash (el bloque no importa, la clave sí)."""
    v = v.strip()
    if "BEGIN PGP" in v:
        block = "\n".join(line.strip() for line in v.splitlines() if line.strip() and line.strip() != ".")
        return "inline:" + hashlib.sha256(block.encode()).hexdigest()[:16]
    parts = sorted({p for p in re.split(r"[\s,]+", v) if p})
    return ",".join(parts)


def _repo(kind: str, uri: str, suite: str, comps, opts: dict) -> tuple:
    other = tuple(sorted((k, v) for k, v in opts.items() if k not in ("signed-by", "trusted", "arch")))
    return (kind, _norm_uri(uri), suite.strip(), tuple(sorted(set(comps))),
            _signed_by(opts.get("signed-by", "")), _yes(opts.get("trusted", "")) is True,
            tuple(sorted({a for a in re.split(r"[\s,]+", opts.get("arch", "")) if a})), other)


def _strip_comment(line: str) -> str:
    return re.split(r"(?:^|\s)#", line, maxsplit=1)[0].strip()


@_safe
def apt_sources(text: str, deb822: bool = False) -> Parsed:
    """Repositorios que APT usará. Vacío o solo comentarios = ningún repositorio (igual que si no existiera)."""
    repos = []
    if not deb822:
        for raw in text.splitlines():
            line = _strip_comment(raw)
            if not line:
                continue
            m = re.match(r"^(deb|deb-src)\s+(?:\[([^\]]*)\]\s+)?(\S+)\s+(\S+)\s*(.*)$", line)
            if not m:
                return Parsed(False, None, "unrecognized line")
            opts = {}
            for item in (m.group(2) or "").split():
                k, sep, v = item.partition("=")
                if not sep:
                    return Parsed(False, None, "bad option")
                k = k.lower().rstrip("+-")
                opts[k] = (opts[k] + "," + v) if k in opts else v
            repos.append(_repo(m.group(1), m.group(3), m.group(4), m.group(5).split(), opts))
        return Parsed(True, tuple(sorted(set(repos))))
    for stanza in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        key = None
        for raw in stanza.splitlines():
            if raw.lstrip().startswith("#"):
                continue
            if raw[:1] in (" ", "\t") and key:
                fields[key] += "\n" + raw.strip()
                continue
            if not raw.strip():
                continue
            k, sep, v = raw.partition(":")
            if not sep or not k.strip() or " " in k.strip():
                return Parsed(False, None, "bad field")
            key = k.strip().lower()
            fields[key] = v.strip()
        if not fields:
            continue
        if _yes(fields.get("enabled", "yes")) is False:
            continue  # APT no la usa
        types, uris, suites = (fields.get(k, "").split() for k in ("types", "uris", "suites"))
        if not (types and uris and suites):
            return Parsed(False, None, "incomplete stanza")
        opts = {"signed-by": fields.get("signed-by", ""), "trusted": fields.get("trusted", ""),
                "arch": fields.get("architectures", "")}
        for k in ("pdiffs", "by-hash", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure",
                  "check-valid-until", "check-date"):
            if k in fields:
                opts[k] = fields[k].lower()
        for t in types:
            if t not in ("deb", "deb-src"):
                return Parsed(False, None, "unknown type")
            for u in uris:
                for s in suites:
                    repos.append(_repo(t, u, s, fields.get("components", "").split(), opts))
    return Parsed(True, tuple(sorted(set(repos))))


_INSECURE_OPTS = ("allow-insecure", "allow-weak", "allow-downgrade-to-insecure")


def _repo_risky(r: tuple) -> bool:
    """Sin comprobación de firma: `trusted=yes` u opciones que aceptan repositorios inseguros."""
    _kind, _uri, _suite, _comps, _signed, trusted, _arch, other = r
    return trusted or any(k in _INSECURE_OPTS and _yes(v) for k, v in other)


# ── APT: apt.conf ────────────────────────────────────────────────────────────
_DANGER_TRUE = ("apt::get::allowunauthenticated", "acquire::allowinsecurerepositories",
                "acquire::allowdowngradetoinsecurerepositories", "acquire::allowweakrepositories")
_DANGER_FALSE_SUFFIX = ("::verify-peer", "::verify-host")
_HOOK_SUFFIX = ("::pre-invoke", "::post-invoke", "::post-invoke-success", "::pre-install-pkgs")
_DANGER_PREFIX = ("dir::bin::", "dir::etc::sourcelist", "dir::etc::sourceparts", "dir::etc::trusted",
                  "dir::etc::parts", "dir::etc::main", "apt::key::")
_HIGH_PREFIX = ("dpkg::options", "dpkg::tools::", "dir::", "apt::key-assert", "apt::key::assert-pubkey-algo")


def _conf_tokens(text: str) -> list[tuple[str, str]]:
    """Fichas de apt.conf como las lee APT: fuera de comillas, `//` y `#` comentan hasta el final de la línea
    (salvo `#include`/`#clear`, que son directivas) y `/* … */` comenta aunque abarque líneas. Dentro de
    comillas nada de eso cuenta: un `/*` en una cadena no puede esconder lo que viene detrás."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif c == '"':
            j = text.find('"', i + 1)
            if j < 0:
                raise ValueError("unterminated string")
            out.append(("str", text[i + 1:j]))
            i = j + 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ValueError("unterminated comment")
            i = j + 2
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "#":
            m = re.match(r"#(include|clear)\b", text[i:i + 9])
            if m:  # directiva: su argumento llega hasta `;` o hasta el final de la línea
                i += len(m.group(0))
                ends = [k for k in (text.find(";", i), text.find("\n", i)) if k >= 0]
                end = min(ends) if ends else n
                out += [("dir", "#" + m.group(1)), ("str", text[i:end].strip().strip('"')), (";", ";")]
                i = end + 1 if end < n and text[end] == ";" else end
            else:
                j = text.find("\n", i)
                i = n if j < 0 else j
        elif c in "{};":
            out.append((c, c))
            i += 1
        else:
            j = i
            while j < n and text[j] not in ' \t\r\n{};"#' and not text.startswith(("//", "/*"), j):
                j += 1
            out.append(("word", text[i:j]))
            i = j
    return out


@_safe
def apt_conf(text: str) -> Parsed:
    """Directivas de apt.conf aplanadas: (clave en minúsculas, valor)."""
    scope, pending, items = [], [], []
    for kind, val in _conf_tokens(text):
        if kind in ("word", "str", "dir"):
            pending.append((kind, val))
        elif kind == "{":
            if len(pending) != 1 or pending[0][0] != "word":
                return Parsed(False, None, "bad scope")
            scope.append(pending[0][1].lower())
            pending = []
            if len(scope) > 32:
                return Parsed(False, None, "too deep")
        elif kind == "}":
            if not scope or pending:
                return Parsed(False, None, "unbalanced")
            scope.pop()
        else:  # ";"
            if not pending:
                continue  # `};` cierra un ámbito
            if pending[0][0] == "dir":
                items.append((pending[0][1], " ".join(v for _k, v in pending[1:])))
                pending = []
                continue
            words = [v for k, v in pending if k == "word"]
            values = [v for k, v in pending if k == "str"]
            pending = []
            if len(words) > 1:
                return Parsed(False, None, "bad directive")
            key = "::".join(scope + ([words[0].lower()] if words else []))
            for v in values or [""]:
                items.append((key, v))
    if scope or pending:
        return Parsed(False, None, "unbalanced")
    return Parsed(True, tuple(sorted(set(items))))


def _conf_risk(item: tuple) -> str | None:
    """crit: ejecuta órdenes, se salta firmas o redirige binarios/fuentes; high: cambia cómo actúa dpkg."""
    key, value = item
    v = _yes(value)
    if key.startswith("#include"):
        return "crit"
    if key in _DANGER_TRUE:
        return "crit" if v is True else None
    if key.startswith("acquire::") and key.endswith(_DANGER_FALSE_SUFFIX):
        return "crit" if v is False else None
    if key.endswith(_HOOK_SUFFIX) or key.startswith(_DANGER_PREFIX):
        return "crit"
    if key.startswith(_HIGH_PREFIX):
        return "high"
    if key.startswith("acquire::") and key.endswith("::check-valid-until") and v is False:
        return "med"
    return None


# ── systemd ──────────────────────────────────────────────────────────────────
_UNIT_SENSITIVE = {
    "execstart", "execstartpre", "execstartpost", "execstop", "execstoppost", "execreload", "execcondition",
    "user", "group", "supplementarygroups", "environment", "environmentfile", "passenvironment",
    "ambientcapabilities", "capabilityboundingset", "dynamicuser", "rootdirectory", "rootimage",
    "listenstream", "listendatagram", "listenseqpacket", "listenfifo", "listennetlink", "accept",
    "unit", "pathchanged", "pathmodified", "pathexists", "pathexistsglob", "directorynotempty",
    "oncalendar", "onbootsec", "onactivesec", "onunitactivesec", "onunitinactivesec", "onstartupsec",
    "onclockchange", "ontimezonechange", "what", "where",
    # dependencias que arrancan otra unidad (persistencia sin tocar Exec*)
    "wants", "requires", "requisite", "bindsto", "upholds", "onfailure", "onsuccess",
    # dónde y con qué se ejecuta
    "execsearchpath", "bindpaths", "bindreadonlypaths", "temporaryfilesystem", "mountimages",
    "extensionimages", "extensiondirectories", "workingdirectory", "umask", "setcredential", "loadcredential",
}


@_safe
def systemd_unit(text: str) -> Parsed:
    """(sección, clave, valor) en orden: dos `ExecStartPre` cuentan, y en orden."""
    items, section, parts = [], None, []
    for raw in text.splitlines():
        piece = raw.strip()
        if piece.endswith("\\"):
            parts.append(piece[:-1])
            continue
        line = " ".join(parts + [piece]) if parts else piece
        parts = []
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        k, sep, v = line.partition("=")
        if not sep or not k.strip() or section is None:
            return Parsed(False, None, "bad line")
        items.append((section, k.strip().lower(), " ".join(v.split())))
    if parts:
        return Parsed(False, None, "dangling continuation")
    return Parsed(True, tuple(items))


def _unit_sensitive(item: tuple) -> bool:
    _section, key, value = item
    low = value.lower()
    return key in _UNIT_SENSITIVE or "ld_preload" in low or "ld_library_path" in low


# ── SSH: authorized_keys ─────────────────────────────────────────────────────
_KEY_TOKEN = re.compile(r"^[a-z0-9][a-z0-9.-]*(?:@[a-z0-9.-]+)?$")


def _blob(b64: str) -> tuple[str, str] | None:
    """(tipo declarado dentro del blob, huella) si `b64` es una clave pública SSH; None si no."""
    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(blob) < 16:
        return None
    n = int.from_bytes(blob[:4], "big")
    if not 0 < n <= 64 or len(blob) < 4 + n:
        return None
    try:
        kind = blob[4:4 + n].decode("ascii")
    except UnicodeDecodeError:
        return None
    return kind, "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _key_at(parts: list[str]) -> tuple[str, str] | None:
    """Si `parts` empieza por «tipo blob» y el blob declara ese mismo tipo, (tipo, huella). Así se reconoce
    cualquier tipo que sshd acepte (certificados, sk-, los futuros) sin depender de una lista."""
    if len(parts) < 2 or not _KEY_TOKEN.match(parts[0]):
        return None
    found = _blob(parts[1])
    if found and found[0] == parts[0]:
        return parts[0], found[1]
    return None


def _split_options(line: str) -> tuple[str, str]:
    """Separa las opciones (que pueden llevar comillas con espacios) del resto."""
    quoted, i = False, 0
    while i < len(line):
        c = line[i]
        if c == "\\" and quoted:
            i += 2
            continue
        if c == '"':
            quoted = not quoted
        elif c in " \t" and not quoted:
            return line[:i], line[i:].strip()
        i += 1
    return line, ""


@_safe
def authorized_keys(text: str) -> Parsed:
    """Claves que sshd aceptará, por huella, con sus opciones. Una línea que no es una clave también cuenta
    (por su hash): sshd la ignora, pero su aparición se ve."""
    keys = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        opts = ""
        key = _key_at(line.split())
        if key is None:
            opts, rest = _split_options(line)
            key = _key_at(rest.split())
        if key:
            keys.add(("key", key[0], key[1], ",".join(sorted(o.strip() for o in _split_csv(opts)))))
        else:
            keys.add(("raw", hashlib.sha256(raw.strip().encode()).hexdigest()[:16], "", ""))
    return Parsed(True, tuple(sorted(keys)))


def _split_csv(opts: str) -> list[str]:
    out, cur, quoted = [], [], False
    for c in opts:
        if c == '"':
            quoted = not quoted
        if c == "," and not quoted:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur))
    return [o for o in out if o.strip()]


# ── líneas (cron, sudoers, ld.so.preload, passwd) ────────────────────────────
@_safe
def lines(text: str, sudoers: bool = False) -> Parsed:
    """Líneas con efecto: sin comentarios ni líneas vacías, espacios normalizados, en orden (en sudoers manda
    la última regla que coincide). En sudoers, `#include`/`@include` no son comentarios, y `#1000 ALL=…` es una
    regla para el uid 1000: tomarla por comentario escondería un permiso de root."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") and not (sudoers and re.match(r"^(?:#include(?:dir)?\s|#\d)", line)):
            continue
        out.append(" ".join(line.split()))
    return Parsed(True, tuple(out))


# ── clasificación ────────────────────────────────────────────────────────────
_ANALYZERS = {
    "apt_sources": apt_sources, "apt_conf": apt_conf, "systemd": systemd_unit,
    "authorized_keys_root": authorized_keys, "authorized_keys_users": authorized_keys,
    "sudoers": lines, "sudoers_d": lines, "ld_preload": lines, "cron": lines, "passwd": lines,
    "rc_local": lines, "shell_init": lines, "ld_conf": lines,
}


def analyze(group: str, text, deb822: bool = False) -> Parsed:
    """Analizador del grupo; los grupos sin significado propio (claves APT) se comparan por contenido."""
    if group == "apt_sources":
        return apt_sources(text, deb822)
    if group in ("sudoers", "sudoers_d"):
        return lines(text, sudoers=True)
    fn = _ANALYZERS.get(group)
    if fn is None:  # sin significado propio (claves APT, a menudo binarias): por contenido
        data = text if isinstance(text, bytes) else str(text).encode("utf-8", "backslashreplace")
        if len(data) > MAX_TEXT:
            return Parsed(False, None, "too large")
        return Parsed(True, (hashlib.sha256(data).hexdigest(),))
    return fn(text)


def _diff(before: Parsed | None, after: Parsed | None) -> tuple[tuple, tuple]:
    a = set(after.canon) if after and after.ok else set()
    b = set(before.canon) if before and before.ok else set()
    return tuple(sorted(a - b, key=repr)), tuple(sorted(b - a, key=repr))


def _short(items, n: int = 3) -> str:
    def one(x):
        if isinstance(x, tuple):
            if len(x) == 8:   # repo
                return f"{x[0]} {x[1]} {x[2]}"
            if len(x) == 4 and x[0] == "key":
                return f"{x[1]} {x[2]}"
            if len(x) == 3:   # unidad
                return f"[{x[0]}] {x[1]}={x[2][:60]}"
            if len(x) == 2:
                return f"{x[0]}={x[1][:60]}"
        return str(x)[:80]
    shown = ", ".join(one(x) for x in list(items)[:n])
    return shown + (f" (+{len(items) - n})" if len(items) > n else "")


def classify(group: str, before: Parsed | None, after: Parsed | None) -> Change | None:
    """¿Cambió lo que el sistema hará? None si no. `before`/`after` None = el fichero no existía."""
    if after is not None and not after.ok:
        if before is not None and not before.ok:
            return None  # seguía ilegible igual: lo decide el hash crudo del llamador
        return Change("high", tr("the file can no longer be understood ({why}): review it by hand",
                                 why=after.reason))
    added, removed = _diff(before, after)
    if not added and not removed:
        if before is not None and before.ok and after is not None and before.canon != after.canon:
            sev = "high" if group in ("sudoers", "sudoers_d") else "med"
            return Change(sev, tr("the order of entries changed"))
        return None
    if group == "apt_sources":
        risky = [r for r in added if _repo_risky(r)]
        if risky:
            return Change("crit", tr("APT repository without signature check: {repos}", repos=_short(risky)),
                          added, removed)
        if added:
            new_uris = {r[1] for r in added} - {r[1] for r in removed}
            if new_uris:
                # La prueba de procedencia confía en lo que llega firmado de un repositorio: uno nuevo es una
                # fuente de confianza nueva, la vía de entrada de un paquete envenenado que pasaría por bueno.
                unsigned = [r for r in added if not r[4]]
                if unsigned:
                    return Change("crit", tr("new APT repository, accepted with any key the system trusts: {repos}",
                                             repos=_short(unsigned)), added, removed)
                return Change("crit", tr("new APT repository: {repos}", repos=_short(added)), added, removed)
            return Change("med", tr("APT repository options changed: {repos}", repos=_short(added)), added, removed)
        return Change("low", tr("APT repository removed: {repos}", repos=_short(removed)), added, removed)
    if group == "apt_conf":
        risks = {i: _conf_risk(i) for i in added}
        for sev in ("crit", "high", "med"):
            hit = [i for i, r in risks.items() if r == sev]
            if hit and sev == "crit":
                return Change("crit", tr("APT setting that runs commands or skips signatures: {items}",
                                         items=_short(hit)), added, removed)
            if hit:
                return Change(sev, tr("APT setting that changes how packages are installed: {items}",
                                      items=_short(hit)), added, removed)
        return Change("low", tr("APT setting changed: {items}", items=_short(added or removed)), added, removed)
    if group == "systemd":
        if after is None:
            return Change("med", tr("systemd unit removed"), added, removed)
        if before is None:  # una unidad o un drop-in nuevos: candidatos a persistencia aunque no lleven Exec*
            return Change("high", tr("new systemd unit or drop-in: {items}", items=_short(added)), added, removed)
        sens = [i for i in added if _unit_sensitive(i)] + [i for i in removed if _unit_sensitive(i)]
        if sens:
            return Change("high", tr("what systemd runs changed: {items}", items=_short(sens)), added, removed)
        return Change("med", tr("systemd setting changed: {items}", items=_short(added or removed)), added, removed)
    if group in ("authorized_keys_root", "authorized_keys_users"):
        new_keys = [k for k in added if k[0] == "key"]
        changed_opts = {k[2] for k in new_keys} & {k[2] for k in removed if k[0] == "key"}
        if new_keys and not changed_opts:
            sev = "crit" if group == "authorized_keys_root" else "high"
            return Change(sev, tr("new SSH key accepted: {keys}", keys=_short(new_keys)), added, removed)
        if new_keys:
            return Change("high", tr("SSH key options changed: {keys}", keys=_short(new_keys)), added, removed)
        if added:  # sshd no la toma por clave, pero en el fichero de root nada debería aparecer sin más
            return Change("high" if group == "authorized_keys_root" else "med",
                          tr("unrecognized line in authorized_keys"), added, removed)
        return Change("low", tr("SSH key removed: {keys}", keys=_short(removed)), added, removed)
    if group in ("sudoers", "sudoers_d", "ld_preload"):
        if added:
            return Change("crit", tr("{group} grants something new: {items}", group=group, items=_short(added)),
                          added, removed)
        return Change("med", tr("{group} lost entries: {items}", group=group, items=_short(removed)), added, removed)
    if group == "cron":
        if added:
            return Change("high", tr("new scheduled command: {items}", items=_short(added)), added, removed)
        return Change("low", tr("scheduled command removed: {items}", items=_short(removed)), added, removed)
    if group in ("rc_local", "shell_init", "ld_conf"):
        what = {"rc_local": tr("runs as root at every boot"), "shell_init": tr("runs in every login shell"),
                "ld_conf": tr("changes where every program loads its libraries from")}[group]
        if added:
            return Change("high", tr("new line in a file that {what}: {items}", what=what, items=_short(added)),
                          added, removed)
        return Change("low", tr("line removed from a file that {what}: {items}", what=what, items=_short(removed)),
                      added, removed)
    if group == "passwd":
        return Change("high" if added else "med", tr("accounts changed: {items}", items=_short(added or removed)),
                      added, removed)
    if group == "apt_keys":
        if added:
            return Change("crit", tr("new APT signing key"), added, removed)
        return Change("low", tr("APT signing key removed"), added, removed)
    return Change("high", tr("{group} changed", group=group), added, removed)
