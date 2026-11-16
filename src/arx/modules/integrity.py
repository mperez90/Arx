"""Integridad de la configuración crítica, fichero a fichero (B77) y con conocimiento de las piezas de Arx (B73).

Antes: un hash por grupo de ficheros. Un `sources.list` vacío nuevo cambiaba «apt_sources» igual que un
repositorio sin firma, y la alerta no decía qué fichero, qué cambió ni cómo. Ahora cada fichero tiene su
estado (contenido, significado según `cfgsem`, permisos, dueño, destino si es un enlace) y se compara por
separado: la alerta dice qué fichero, qué significa el cambio y trae el diff contra la copia buena.

Lo que escribe el propio Arx (sus unidades de systemd y sus drop-ins) está en un manifiesto con su contenido
esperado: si coincide, no es un hallazgo; si no coincide, alguien ha tocado a Arx.

Todo lo que se lee lo controla un atacante: sin seguir enlaces al leer, sin bloquearse en un FIFO, con
límite de tamaño y de número de ficheros.
"""
from __future__ import annotations

import difflib
import glob
import hashlib
import os
import stat
import time

from arx import config, redact
from arx.i18n import tr
from arx.modules import cfgsem

MAX_FILES_PER_GROUP = 2_000
MAX_HASH = 64 << 20   # se hashea entero hasta aquí: añadir detrás del primer MB no puede pasar inadvertido
FULL_RECHECK_S = 3600  # aunque nada parezca cambiar, todo se relee y se rehashea al menos una vez por hora
MAX_DIFF_LINES = 40
OWN_MANIFEST = "own-artifacts.json"

_SYSTEMD_DIRS = ("/etc/systemd/system", "/usr/local/lib/systemd/system")
_UNIT_EXT = (".service", ".timer", ".socket", ".path", ".mount", ".automount", ".target")


def _systemd_paths() -> list[str]:
    out = []
    for d in _SYSTEMD_DIRS:
        for ext in _UNIT_EXT:
            out += glob.glob(f"{d}/*{ext}")
        out += glob.glob(f"{d}/*.d/*.conf")           # drop-ins: persistencia clásica (ExecStartPre=…)
        out += glob.glob(f"{d}/*.wants/*") + glob.glob(f"{d}/*.requires/*")  # enlaces que habilitan
    for d in ("/etc/systemd/system-generators", "/usr/local/lib/systemd/system-generators"):
        out += glob.glob(f"{d}/*")
    return out


GROUP_NAMES = ("authorized_keys_root", "authorized_keys_users", "sudoers", "sudoers_d", "passwd", "ld_preload",
               "cron", "systemd", "apt_sources", "apt_conf", "apt_keys", "rc_local", "shell_init", "ld_conf")
# Grupos que se vigilan desde después de la primera base por fichero (0.0.9rc3): una base de entonces no guarda
# `meta.integrity_groups` y no los conocía. Sus ficheros no son «nuevos» al actualizar: ya estaban (piloto A).
ADDED_AFTER_PER_FILE = frozenset({"rc_local", "shell_init", "ld_conf"})


def known_groups(meta: dict) -> set[str]:
    """Los grupos que vigilaba Arx cuando se selló (o se adoptó por última vez) la base."""
    recorded = meta.get("integrity_groups")
    if isinstance(recorded, list):
        return set(recorded)
    return set(GROUP_NAMES) - ADDED_AFTER_PER_FILE


def groups() -> dict[str, list[str]]:
    """Grupo → rutas candidatas (existan o no). El grupo decide cómo se entiende el contenido."""
    home_keys = [f"{h}/.ssh/{n}" for h in glob.glob("/home/*") for n in ("authorized_keys", "authorized_keys2")]
    return {
        "authorized_keys_root": ["/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"],
        "authorized_keys_users": home_keys,
        "sudoers": ["/etc/sudoers"],
        "sudoers_d": glob.glob("/etc/sudoers.d/*"),
        "passwd": ["/etc/passwd"],
        "ld_preload": ["/etc/ld.so.preload"],
        "cron": ["/etc/crontab", *glob.glob("/etc/cron.d/*"), *glob.glob("/var/spool/cron/crontabs/*"),
                 *(p for d in ("hourly", "daily", "weekly", "monthly") for p in glob.glob(f"/etc/cron.{d}/*"))],
        "systemd": _systemd_paths(),
        "apt_sources": ["/etc/apt/sources.list", *glob.glob("/etc/apt/sources.list.d/*")],
        "apt_conf": ["/etc/apt/apt.conf", *glob.glob("/etc/apt/apt.conf.d/*")],
        "apt_keys": ["/etc/apt/trusted.gpg", *glob.glob("/etc/apt/trusted.gpg.d/*"), *glob.glob("/etc/apt/keyrings/*")],
        # persistencias clásicas que no pasan por systemd ni cron (HZ#M3-6: rc-local.service ejecuta /etc/rc.local)
        "rc_local": ["/etc/rc.local"],
        "shell_init": ["/etc/profile", *glob.glob("/etc/profile.d/*"), "/etc/bash.bashrc", "/etc/environment",
                       "/root/.bashrc", "/root/.profile", "/root/.bash_profile", "/root/.bash_login"],
        "ld_conf": ["/etc/ld.so.conf", *glob.glob("/etc/ld.so.conf.d/*")],
    }


def _read_safely(path: str) -> tuple[dict | None, bytes | None]:
    """(metadatos, contenido) sin seguir enlaces ni bloquearse. (None, None) si no existe.

    El contenido devuelto es el primer MB (lo que se analiza); `meta` lleva el tamaño y el sha256 del fichero
    ENTERO (hasta MAX_HASH), para que lo añadido detrás también cambie la huella."""
    try:
        st = os.lstat(path)
    except OSError:
        return None, None
    meta = {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
    if stat.S_ISLNK(st.st_mode):
        try:
            meta["link"] = os.readlink(path)
        except OSError:
            meta["link"] = "?"
        return meta, None
    if not stat.S_ISREG(st.st_mode):
        meta["special"] = stat.S_IFMT(st.st_mode)  # un FIFO o un dispositivo donde va configuración
        return meta, None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return meta, None
    with os.fdopen(fd, "rb") as f:
        fst = os.fstat(f.fileno())
        if not stat.S_ISREG(fst.st_mode):
            return meta, None
        data = f.read(cfgsem.MAX_TEXT + 1)
        h, seen = hashlib.sha256(data), len(data)
        while seen < MAX_HASH and (chunk := f.read(min(1 << 20, MAX_HASH - seen))):
            h.update(chunk)
            seen += len(chunk)
    meta["size"] = fst.st_size
    meta["full_sha"] = h.hexdigest()
    return meta, data


def state_from(path: str, group: str, data: bytes, meta: dict) -> dict:
    """Estado de unos bytes conocidos (la copia de la bóveda), con los metadatos que se le den."""
    if group == "apt_keys":
        parsed = cfgsem.analyze(group, data)
    else:
        parsed = cfgsem.analyze(group, data.decode("utf-8", errors="replace"), deb822=path.endswith(".sources"))
    out = {"g": group, **meta, "at": time.time(), "sha": hashlib.sha256(data).hexdigest(), "ok": parsed.ok,
           "canon": _jsonable(parsed.canon) if parsed.ok else None}
    if not parsed.ok:
        out["reason"] = parsed.reason
    return out


def state(path: str, group: str) -> dict | None:
    """Estado de un fichero vigilado, apto para JSON. None si no existe."""
    meta, data = _read_safely(path)
    if meta is None:
        return None
    out = {"g": group, **meta, "at": time.time()}
    if data is None:
        out["sha"] = None
        out["ok"] = "link" in meta  # un enlace se compara por su destino; lo especial no se entiende
        out["canon"] = None
        return out
    out["sha"] = out.pop("full_sha", None) or hashlib.sha256(data).hexdigest()
    if group == "apt_keys":
        parsed = cfgsem.analyze(group, data)
    else:
        text = data.decode("utf-8", errors="replace")
        parsed = cfgsem.analyze(group, text, deb822=path.endswith(".sources"))
    out["ok"] = parsed.ok
    out["canon"] = _jsonable(parsed.canon) if parsed.ok else None
    if not parsed.ok:
        out["reason"] = parsed.reason
    return out


def _jsonable(x):
    if isinstance(x, (tuple, list)):
        return [_jsonable(i) for i in x]
    return x


def _tupled(x):
    if isinstance(x, list):
        return tuple(_tupled(i) for i in x)
    return x


# Caché por fichero para el barrido de cada 30 s: releer, hashear y analizar ~100 ficheros cada vez costaba un 2-3 %
# de CPU en reposo. Un fichero se relee si cambia su lstat (con ctime, que un `touch -r` no puede devolver a su
# valor), si auditd vio una escritura que la caché no conocía, o si pasó FULL_RECHECK_S desde la última lectura.
# Lo de auditd se compara por la IDENTIDAD del último evento (serie, arranque, pid, ejecutable), no por su fecha: con
# el reloj retrocedido una escritura nueva lleva una fecha vieja (HZ#8 de Q) y un filtro por fecha la dejaría fuera.
_cache: dict[str, tuple[tuple, dict, float, str | None]] = {}


def _last_writer(writers, path: str) -> str | None:
    if not writers:
        return None
    evs = writers(path, None)
    if not evs:
        return None
    last = evs[-1]
    return repr(tuple(last.get(k) for k in ("boot", "serial", "at", "pid", "exe")))


def _stat_key(path: str) -> tuple | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_uid, st.st_gid)


def clear_cache() -> None:
    _cache.clear()


def cached_state(path: str, group: str, writers=None, now: float | None = None) -> dict | None:
    """Como `state`, pero sin releer lo que no cambió. `writers(path, since)` invalida si auditd vio una escritura."""
    now = time.monotonic() if now is None else now
    key = _stat_key(path)
    if key is None:
        _cache.pop(path, None)
        return None
    hit = _cache.get(path)
    last = _last_writer(writers, path)
    if hit and hit[0] == key and hit[1].get("g") == group and now - hit[2] < FULL_RECHECK_S \
            and (hit[3] if len(hit) > 3 else None) == last:
        return hit[1]
    s = state(path, group)
    if s is not None:
        _cache[path] = (key, s, now, last)
    else:
        _cache.pop(path, None)
    return s


def snapshot(cached: bool = False, writers=None) -> tuple[dict[str, dict], list[str]]:
    """({ruta: estado}, grupos que superaron el límite de ficheros). `cached` para el barrido periódico; al sellar o
    aceptar se lee todo de nuevo."""
    out, overflow = {}, []
    for group, paths in groups().items():
        existing = sorted({p for p in paths if os.path.lexists(p)})
        if len(existing) > MAX_FILES_PER_GROUP:
            overflow.append(group)
            existing = existing[:MAX_FILES_PER_GROUP]
        for p in existing:
            s = cached_state(p, group, writers) if cached else state(p, group)
            if s is not None:
                out[p] = s
    if cached:
        for p in [p for p in _cache if p not in out]:
            _cache.pop(p, None)  # lo que ya no se vigila no ocupa memoria
    return out, overflow


# ── piezas propias de Arx (B73) ──────────────────────────────────────────────
def _own_path():
    return config.state_dir() / OWN_MANIFEST


def own_artifacts() -> dict[str, str]:
    """{ruta: sha256 esperado} de lo que Arx escribió en el sistema."""
    data = config.read_json(_own_path(), {})
    return {p: h for p, h in data.items() if isinstance(p, str) and isinstance(h, str)}


def register_own(path: str, content: str | bytes) -> None:
    raw = content.encode() if isinstance(content, str) else content
    data = own_artifacts()
    data[path] = hashlib.sha256(raw).hexdigest()
    config.write_json(_own_path(), data)


def forget_own(path: str) -> None:
    data = own_artifacts()
    if data.pop(path, None) is not None:
        config.write_json(_own_path(), data)


# ── comparación ──────────────────────────────────────────────────────────────
def _parsed(s: dict | None) -> cfgsem.Parsed | None:
    if s is None:
        return None
    if s.get("ok") and s.get("canon") is not None:
        return cfgsem.Parsed(True, _tupled(s["canon"]))
    if s.get("ok"):
        return cfgsem.Parsed(True, ())
    return cfgsem.Parsed(False, None, s.get("reason", "unreadable"))


def _loosened(before: dict, after: dict) -> bool:
    """¿Ahora puede escribirlo alguien más, o cambió de dueño?"""
    if before.get("uid") != after.get("uid") or before.get("gid") != after.get("gid"):
        return True
    return bool((after.get("mode", 0) & 0o022) & ~(before.get("mode", 0) & 0o022))


def unified_diff(path: str, good: bytes | None, now: bytes | None) -> str:
    """Diff redactado y acotado entre la copia buena y lo que hay ahora (vacío si no se puede)."""
    if good is None and now is None:
        return ""
    a = (good or b"").decode("utf-8", errors="replace").splitlines()
    b = (now or b"").decode("utf-8", errors="replace").splitlines()
    lines = list(difflib.unified_diff(a, b, f"{path} (sellado)", f"{path} (ahora)", lineterm="", n=1))
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES] + [tr("… ({n} more lines)", n=len(lines) - MAX_DIFF_LINES)]
    return redact.scrub("\n".join(lines))


def existing() -> dict[str, list[str]]:
    """Grupo → ficheros regulares que existen (para la copia buena en la bóveda)."""
    out = {}
    for group, paths in groups().items():
        files = sorted({p for p in paths if os.path.isfile(p) and not os.path.islink(p)})[:MAX_FILES_PER_GROUP]
        if files:
            out[group] = files
    return out


DPKG = "/usr/bin/dpkg"


def _session(w: dict) -> str:
    auid, ses = str(w.get("auid", "")), str(w.get("ses", ""))
    if auid in ("", "?", "4294967295", "-1"):
        return ""
    return tr(", login uid {auid}, session {ses}", auid=auid, ses=ses)


def who(w: dict) -> str:
    """«por /usr/bin/sed (pid 123, uid 0, sesión 4)» a partir de un escritor visto por auditd."""
    return tr("by {exe} (pid {pid}, uid {uid}{session})", exe=w.get("exe", "?"), pid=w.get("pid", "?"),
              uid=w.get("uid", "?"), session=_session(w))


def drift(sealed: dict[str, dict], now: dict[str, dict], own: dict[str, str] | None = None,
          vault_read=None, skip=(), writers=None, package_wrote=None) -> tuple[list[dict], dict[str, dict]]:
    """(hallazgos, adopciones) del estado actual contra el sellado, fichero a fichero.

    `adopciones` son lo que se incorpora a la base sin alertar: piezas propias de Arx que coinciden con lo
    esperado, y ficheros de un paquete que solo cambió el dpkg verificado (`package_wrote(path)` lo comprueba).
    `vault_read(path) -> bytes|None` da la copia buena para el diff; `writers(path, since)` dice quién escribió
    el fichero según auditd, y eso viaja en la alerta."""
    own = own or {}
    skip = set(skip)
    findings, adopt = [], {}
    for path in sorted(set(sealed) | set(now)):
        if path in skip:
            continue
        b, a = sealed.get(path), now.get(path)
        if b and a and all(b.get(k) == a.get(k) for k in ("sha", "link", "mode", "uid", "gid", "special", "size")):
            continue
        group = (a or b)["g"]
        if path in own:
            want = own[path]
            got = ("link:" + str(a.get("link"))) if a is not None and "link" in a else (a or {}).get("sha")
            if a is not None and got == want and not _loosened(b or a, a):
                adopt[path] = a
                continue
            findings.append(_finding("crit", group, path, a,
                                     tr("an Arx file was altered or removed: {path}", path=path),
                                     tr("someone changed Arx itself: it could be switched off or turned against you"),
                                     kind="self_tamper"))
            continue
        if b and a and _loosened(b, a):
            # HZ#6 de Q: con un cambio de contenido nulo (un comentario) esto quedaba en silencio
            findings.append(_finding("high", group, path, a,
                                     tr("permissions or owner of {path} changed (now {mode:o}, uid {uid})",
                                        path=path, mode=a.get("mode", 0), uid=a.get("uid")),
                                     tr("someone else can now write a critical file"), tag="perm"))
        if b and a and b.get("sha") == a.get("sha") and b.get("link") == a.get("link"):
            continue
        if (a and "special" in a) or (b and "special" in b):
            findings.append(_finding("high", group, path, a, tr("{path} is no longer a regular file", path=path),
                                     tr("a FIFO or device where configuration should be can block or fool readers")))
            continue
        if (a and "link" in a) or (b and "link" in b):
            if a is None:
                sev, msg = "low", tr("link removed: {path}", path=path)
            else:
                sev = "high" if group == "systemd" else "med"
                msg = tr("link {path} → {target}", path=path, target=a.get("link"))
            findings.append(_finding(sev, group, path, a, msg, tr("a link here enables or redirects configuration")))
            continue
        change = cfgsem.classify(group, _parsed(b), _parsed(a))
        if change is None:
            if b and a and not b.get("ok") and not a.get("ok"):
                change = cfgsem.Change("high", tr("the file can no longer be understood ({why}): review it by hand",
                                                  why=a.get("reason", "?")))
            else:
                continue  # mismo significado: formato, comentarios, un fichero vacío
        ws = writers(path, (b or {}).get("at")) if writers else []
        if ws and package_wrote and a is not None and all(w.get("exe") == DPKG for w in ws) and package_wrote(path):
            adopt[path] = {**a, "by_package": True}  # una actualización de paquete firmada y verificada
            continue
        f = _finding(change.sev, group, path, a, f"{path}: {change.summary}",
                     tr("critical file altered → possible tampering or persistence"))
        if ws:
            f["by"] = ws[-3:]
            f["detail"] += f" — {who(ws[-1])}"
        if vault_read is not None:
            try:
                good = vault_read(path)
                _meta, cur = _read_safely(path)
                diff = unified_diff(path, good, cur)
                if diff:
                    f["diff"] = diff
            except Exception:  # noqa: BLE001 - el diff es ayuda, nunca bloquea la alerta
                pass
        findings.append(f)
    return findings, adopt


def _finding(sev: str, group: str, path: str, now: dict | None, detail: str, why: str,
             kind: str = "integrity", tag: str = "") -> dict:
    tag = (tag + ":" if tag else "") + ((now or {}).get("sha") or (now or {}).get("link") or "gone")
    if tag.startswith("perm:"):
        tag += f":{(now or {}).get('mode')}:{(now or {}).get('uid')}:{(now or {}).get('gid')}"
    return {"sev": sev, "kind": kind, "detail": detail, "why": why,
            "fp_key": f"integrity|{path}|{tag}",
            "target": {"file": group, "path": path}, "set": "integrity", "item": path}


# ── migración desde la huella por grupo ──────────────────────────────────────
def legacy_groups() -> dict[str, list[str]]:
    """Los grupos tal como los sellaban las versiones anteriores (para migrar sin falsas alarmas)."""
    return {
        "authorized_keys_root": ["/root/.ssh/authorized_keys"],
        "sudoers": ["/etc/sudoers"],
        "passwd": ["/etc/passwd"],
        "ld_preload": ["/etc/ld.so.preload"],
        "authorized_keys_users": glob.glob("/home/*/.ssh/authorized_keys"),
        "sudoers_d": glob.glob("/etc/sudoers.d/*"),
        "cron": ["/etc/crontab", *glob.glob("/etc/cron.d/*"), *glob.glob("/var/spool/cron/crontabs/*")],
        "systemd_units": glob.glob("/etc/systemd/system/*.service") + glob.glob("/etc/systemd/system/*.timer"),
        "apt_sources": ["/etc/apt/sources.list", *glob.glob("/etc/apt/sources.list.d/*"),
                        *glob.glob("/etc/apt/apt.conf.d/*")],
        "apt_keys": ["/etc/apt/trusted.gpg", *glob.glob("/etc/apt/trusted.gpg.d/*"),
                     *glob.glob("/etc/apt/keyrings/*")],
    }


def risky_preexisting(paths: list[str], now: dict[str, dict], owner=None, own=()) -> list[str]:
    """De lo que se empieza a vigilar al migrar, lo que ejecuta órdenes o da confianza (crit/high si fuera
    nuevo) y no pertenece a ningún paquete ni a Arx: persistencia que pudo plantarse antes de que Arx mirara."""
    out, own = [], set(own)
    for p in paths:
        s = now.get(p)
        if not s or p in own:
            continue
        ch = cfgsem.classify(s["g"], None, _parsed(s)) if "link" not in s else cfgsem.Change("high", "link")
        if ch is None or ch.sev not in ("crit", "high"):
            continue
        try:
            pkg = owner(p) if owner else None
        except Exception:  # noqa: BLE001 - sin respuesta de dpkg, se nombra (más vale revisarlo)
            pkg = None
        if not pkg:
            out.append(p)
    return out


def migrate(sealed_groups: dict[str, str], now: dict[str, dict], legacy_now: dict[str, str],
            vault: dict[str, tuple[bytes, dict]] | None = None, legacy_hash=None) -> tuple[dict, list[str], list[str]]:
    """De la huella por grupo al estado por fichero.

    Un grupo cuya huella sigue igual que al sellar se adopta tal cual (fichero a fichero, en silencio). Uno que
    cambió conserva el aviso de grupo de siempre hasta que alguien lo acepte. Lo que antes no se vigilaba
    (drop-ins, `.wants`, `authorized_keys2`, `cron.daily`…) se adopta y se dice, para que se revise una vez.
    Devuelve (estado adoptado, grupos antiguos que cambiaron, rutas recién vigiladas)."""
    covered: dict[str, str] = {}
    for g, paths in legacy_groups().items():
        for p in paths:
            covered[p] = g
    adopted, changed_groups, newly, rebuilt_groups = {}, [], [], set()
    vault = vault or {}
    by_group: dict[str, dict[str, tuple[bytes, dict]]] = {}
    for p, (data, meta) in vault.items():
        g = covered.get(p)
        if g:
            by_group.setdefault(g, {})[p] = (data, meta)
    for g, h in sealed_groups.items():
        if g == "suid_set" or legacy_now.get(g) == h:
            continue
        copies = by_group.get(g, {})
        if legacy_hash and copies and legacy_hash(g, {p: d for p, (d, _m) in copies.items()}) == h:
            # la bóveda guarda exactamente lo sellado: se reconstruye fichero a fichero y se juzga por significado
            for p, (data, meta) in copies.items():
                cur = now.get(p) or {}
                if "link" in cur:
                    # las versiones anteriores leían a través del enlace: la copia es el contenido del destino.
                    # Si sigue siendo el mismo, el enlace es lo sellado (un alias como syslog.service).
                    if _read_target(p) == data:
                        adopted[p] = cur
                        continue
                full = {"mode": meta.get("mode", cur.get("mode")), "uid": cur.get("uid"), "gid": cur.get("gid")}
                adopted[p] = state_from(p, _new_group(p, now), data, full)
            rebuilt_groups.add(g)
            continue
        changed_groups.append(g)
    for path, s in now.items():
        old = covered.get(path)
        if old is None or old not in sealed_groups:
            adopted[path] = s  # nunca se vigiló (o la base no tenía ese grupo): se adopta y se dice
            newly.append(path)
        elif old in changed_groups or path in adopted:
            continue  # pendiente de aceptar, o ya reconstruido desde la bóveda
        elif old in rebuilt_groups:
            continue  # no estaba en lo sellado: es nuevo, lo juzga la comparación
        else:
            adopted[path] = s  # el grupo no cambió: lo de ahora es lo sellado
    return adopted, sorted(changed_groups), sorted(newly)


def _read_target(path: str) -> bytes | None:
    """Contenido al que apunta un enlace (como lo leían las versiones anteriores), sin bloquearse."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        return f.read(cfgsem.MAX_TEXT + 1)


def _new_group(path: str, now: dict[str, dict]) -> str:
    if path in now:
        return now[path]["g"]
    for g, paths in groups().items():
        if path in paths:
            return g
    return "apt_conf" if path.startswith("/etc/apt/apt.conf") else "systemd" if "/systemd/" in path else "apt_sources"
