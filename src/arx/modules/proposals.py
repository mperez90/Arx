"""Arx · proposals — Arx propone, tú apruebas (promesa Core, §9 y §12.2).

Dos clases de propuesta, ninguna se aplica sola:

  · Lo que lleva días viéndose sin que nadie diga nada: probablemente es normal, y aceptarlo
    deja de hacer ruido. Solo lo que no es de severidad alta: eso no se normaliza por cansancio.
  · Cerrar lo que un ataque ha demostrado abierto (parche de postura): hoy, SSH. Es un cambio de
    configuración, así que pide tu palabra y se puede deshacer. Se comprueba con sshd que el cambio
    tiene efecto, y nunca se ofrece si te podría dejar fuera.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

from arx import config
from arx.modules import response
from arx.redact import printable

SSHD_DROPIN_DIR = "/etc/ssh/sshd_config.d"
SSHD_DROPIN = f"{SSHD_DROPIN_DIR}/00-arx-hardening.conf"
MIN_SEEN = 20        # barridos
MIN_DAYS = 3
# Lo que escribe cada propuesta y cómo se comprueba con `sshd -T`
_SSH_FIXES = {
    "ssh-sin-contrasena": {"line": "PasswordAuthentication no", "key": "passwordauthentication", "value": "no",
                           "bad": ("yes",), "title": "que SSH no admita contraseñas, solo llaves"},
    "ssh-root-sin-contrasena": {"line": "PermitRootLogin prohibit-password", "key": "permitrootlogin",
                                "value": "without-password", "bad": ("yes",),
                                "title": "que root solo entre por SSH con llave"},
}


def _sshd_effective() -> dict[str, str] | None:
    """La configuración que sshd aplica de verdad, incluidos sus ficheros incluidos."""
    if not shutil.which("sshd"):
        return None
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True, errors="replace", timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return {k.lower(): v.strip() for k, _, v in (line.partition(" ") for line in r.stdout.splitlines())}


def _includes_dropins() -> bool:
    """Sin un `Include` del directorio, el fichero de Arx no tendría ningún efecto."""
    try:
        with open("/etc/ssh/sshd_config", encoding="utf-8", errors="replace") as f:
            return re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/", f.read(), re.M | re.I) is not None
    except OSError:
        return False


def _admin_with_key() -> str | None:
    """Una cuenta de administración que entra con llave. Sin ella, cerrar contraseñas te deja fuera."""
    import pwd

    for name in sorted(response._admin_accounts()):
        try:
            keys = os.path.join(pwd.getpwnam(name).pw_dir, ".ssh", "authorized_keys")
            if os.path.getsize(keys) > 0 and (response._shadow_entry(name) or [""] * 8)[7] != "1":
                return name
        except (KeyError, OSError):
            continue
    return None


def _bruteforce_seen() -> int:
    return sum(e.get("kind") == "auth_bruteforce" for e in response.load_findings().values())


def _applied() -> list[str]:
    try:
        with open(SSHD_DROPIN, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []
    return [pid for pid, fix in _SSH_FIXES.items() if fix["line"] in text]


def _ssh_proposals() -> list[dict]:
    effective = _sshd_effective()
    if effective is None or not _includes_dropins():
        return []
    attacks = _bruteforce_seen()
    out = []
    for pid, fix in _SSH_FIXES.items():
        if effective.get(fix["key"]) not in fix["bad"] or pid in _applied():
            continue
        out.append({"id": pid, "kind": "postura", "title": fix["title"],
                    "why": (f"has recibido {attacks} ataque(s) de fuerza bruta: con esto dejarían de poder funcionar"
                            if attacks else "evita que una contraseña débil o robada baste para entrar"),
                    "admin_with_key": _admin_with_key()})
    return out


def _repeat_proposals(now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=MIN_DAYS)
    out = []
    for fp, e in response.load_findings().items():
        if not e.get("set") or e.get("kind") in ("login_users", "uid0_account", "suid_new", "integrity", "intel_ip"):
            continue  # quién entra o qué da root no se normaliza porque lleve días ahí
        try:
            first = datetime.fromisoformat(str(e.get("first_seen")))
        except ValueError:
            continue
        if e.get("seen", 0) >= MIN_SEEN and first <= cutoff:
            out.append({"id": fp, "kind": "normalizar", "title": f"aceptar como normal: {printable(e.get('item'))}",
                        "why": f"visto {e['seen']} veces desde {str(e.get('first_seen'))[:10]}, sin que nadie lo revisara"})
    return out


def all_proposals(now: datetime | None = None) -> list[dict]:
    return _ssh_proposals() + _repeat_proposals(now)


def _reload_sshd() -> bool:
    for argv in (["systemctl", "reload", "ssh"], ["systemctl", "reload", "sshd"]):
        if shutil.which(argv[0]):
            try:
                if subprocess.run(argv, capture_output=True, timeout=15).returncode == 0:
                    return True
            except (OSError, subprocess.TimeoutExpired):
                pass
    try:  # sin systemd: la señal de recarga de toda la vida
        with open("/run/sshd.pid", encoding="ascii") as f:
            os.kill(int(f.read().strip()), 1)
        return True
    except (OSError, ValueError):
        return False


def _write_dropin(lines: list[str]) -> None:
    if not lines:
        try:
            os.unlink(SSHD_DROPIN)
        except OSError:
            pass
        return
    fd = os.open(SSHD_DROPIN, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write("# Arx: propuesta aprobada por el operador. Deshazlo con: arx proposals revert <id>\n")
        f.write("\n".join(lines) + "\n")


def apply_ssh(pid: str) -> str:
    fix = _SSH_FIXES.get(pid)
    if fix is None:
        return f"no conozco la propuesta {printable(pid)}"
    if pid == "ssh-sin-contrasena" and not _admin_with_key():
        return "no se aplica: ninguna cuenta de administración tiene llave SSH, y te quedarías fuera"
    if not _includes_dropins():
        return f"no se aplica: sshd_config no incluye {SSHD_DROPIN_DIR}/ y no tendría efecto"
    current = [_SSH_FIXES[p]["line"] for p in _applied()]
    _write_dropin(sorted({*current, fix["line"]}))
    effective = _sshd_effective()
    if effective is None or effective.get(fix["key"]) != fix["value"]:  # sshd -T falla si no es válida
        _write_dropin(current)
        return "no se aplica: sshd no lo acepta o sigue con otro valor. Se ha dejado como estaba"
    if not _reload_sshd():
        _write_dropin(current)
        return "no se pudo recargar sshd: se ha dejado como estaba"
    response.record({"kind": "proposal_applied", "detail": fix["title"], "result": fix["line"]})
    return (f"hecho: {fix['title']}. Las sesiones abiertas siguen. Pruébalo desde OTRA terminal antes de cerrar "
            f"esta. Se deshace con:  arx proposals revert {pid}")


def revert_ssh(pid: str) -> str:
    fix = _SSH_FIXES.get(pid)
    if fix is None or pid not in _applied():
        return f"la propuesta {printable(pid)} no está aplicada"
    _write_dropin([_SSH_FIXES[p]["line"] for p in _applied() if p != pid])
    reloaded = _reload_sshd()
    response.record({"kind": "proposal_reverted", "detail": fix["title"]})
    return f"deshecho: {fix['title']}" + ("" if reloaded else ". Ojo: no pude recargar sshd, hazlo a mano")


def run(action: str = "list", pid: str | None = None) -> int:
    import getpass

    if action == "list":
        props = all_proposals()
        applied = _applied()
        if not props and not applied:
            print("Arx no tiene nada que proponerte ahora mismo.")
            return 0
        if props:
            print("\n▸ Arx te propone (nada de esto se aplica solo):")
        for p in props:
            print(f"  {p['id']}\n      {p['title']}\n      por qué: {p['why']}")
            if p.get("kind") == "postura" and p["id"] == "ssh-sin-contrasena" and not p.get("admin_with_key"):
                print("      ⚠ hoy no se puede: ninguna cuenta de administración tiene llave SSH")
        for a in applied:
            print(f"  aplicada: {a}  ·  se deshace con:  arx proposals revert {a}")
        if props:
            print("\nAplica una con:  arx proposals apply <id>\n")
        return 0
    cfg = config.load_config()
    if not cfg.get("auth_word"):
        print("No hay palabra de autorización configurada. Ejecuta:  arx setup")
        return 1
    word = getpass.getpass("Palabra de autorización: ").strip()
    if not config.verify_word(word, cfg.get("auth_word", {})):
        print("Palabra incorrecta. No se ha cambiado nada.")
        return 1
    if action == "revert":
        msg = revert_ssh(str(pid))
    elif pid in _SSH_FIXES:
        msg = apply_ssh(str(pid))
    else:
        msg = response.accept(str(pid)) or f"no hay ninguna propuesta con id {printable(pid)}"
    print(msg)
    return 0 if msg.startswith(("hecho", "deshecho", "✓")) else 1
