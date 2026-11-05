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
from arx.i18n import tr
from arx.modules import response
from arx.redact import printable

SSHD_DROPIN_DIR = "/etc/ssh/sshd_config.d"
SSHD_DROPIN = f"{SSHD_DROPIN_DIR}/00-arx-hardening.conf"
MIN_SEEN = 20        # barridos
MIN_DAYS = 3
# Lo que escribe cada propuesta y cómo se comprueba con `sshd -T`
_SSH_FIXES = {
    "ssh-no-password": {"line": "PasswordAuthentication no", "key": "passwordauthentication", "value": "no",
                           "bad": ("yes",), "title": tr("stop SSH accepting passwords, keys only")},
    "ssh-root-key-only": {"line": "PermitRootLogin prohibit-password", "key": "permitrootlogin",
                                "value": "without-password", "bad": ("yes",),
                                "title": tr("root can only log in over SSH with a key")},
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
        out.append({"id": pid, "kind": "posture", "title": fix["title"],
                    "why": (tr("you have had {attacks} brute-force attack(s): with this they could "
                               "no longer work", attacks=attacks)
                            if attacks else tr("keeps a weak or stolen password from being enough "
                                               "to get in")),
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
            out.append({"id": fp, "kind": "normalize", "title": tr("accept as normal: {v}",
                                                                    v=printable(e.get('item'))),
                        "why": tr("seen {seen} times since {v}, with nobody reviewing it",
                                  seen=e['seen'], v=str(e.get('first_seen'))[:10])})
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
        f.write("# Arx: proposal approved by the operator. Undo it with: arx proposals revert <id>\n")
        f.write("\n".join(lines) + "\n")


def apply_ssh(pid: str) -> str:
    fix = _SSH_FIXES.get(pid)
    if fix is None:
        return tr("unknown proposal {pid}", pid=printable(pid))
    if pid == "ssh-no-password" and not _admin_with_key():
        return tr("not applied: no admin account has an SSH key, and you would be locked out")
    if not _includes_dropins():
        return tr("not applied: sshd_config does not include {SSHD_DROPIN_DIR}/ and it would have "
                  "no effect", SSHD_DROPIN_DIR=SSHD_DROPIN_DIR)
    current = [_SSH_FIXES[p]["line"] for p in _applied()]
    _write_dropin(sorted({*current, fix["line"]}))
    effective = _sshd_effective()
    if effective is None or effective.get(fix["key"]) != fix["value"]:  # sshd -T falla si no es válida
        _write_dropin(current)
        return tr("not applied: sshd does not accept it or keeps another value. It was left as it "
                  "was")
    if not _reload_sshd():
        _write_dropin(current)
        return tr("could not reload sshd: it was left as it was")
    response.record({"kind": "proposal_applied", "detail": fix["title"], "result": fix["line"]})
    return (tr("done: {title}. Open sessions stay up. Test it from ANOTHER terminal before closing "
               "this one. Undo with:  arx proposals revert {pid}", title=fix['title'], pid=pid))


def revert_ssh(pid: str) -> str:
    fix = _SSH_FIXES.get(pid)
    if fix is None or pid not in _applied():
        return tr("proposal {pid} is not applied", pid=printable(pid))
    _write_dropin([_SSH_FIXES[p]["line"] for p in _applied() if p != pid])
    reloaded = _reload_sshd()
    response.record({"kind": "proposal_reverted", "detail": fix["title"]})
    return tr("undone: {title}", title=fix['title']) + ("" if reloaded else tr(". Note: could not reload sshd, do it "
                                                                 "by hand"))


def run(action: str = "list", pid: str | None = None) -> int:
    import getpass

    if action == "list":
        props = all_proposals()
        applied = _applied()
        if not props and not applied:
            print(tr("Arx has nothing to propose right now."))
            return 0
        if props:
            print(tr("\n▸ Arx proposes (none of this applies on its own):"))
        for p in props:
            print(tr("  {id}\n      {title}\n      why: {why}",
                     id=p['id'], title=p['title'], why=p['why']))
            if p.get("kind") == "posture" and p["id"] == "ssh-no-password" and not p.get("admin_with_key"):
                print(tr("      ⚠ not possible today: no admin account has an SSH key"))
        for a in applied:
            print(tr("  applied: {a}  ·  undo with:  arx proposals revert {a}", a=a))
        if props:
            print(tr("\nApply one with:  arx proposals apply <id>\n"))
        return 0
    cfg = config.load_config()
    if not cfg.get("auth_word"):
        print(tr("No authorization word configured. Run:  arx setup"))
        return 1
    word = getpass.getpass(tr("Authorization word: ")).strip()
    if not config.verify_word(word, cfg.get("auth_word", {})):
        print(tr("Wrong word. Nothing was changed."))
        return 1
    if action == "revert":
        msg = revert_ssh(str(pid))
    elif pid in _SSH_FIXES:
        msg = apply_ssh(str(pid))
    else:
        msg = response.accept(str(pid)) or tr("no proposal with id {pid}", pid=printable(pid))
    print(msg)
    return 0 if msg.startswith((tr("done"), tr("undone"), "✓")) else 1
