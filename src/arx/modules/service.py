"""Arx · service — integración con systemd (correr `guard` 24/7).

Genera el unit y, si hay systemd + root, lo instala y arranca (`enable --now`). Si no
(otro SO, sin root, o Linux sin systemd — p. ej. un contenedor), NO finge ni crashea:
escribe el unit en el dir de estado y muestra los comandos exactos para el servidor.
Arx corre como root porque contiene amenazas (firewall, señales, integridad de ficheros);
el unit incluye endurecimiento que no rompe su función. Por defecto el servicio arranca en
modo OBSERVAR; las acciones Tier 1 automáticas exigen `--enforce` explícito.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from arx import config
from arx.i18n import tr

UNIT_PATH = "/etc/systemd/system/arx.service"
EARLY_UNIT_PATH = "/etc/systemd/system/arx-firewall.service"


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _systemd_available() -> bool:
    """Linux con systemd como init y systemctl disponible (no basta con ser root)."""
    return (
        sys.platform.startswith("linux")
        and shutil.which("systemctl") is not None
        and Path("/run/systemd/system").is_dir()
    )


def _default_exec() -> str:
    """ExecStart según cómo se invoca Arx ahora (binario en PATH, .pyz, o módulo)."""
    argv0 = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    if argv0.endswith(".pyz"):
        return f"/usr/bin/env python3 {argv0}"
    return shutil.which("arx") or f"{sys.executable} -m arx.cli"


def unit_text(exec_start: str, enforce: bool = False) -> str:
    return f"""[Unit]
Description=Arx - autonomous defensive agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=10

[Service]
Type=simple
ExecStart={exec_start} guard{' --enforce' if enforce else ''}
# Whoever stops Arx gets reported outside the host (unless it is Arx's own uninstall, or a shutdown).
ExecStopPost=-{exec_start} service stopped
Restart=always
RestartSec=10
# Arx never takes the host down: capped, low priority, and the first the kernel kills if memory runs out.
MemoryHigh=384M
MemoryMax=512M
CPUQuota=50%
TasksMax=256
Nice=5
IOSchedulingClass=best-effort
IOSchedulingPriority=7
OOMScoreAdjust=500
# Runs as root: it contains threats (firewall, signals, system files).
# Hardened without blocking its job. No ProtectHome: authorizing from the chat happens inside this
# service, and restoring an authorized_keys or removing a dropper from /home would fail.
ProtectClock=true
ProtectKernelTunables=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
"""


def early_unit_text(exec_start: str) -> str:
    """Repone la contención antes de que haya red. Sin él, tras un reinicio, un programa confinado
    salió una vez a la red antes del primer barrido de Arx (medido en Lima). Va después de
    nftables.service: su configuración empieza con `flush ruleset` y borraría lo repuesto."""
    return f"""[Unit]
Description=Arx - put containment back in the kernel before the network comes up
DefaultDependencies=no
After=local-fs.target nftables.service
Before=network-pre.target arx.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={exec_start} service restore
# runs before the network: a hang must never hold the host's boot
TimeoutStartSec=30
MemoryMax=256M

[Install]
WantedBy=sysinit.target
"""


def _prereqs_ok() -> bool:
    from arx.modules import baseline

    base = baseline.load()
    return bool(config.load_config()) and bool(base and base.get("meta", {}).get("sealed"))


def _manual_instructions(dest: Path) -> None:
    print(tr("systemd unit generated at: {dest}", dest=dest))
    if not sys.platform.startswith("linux"):
        print(tr("This is not a Linux host. On the Ubuntu server:"))
    elif not _systemd_available():
        print(tr("systemd not detected here. On a server with systemd:"))
    else:
        print(tr("Requires root. Install it with:"))
    print(f"  sudo cp {dest} {UNIT_PATH}")
    print("  sudo systemctl daemon-reload && sudo systemctl enable --now arx")


def install(exec_start: str | None = None, enforce: bool = False) -> int:
    if not _prereqs_ok():
        print(tr("⚠ Prerequisites missing to run 24/7:"))
        print(tr("  run  setup → recon → learn → learn --seal  before starting the service."))
        print(tr("  (Without a sealed baseline, guard exits with an error and systemd would retry "
                 "in a loop.)\n"))
    text = unit_text(exec_start or _default_exec(), enforce)
    if not enforce:
        print(tr("ℹ OBSERVE mode: Arx detects, logs and alerts, but does not apply Tier 1 "
                 "actions.\n  Review its findings for a few days (arx status) and, if they are "
                 "reliable, reinstall with:\n  arx service install --enforce\n"))
    if not (_systemd_available() and _is_root()):
        dest = config.state_dir() / "arx.service"
        dest.write_text(text)
        _manual_instructions(dest)
        return 0
    Path(UNIT_PATH).write_text(text)
    Path(EARLY_UNIT_PATH).write_text(early_unit_text(exec_start or _default_exec()))
    _seal_units()
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "arx-firewall"], check=False)
    r = subprocess.run(["systemctl", "enable", "--now", "arx"], check=False)
    if r.returncode == 0:
        print(tr("✓ Arx installed as a systemd service and started (enable --now)."))
        return 0
    print(tr("Unit written, but systemctl failed. Check:  systemctl status arx"))
    return 1


# ── autoprotección (DoD-6): parar o tocar a Arx se avisa fuera del host ───────
PLANNED_STOP = "/run/arx/planned-stop"
PLANNED_STOP_S = 300
DROPIN_DIRS = ("/etc/systemd/system/arx.service.d", "/etc/systemd/system/arx-firewall.service.d")


def _sha(path: str) -> str | None:
    import hashlib
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _seal_units() -> None:
    """La huella de las units que Arx acaba de escribir: otra cosa en su lugar es manipulación."""
    config.write_json(config.state_dir() / "self.json", {p: _sha(p) for p in (UNIT_PATH, EARLY_UNIT_PATH)})


def self_check(dropin_dirs=DROPIN_DIRS) -> list[dict]:
    """Arx comprueba que nadie lo ha tocado: sus units, sus drop-ins y sus ficheros (contra dpkg)."""
    findings = []
    sealed = config.read_json(config.state_dir() / "self.json", {}) or {}
    for path, sha in sealed.items():
        now = _sha(path)
        if sha and now != sha:
            findings.append(_tamper(tr("Arx's unit {path} was changed or removed", path=path), f"unit|{path}|{now}"))
    for d in dropin_dirs:
        try:
            extra = sorted(n for n in os.listdir(d) if n.endswith(".conf"))
        except OSError:
            continue
        if extra:
            findings.append(_tamper(tr("someone added drop-ins to Arx's unit: {files}", files=", ".join(extra)),
                                    f"dropin|{d}|{','.join(extra)}"))
    try:
        out = subprocess.run(["dpkg", "--verify", "arx"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    changed = [line.split()[-1] for line in out.splitlines() if len(line) > 2 and line[2] == "5"]
    if changed:
        findings.append(_tamper(tr("Arx's own files differ from its package: {files}", files=", ".join(changed[:3])),
                                f"code|{','.join(changed)}"))
    return findings


def _tamper(detail: str, key: str) -> dict:
    return {"sev": "crit", "kind": "self_tamper", "detail": detail,
            "why": tr("someone changed Arx itself: it may be an attempt to blind it"), "fp_key": f"self_tamper|{key}"}


def stopped(env=None, notify_send=None) -> int:
    """ExecStopPost: Arx se ha parado. Fuera de su desinstalación o de un apagado, se avisa fuera del host."""
    import socket
    env = os.environ if env is None else env
    try:
        planned = time.time() - os.stat(PLANNED_STOP).st_mtime < PLANNED_STOP_S
        os.unlink(PLANNED_STOP)
    except OSError:
        planned = False
    if planned:  # una marca vieja no se traga una parada de verdad
        return 0
    try:
        state = subprocess.run(["systemctl", "is-system-running"], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        state = ""
    why = f"{env.get('SERVICE_RESULT', '?')} ({env.get('EXIT_CODE', '?')} {env.get('EXIT_STATUS', '')})".strip()
    from arx.modules import response
    response.record({"kind": "self_stopped", "sev": "crit", "detail": tr("Arx stopped: {why}", why=why)})
    if state == "stopping":  # un apagado: sin red y sin prisa por avisar
        return 0
    from arx import notify
    (notify_send or notify.send)(tr("⚠ Arx stopped on {host}: {why}. If it wasn't you, someone may be trying "
                                    "to blind it.", host=socket.gethostname(), why=why))
    return 0


def uninstall() -> int:
    if not (_systemd_available() and _is_root()):
        print(tr("Requires Linux + root with systemd. On the server:"))
        print(f"  sudo systemctl disable --now arx arx-firewall && sudo rm -f {UNIT_PATH} {EARLY_UNIT_PATH} "
              "&& sudo systemctl daemon-reload")
        return 0
    try:  # la parada que viene es la de su propia desinstalación: no es un ataque
        os.makedirs(os.path.dirname(PLANNED_STOP), exist_ok=True)
        Path(PLANNED_STOP).touch()
    except OSError:
        pass
    subprocess.run(["systemctl", "disable", "--now", "arx", "arx-firewall"], check=False)
    try:  # la marca vale solo para esta parada: si Arx ya estaba parado, no puede tragarse la siguiente
        os.unlink(PLANNED_STOP)
    except OSError:
        pass
    from arx.modules import profile, response
    profile.release_all()  # sin Arx, los drop-ins de vigilancia no tienen sentido
    released = response.release_all_confinements()
    if released:
        print(tr("  {n} confined service(s) or program(s) got their network back.", n=released))
    if shutil.which("nft"):  # bloqueos, sets y reglas: sin Arx, nadie los gestionaría
        subprocess.run(["nft", "delete", "table", "inet", "arx"], capture_output=True, check=False)
    for unit in (UNIT_PATH, EARLY_UNIT_PATH):
        try:
            Path(unit).unlink()
        except OSError:
            pass
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print(tr("✓ Arx service removed."))
    return 0


def status() -> int:
    if not _systemd_available():
        print(tr("Service status: requires systemd (systemctl). On the server:  systemctl status "
                 "arx"))
        return 0
    subprocess.run(["systemctl", "status", "arx", "--no-pager"], check=False)
    return 0


def run(action: str, exec_start: str | None = None, enforce: bool = False) -> int:
    if action == "restore":
        from arx.modules import response
        print(response.boot_restore())
        return 0
    if action == "stopped":
        return stopped()
    if action == "install":
        return install(exec_start, enforce)
    if action == "uninstall":
        return uninstall()
    return status()
