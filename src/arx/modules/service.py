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
from arx.modules import maintenance

UNIT_PATH = "/etc/systemd/system/arx.service"
EARLY_UNIT_PATH = "/etc/systemd/system/arx-firewall.service"
DOWN_UNIT_PATH = "/etc/systemd/system/arx-down.service"
REVIVE_UNIT_PATH = "/etc/systemd/system/arx-revive.service"
REVIVE_TIMER_PATH = "/etc/systemd/system/arx-revive.timer"
MAINTENANCE_SLICE_PATH = "/etc/systemd/system/arx-maintenance.slice"


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
# every failure runs this, including a scheduled restart: arx-down records the real systemd state
OnFailure=arx-down.service

[Service]
Type=simple
ExecStart={exec_start} guard{' --enforce' if enforce else ''}
# Whoever stops Arx gets reported outside the host (unless it is Arx's own uninstall, or a shutdown).
ExecStopPost=-{exec_start} service stopped
# Alerts have a 45 s total budget; the rest is margin to persist every channel result.
TimeoutStopSec=90
Restart=always
RestartSec=10
# Arx never takes the host down: capped and at low priority. MemoryMax already keeps it from starving the
# host; a positive OOMScoreAdjust would make it the first victim of memory pressure an attacker induces.
MemoryHigh=384M
MemoryMax=512M
CPUQuota=50%
TasksMax=256
Nice=5
IOSchedulingClass=best-effort
IOSchedulingPriority=7
OOMScoreAdjust=0
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


def down_unit_text(exec_start: str) -> str:
    return f"""[Unit]
Description=Arx - report its real systemd restart state

[Service]
Type=oneshot
ExecStart={exec_start} service down
# notify.send gets 45 s in total; keep ample margin for JSONL persistence and slow storage.
TimeoutStartSec=90
"""


def maintenance_slice_text() -> str:
    """Presupuesto agregado de APT/dpkg, separado de los 512 MiB del guardián.

    En d13 lo que agotó los 512 MiB de Arx fue la concurrencia: 20 apt-get/apt-cache a la vez, cada
    uno ≤58 MiB RSS. Serializados, el mayor auxiliar medido (Debian 13: apt-get download de un
    kernel, page cache incluida) llegó a 52 MiB: 384 MiB dejan ~7× para cachés APT mayores sin
    estrangular, y 512 MiB acotan el peor caso. Son techos, no reservas.
    """
    return """[Unit]
Description=Arx - bounded APT and dpkg maintenance helpers

[Slice]
MemoryHigh=384M
MemoryMax=512M
CPUQuota=50%
TasksMax=64
"""


def revive_unit_text() -> str:
    """Solo si quedó en fallo: una parada hecha a mano no se deshace."""
    systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"
    return f"""[Unit]
Description=Arx - start it again if it is down after a failure

[Service]
Type=oneshot
ExecCondition={systemctl} is-failed -q arx.service
ExecStart={systemctl} reset-failed arx.service
ExecStart={systemctl} start arx.service
"""


def revive_timer_text() -> str:
    return """[Unit]
Description=Arx - every 15 minutes, start it again if it is down after a failure

[Timer]
OnBootSec=15min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
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
    slice_dest = dest.with_name("arx-maintenance.slice")
    print(f"  sudo cp {slice_dest} {MAINTENANCE_SLICE_PATH}")
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
        (config.state_dir() / "arx-maintenance.slice").write_text(maintenance_slice_text())
        _manual_instructions(dest)
        return 0
    Path(UNIT_PATH).write_text(text)
    Path(EARLY_UNIT_PATH).write_text(early_unit_text(exec_start or _default_exec()))
    Path(DOWN_UNIT_PATH).write_text(down_unit_text(exec_start or _default_exec()))
    Path(REVIVE_UNIT_PATH).write_text(revive_unit_text())
    Path(REVIVE_TIMER_PATH).write_text(revive_timer_text())
    Path(MAINTENANCE_SLICE_PATH).write_text(maintenance_slice_text())
    _seal_units()
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "arx-firewall"], check=False)
    subprocess.run(["systemctl", "enable", "--now", "arx-revive.timer"], check=False)
    r = subprocess.run(["systemctl", "enable", "--now", "arx"], check=False)
    if r.returncode == 0:
        print(tr("✓ Arx installed as a systemd service and started (enable --now)."))
        return 0
    print(tr("Unit written, but systemctl failed. Check:  systemctl status arx"))
    return 1


def refresh_maintenance() -> int:
    """Una actualización instala el slice sin rearrancar ni resellar units que no escribió."""
    if not (_systemd_available() and _is_root()):
        return 1
    if not os.path.exists(UNIT_PATH):
        return 0
    Path(MAINTENANCE_SLICE_PATH).write_text(maintenance_slice_text())
    sealed = config.read_json(config.state_dir() / "self.json", {}) or {}
    sealed[MAINTENANCE_SLICE_PATH] = _sha(MAINTENANCE_SLICE_PATH)
    config.write_json(config.state_dir() / "self.json", sealed)
    try:
        subprocess.run(["systemctl", "daemon-reload"], check=False, timeout=20)
    except subprocess.TimeoutExpired:
        # Un refresco opcional no puede retener dpkg para siempre si D-Bus/systemd no responde.
        return 1
    return 0


# ── autoprotección (DoD-6): parar o tocar a Arx se avisa fuera del host ───────
PLANNED_STOP = "/run/arx/planned-stop"
PLANNED_STOP_S = 300
# El preinst la deja al parar un Arx activo antes de reemplazar su zipapp; el postinst lo arranca si sigue.
UPGRADE_MARK = "/run/arx/package-upgrade-active"


def clear_upgrade_mark(env=None) -> bool:
    """Arrancar bajo systemd deja la marca sin objeto: ya no hay arranque pendiente que reanudar.

    Así, una marca que sobrevive solo puede venir de una operación de paquete que paró a Arx y no llegó a
    arrancarlo, y nunca reanima un Arx que alguien arrancó y paró a mano después."""
    env = os.environ if env is None else env
    if not env.get("INVOCATION_ID"):  # un guard lanzado a mano no es el servicio
        return False
    try:
        os.unlink(UPGRADE_MARK)
    except OSError:
        return False
    return True


def _units() -> tuple:
    return (UNIT_PATH, EARLY_UNIT_PATH, DOWN_UNIT_PATH, REVIVE_UNIT_PATH, REVIVE_TIMER_PATH,
            MAINTENANCE_SLICE_PATH)
DROPIN_DIRS = tuple(f"{p}.d" for p in _units())


def _sha(path: str) -> str | None:
    import hashlib
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _seal_units() -> None:
    """La huella de las units que Arx acaba de escribir: otra cosa en su lugar es manipulación."""
    config.write_json(config.state_dir() / "self.json", {p: _sha(p) for p in _units()})


def self_check(dropin_dirs=DROPIN_DIRS) -> list[dict]:
    """Arx comprueba que nadie lo ha tocado: sus units, sus drop-ins y sus ficheros (contra dpkg)."""
    findings = []
    sealed = config.read_json(config.state_dir() / "self.json", {}) or {}
    for path in _units():
        if sealed and path not in sealed:
            findings.append(_tamper(tr("Arx's unit {path} was changed or removed", path=path),
                                    f"unit|{path}|unsealed"))
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
    rc, unavailable = 0, False
    inside = maintenance._in_arx_service()
    try:
        result = maintenance.run(["dpkg", "--verify", "arx"], capture_output=True,
                                 text=True, timeout=30)
        out, rc = result.stdout or "", result.returncode
    except maintenance.MaintenanceUnavailable:
        out, unavailable = "", True
    except subprocess.TimeoutExpired:
        out, unavailable = "", True
    except OSError:
        # Una CLI en macOS o un host sin dpkg no declara integridad: simplemente no hace esta prueba.
        out, unavailable = "", inside
    changed = [line.split()[-1] for line in out.splitlines() if len(line) > 2 and line[2] == "5"]
    changed += [line.split(None, 1)[1].strip() for line in out.splitlines() if line.startswith("missing ")]
    if changed:
        findings.append(_tamper(tr("Arx's own files differ from its package: {files}", files=", ".join(changed[:3])),
                                f"code|{','.join(changed)}"))
    elif unavailable or rc != 0:
        detail = (tr("Arx could not run dpkg --verify in its isolated maintenance slice; "
                     "file integrity is unknown") if inside else
                  tr("Arx could not run dpkg --verify; file integrity is unknown"))
        why = (tr("without an isolated dpkg, Arx must not report a clean self-check") if inside else
               tr("a failed verification must not be reported as clean"))
        findings.append({"sev": "high", "kind": "self_check_unavailable", "detail": detail,
                         "why": why, "fp_key": "self_check_unavailable|dpkg"})
    return findings


def _tamper(detail: str, key: str) -> dict:
    return {"sev": "crit", "kind": "self_tamper", "detail": detail,
            "why": tr("someone changed Arx itself: it may be an attempt to blind it"), "fp_key": f"self_tamper|{key}"}


NOTIFY_BUDGET_S = 45


def _notify_and_record(event: str, text: str, notify_send=None) -> None:
    """Conserva el resultado por canal sin sustituir el incidente crítico que motivó el aviso.

    «ok» acredita que el canal aceptó el envío local, no que una persona lo haya leído. El presupuesto
    deja margen para escribir todos los resultados; response.record redacta también valores anidados.
    """
    from arx import notify
    from arx.modules import response
    try:
        results = notify_send(text) if notify_send is not None else notify.send(text, budget_s=NOTIFY_BUDGET_S)
    except Exception as e:  # avisar nunca puede impedir registrar el incidente ni romper ExecStopPost
        results = {"notifier": f"error: {e}"}
    if not isinstance(results, dict):
        results = {"notifier": "error: notifier returned no per-channel result"}
    response.record({"kind": "notify_result", "sev": "info", "event": event, "results": results})


def _restart_status() -> dict:
    """Estado real de arx.service al entrar en OnFailure; ninguna ausencia de datos se inventa."""
    unknown = {"restart_state": "unknown", "active_state": None, "sub_state": None,
               "result": None, "restarts": None}
    try:
        r = subprocess.run(["systemctl", "show", "arx.service", "--no-pager",
                            "--property=ActiveState,SubState,Result,NRestarts,Restart"],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return unknown
    if r.returncode != 0:
        return unknown
    values = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    active, sub, result = (values.get(k) or None for k in ("ActiveState", "SubState", "Result"))
    try:
        restarts = int(values["NRestarts"])
    except (KeyError, TypeError, ValueError):
        restarts = None
    if active == "active":  # un Result anterior no puede convertir una recuperación en caída terminal
        state = "recovered"
    elif sub == "auto-restart" or active == "activating":
        state = "scheduled"
    elif result == "start-limit-hit" or (active == "failed" and values.get("Restart") == "always"):
        # systemd 255 (medido en Ubuntu 24.04): al agotar el límite en reinicios automáticos queda failed y
        # Result conserva el motivo original; start-limit-hit solo aparece si se rechaza un arranque manual.
        # Con Restart=always, quedarse en failed tras un fallo solo ocurre cuando systemd deja de reintentar.
        state = "exhausted"
    elif active == "failed" or sub == "failed":
        state = "failed"
    else:
        state = "unknown"
    return {"restart_state": state, "active_state": active, "sub_state": sub,
            "result": result, "restarts": restarts}


def _down_detail(status: dict) -> str:
    state, result = status["restart_state"], status.get("result") or "unknown"
    n = status.get("restarts") if status.get("restarts") is not None else "?"
    if state == "scheduled":
        return tr("systemd restart {n} is scheduled in 10 seconds after {result}; arx-revive.timer retries "
                  "every 15 minutes only while Arx remains failed", n=n, result=result)
    if state == "recovered":
        return tr("Arx has already recovered after {result}; systemd reports it active", result=result)
    if state == "exhausted":
        return tr("Arx is down: the systemd restart limit is exhausted after {n} restarts ({result}); "
                  "arx-revive.timer will retry every 15 minutes", n=n, result=result)
    if state == "failed":
        return tr("Arx remains failed without evidence that the restart limit was exhausted ({result}); "
                  "arx-revive.timer will retry every 15 minutes", result=result)
    return tr("Arx failed, but its systemd restart state is unknown; check: systemctl status arx && "
              "journalctl -u arx")


def down(notify_send=None) -> int:
    """OnFailure: registra si el reinicio está programado, recuperado, agotado o indeterminado."""
    import socket
    from arx.modules import response
    status = _restart_status()
    detail = _down_detail(status)
    response.record({"kind": "self_down", "sev": "crit", "detail": detail,
                     "restart_state": status["restart_state"], "active_state": status["active_state"],
                     "sub_state": status["sub_state"], "systemd_result": status["result"],
                     "restarts": status["restarts"]})
    _notify_and_record("self_down", tr("🛑 Arx failure on {host}: {detail}",
                                      host=socket.gethostname(), detail=detail), notify_send)
    return 0


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
    _notify_and_record("self_stopped",
                       tr("⚠ Arx stopped on {host}: {why}. If it wasn't you, someone may be trying "
                          "to blind it.", host=socket.gethostname(), why=why), notify_send)
    return 0


def uninstall() -> int:
    if not (_systemd_available() and _is_root()):
        print(tr("Requires Linux + root with systemd. On the server:"))
        print(f"  sudo systemctl disable --now arx arx-firewall arx-revive.timer && sudo rm -f "
              f"{' '.join(_units())} && sudo systemctl daemon-reload")
        return 0
    try:  # la parada que viene es la de su propia desinstalación: no es un ataque
        os.makedirs(os.path.dirname(PLANNED_STOP), exist_ok=True)
        Path(PLANNED_STOP).touch()
    except OSError:
        pass
    subprocess.run(["systemctl", "disable", "--now", "arx-revive.timer", "arx", "arx-firewall"], check=False)
    maintenance.stop_all()
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
    for unit in _units():
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
    if action == "down":
        return down()
    if action == "install":
        return install(exec_start, enforce)
    if action == "uninstall":
        return uninstall()
    if action == "refresh-maintenance":
        return refresh_maintenance()
    return status()
