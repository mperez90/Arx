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
from pathlib import Path

from arx import config
from arx.i18n import tr

UNIT_PATH = "/etc/systemd/system/arx.service"


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

[Service]
Type=simple
ExecStart={exec_start} guard{' --enforce' if enforce else ''}
Restart=always
RestartSec=10
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
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    r = subprocess.run(["systemctl", "enable", "--now", "arx"], check=False)
    if r.returncode == 0:
        print(tr("✓ Arx installed as a systemd service and started (enable --now)."))
        return 0
    print(tr("Unit written, but systemctl failed. Check:  systemctl status arx"))
    return 1


def uninstall() -> int:
    if not (_systemd_available() and _is_root()):
        print(tr("Requires Linux + root with systemd. On the server:"))
        print(f"  sudo systemctl disable --now arx && sudo rm -f {UNIT_PATH} && sudo systemctl daemon-reload")
        return 0
    subprocess.run(["systemctl", "disable", "--now", "arx"], check=False)
    try:
        Path(UNIT_PATH).unlink()
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
    if action == "install":
        return install(exec_start, enforce)
    if action == "uninstall":
        return uninstall()
    return status()
