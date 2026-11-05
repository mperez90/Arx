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
# Corre como root: contiene amenazas (firewall, señales, ficheros del sistema).
# Endurecido sin bloquear su función. Sin ProtectHome: autorizar desde el chat ocurre dentro de este
# servicio, y restaurar un authorized_keys o retirar un dropper de /home fallaría.
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
    print(f"Unit systemd generado en: {dest}")
    if not sys.platform.startswith("linux"):
        print("Este no es un host Linux. En el servidor Ubuntu:")
    elif not _systemd_available():
        print("systemd no detectado aquí. En un servidor con systemd:")
    else:
        print("Requiere root. Instálalo con:")
    print(f"  sudo cp {dest} {UNIT_PATH}")
    print("  sudo systemctl daemon-reload && sudo systemctl enable --now arx")


def install(exec_start: str | None = None, enforce: bool = False) -> int:
    if not _prereqs_ok():
        print("⚠ Prerequisitos incompletos para operar 24/7:")
        print("  ejecuta  setup → recon → learn → learn --seal  antes de arrancar el servicio.")
        print("  (Sin baseline sellada, guard sale con error y systemd reintentaría en bucle.)\n")
    text = unit_text(exec_start or _default_exec(), enforce)
    if not enforce:
        print("ℹ Modo OBSERVAR: Arx detecta, registra y alerta, pero no aplica acciones Tier 1.\n"
              "  Revisa unos días sus hallazgos (arx status) y, si son fiables, reinstala con:\n"
              "  arx service install --enforce\n")
    if not (_systemd_available() and _is_root()):
        dest = config.state_dir() / "arx.service"
        dest.write_text(text)
        _manual_instructions(dest)
        return 0
    Path(UNIT_PATH).write_text(text)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    r = subprocess.run(["systemctl", "enable", "--now", "arx"], check=False)
    if r.returncode == 0:
        print("✓ Arx instalado como servicio systemd y arrancado (enable --now).")
        return 0
    print("Unit escrito, pero systemctl falló. Revisa:  systemctl status arx")
    return 1


def uninstall() -> int:
    if not (_systemd_available() and _is_root()):
        print("Requiere Linux + root con systemd. En el servidor:")
        print(f"  sudo systemctl disable --now arx && sudo rm -f {UNIT_PATH} && sudo systemctl daemon-reload")
        return 0
    subprocess.run(["systemctl", "disable", "--now", "arx"], check=False)
    try:
        Path(UNIT_PATH).unlink()
    except OSError:
        pass
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("✓ Servicio Arx retirado.")
    return 0


def status() -> int:
    if not _systemd_available():
        print("Estado del servicio: requiere systemd (systemctl). En el servidor:  systemctl status arx")
        return 0
    subprocess.run(["systemctl", "status", "arx", "--no-pager"], check=False)
    return 0


def run(action: str, exec_start: str | None = None, enforce: bool = False) -> int:
    if action == "install":
        return install(exec_start, enforce)
    if action == "uninstall":
        return uninstall()
    return status()
