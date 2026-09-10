"""Arx · recon — reconocimiento inicial del host.

Capa RÁPIDA (determinista, sin LLM): enumera todo el sistema, calcula la
superficie de ataque y produce un plan de defensa base. El motor (LLM) enriquece
este plan después, async y fuera del hot path — aquí queda el "seam" (plan_defense).

Diseñado para Ubuntu Server. Cada colector DEGRADA con elegancia: si un comando o
fichero no existe (otro SO, sin permiso), devuelve None/parcial en vez de romper.
Así el mismo módulo corre parcial en el equipo de desarrollo y completo en destino.
"""
from __future__ import annotations

import glob
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TIMEOUT = 8  # segundos por comando; los colectores lentos lo suben explícitamente

# ── severidad ────────────────────────────────────────────────────────────────
SEV_ORDER = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}
SEV_COLOR = {"crit": "91;1", "high": "91", "med": "93", "low": "90", "info": "90"}
SEV_LABEL = {"crit": "CRÍTICO", "high": "ALTO", "med": "MEDIO", "low": "BAJO", "info": "INFO"}


# ── helpers de E/S robustos ──────────────────────────────────────────────────
def _run(args: list[str], timeout: int = TIMEOUT) -> str | None:
    """Ejecuta un comando (sin shell). Devuelve stdout o None ante cualquier fallo."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _c(text: str, sev: str) -> str:
    """Colorea por severidad solo si la salida es un terminal."""
    if sys.stdout.isatty() and sev in SEV_COLOR:
        return f"\033[{SEV_COLOR[sev]}m{text}\033[0m"
    return text


# ── colectores ───────────────────────────────────────────────────────────────
def collect_os() -> dict:
    d: dict = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "arch": platform.machine(),
    }
    osr = _read("/etc/os-release")
    if osr:
        kv = {}
        for line in osr.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                kv[k] = v.strip().strip('"')
        d["distro"] = kv.get("PRETTY_NAME") or kv.get("NAME")
        d["version"] = kv.get("VERSION_ID")
    up = _read("/proc/uptime")
    if up:
        d["uptime_h"] = round(float(up.split()[0]) / 3600, 1)
    return d


def collect_hardware() -> dict:
    d: dict = {"cpu_count": os.cpu_count()}
    cpuinfo = _read("/proc/cpuinfo")
    if cpuinfo:
        for line in cpuinfo.splitlines():
            if line.startswith("model name"):
                d["cpu_model"] = line.split(":", 1)[1].strip()
                break
    mem = _read("/proc/meminfo")
    if mem:
        for line in mem.splitlines():
            if line.startswith("MemTotal"):
                d["mem_total_gb"] = round(int(line.split()[1]) / 1024 / 1024, 1)
            elif line.startswith("MemAvailable"):
                d["mem_available_gb"] = round(int(line.split()[1]) / 1024 / 1024, 1)
    try:
        du = shutil.disk_usage("/")
        d["root_disk_gb"] = round(du.total / 1e9, 1)
        d["root_free_gb"] = round(du.free / 1e9, 1)
        d["root_used_pct"] = round(du.used / du.total * 100, 1)
    except OSError:
        pass
    lsblk = _run(["lsblk", "-dno", "NAME,SIZE,TYPE"])
    if lsblk:
        d["block_devices"] = lsblk.splitlines()
    if _has("lsusb"):
        usb = _run(["lsusb"])
        if usb:
            d["usb"] = usb.splitlines()
    return d


def collect_network() -> dict:
    d: dict = {}
    ipaddr = _run(["ip", "-o", "addr"])
    if ipaddr:
        addrs = []
        for line in ipaddr.splitlines():
            f = line.split()
            if len(f) >= 4 and f[2] in ("inet", "inet6"):
                addrs.append(f"{f[1]} {f[3]}")
        d["addresses"] = addrs
    route = _run(["ip", "route"])
    if route:
        d["routes"] = route.splitlines()
    resolv = _read("/etc/resolv.conf")
    if resolv:
        d["dns"] = [l.split()[1] for l in resolv.splitlines() if l.startswith("nameserver")]
    return d


def _classify_exposure(local: str) -> str:
    """all = escucha en todas las interfaces; local = solo loopback; iface = una IP concreta."""
    host = local.rsplit(":", 1)[0].strip("[]")
    if host in ("0.0.0.0", "*", "::", ""):
        return "all"
    if host in ("127.0.0.1", "::1"):
        return "local"
    return "iface"


def collect_ports() -> list[dict]:
    """Sockets en escucha (TCP/UDP) con proceso dueño y grado de exposición."""
    out = _run(["ss", "-tulpnH"]) or _run(["ss", "-tulpn"])
    ports: list[dict] = []
    if not out:
        return ports
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5 or f[0] in ("Netid", "State"):
            continue
        local = f[4]
        proc = " ".join(f[6:]) if len(f) > 6 else ""
        ports.append(
            {
                "proto": f[0],
                "local": local,
                "exposed": _classify_exposure(local),
                "process": proc,
            }
        )
    return ports


def collect_services() -> list[str] | None:
    out = _run(
        ["systemctl", "list-units", "--type=service", "--state=running",
         "--no-legend", "--no-pager"]
    )
    if out is None:
        return None
    return [l.split()[0] for l in out.splitlines() if l.strip()]


def collect_packages() -> dict:
    d: dict = {}
    if _has("dpkg-query"):
        out = _run(["dpkg-query", "-f", "${Package}\n", "-W"])
        if out:
            d["manager"] = "dpkg"
            d["count"] = len(out.splitlines())
    return d


def collect_ssh() -> dict | None:
    cfg = _read("/etc/ssh/sshd_config")  # puede requerir root → degrada a None
    if not cfg:
        return None
    d: dict = {}
    for raw in cfg.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("permitrootlogin"):
            d["permit_root_login"] = line.split()[1]
        elif low.startswith("passwordauthentication"):
            d["password_auth"] = line.split()[1]
        elif low.startswith("port "):
            d.setdefault("ports", []).append(line.split()[1])
    return d or None


def collect_users() -> dict:
    d: dict = {}
    passwd = _read("/etc/passwd")
    if passwd:
        humans = []
        for line in passwd.splitlines():
            p = line.split(":")
            if len(p) >= 7:
                try:
                    uid = int(p[2])
                except ValueError:
                    continue
                if 1000 <= uid < 65534:
                    humans.append({"user": p[0], "uid": uid, "home": p[5], "shell": p[6]})
        d["human_users"] = humans
    grp = _read("/etc/group")
    if grp:
        for line in grp.splitlines():
            name = line.split(":", 1)[0]
            if name in ("sudo", "admin", "wheel"):
                members = line.split(":")[3].strip()
                if members:
                    d.setdefault("sudo_members", []).extend(members.split(","))
    # SUID: solo el fs raíz (-xdev), acotado en tiempo
    suid = _run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"], timeout=25)
    if suid is not None:
        d["suid_binaries"] = suid.splitlines() if suid else []
    cron = [p for p in ["/etc/crontab", *glob.glob("/etc/cron.d/*")] if _read(p)]
    if cron:
        d["cron_files"] = cron
    last = _run(["last", "-n", "5", "-w"])
    if last:
        d["recent_logins"] = [l for l in last.splitlines()[:5] if l.strip()]
    return d


def collect_containers() -> dict | None:
    if not _has("docker"):
        return None
    ps = _run(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"])
    if ps is None:
        return None
    return {"running": ps.splitlines() if ps else []}


def collect_firewall() -> dict | None:
    d: dict = {}
    if _has("ufw"):
        out = _run(["ufw", "status"])
        if out:
            d["ufw"] = out.splitlines()
    if not d and _has("nft"):
        out = _run(["nft", "list", "ruleset"], timeout=5)
        if out is not None:
            d["nftables_rules"] = len(out.splitlines())
    return d or None


def collect() -> dict:
    """Ejecuta todos los colectores y arma el inventario."""
    return {
        "meta": {
            "arx_recon": 1,
            "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "os": collect_os(),
        "hardware": collect_hardware(),
        "network": collect_network(),
        "ports": collect_ports(),
        "services": collect_services(),
        "packages": collect_packages(),
        "ssh": collect_ssh(),
        "users": collect_users(),
        "containers": collect_containers(),
        "firewall": collect_firewall(),
    }


# ── análisis de superficie (determinista) ────────────────────────────────────
def analyze_surface(inv: dict) -> list[dict]:
    """Hallazgos deterministas. Cada uno: {sev, area, detail, why}."""
    f: list[dict] = []

    exposed = [p for p in inv.get("ports") or [] if p.get("exposed") == "all"]
    for p in exposed:
        f.append(
            {
                "sev": "info",
                "area": "perímetro",
                "detail": f"{p['proto']} {p['local']} escucha en todas las interfaces "
                f"({p['process'] or 'proceso desconocido'})",
                "why": "Cada puerto expuesto es superficie de ataque; hay que vigilarlo y basar su tráfico.",
            }
        )

    ssh = inv.get("ssh") or {}
    if str(ssh.get("permit_root_login", "")).lower() in ("yes", "prohibit-password"):
        f.append(
            {
                "sev": "high",
                "area": "ssh",
                "detail": f"PermitRootLogin = {ssh['permit_root_login']}",
                "why": "Login directo de root amplía el impacto de credenciales filtradas o fuerza bruta.",
            }
        )
    if str(ssh.get("password_auth", "")).lower() == "yes":
        f.append(
            {
                "sev": "med",
                "area": "ssh",
                "detail": "PasswordAuthentication = yes",
                "why": "Habilita fuerza bruta/credential stuffing; preferible solo claves.",
            }
        )

    fw = inv.get("firewall")
    ufw = (fw or {}).get("ufw", [])
    if fw is None or any("inactive" in l.lower() for l in ufw):
        f.append(
            {
                "sev": "med",
                "area": "firewall",
                "detail": "Firewall inactivo o no detectado (ufw/nftables)",
                "why": "Sin firewall, todo puerto abierto queda expuesto sin filtrado.",
            }
        )

    suid = inv.get("users", {}).get("suid_binaries")
    if suid is not None and len(suid) > 30:
        f.append(
            {
                "sev": "low",
                "area": "usuarios",
                "detail": f"{len(suid)} binarios SUID (revisar excesos)",
                "why": "Cada SUID es vía potencial de escalada; conviene fijar la línea base y vigilar cambios.",
            }
        )

    hw = inv.get("hardware", {})
    if hw.get("root_used_pct", 0) >= 90:
        f.append(
            {
                "sev": "low",
                "area": "hardware",
                "detail": f"Disco raíz al {hw['root_used_pct']}%",
                "why": "Disco lleno degrada logs y respuesta; también puede ser exfiltración/DoS.",
            }
        )

    f.sort(key=lambda x: SEV_ORDER.get(x["sev"], 9))
    return f


# ── plan de defensa base (seam para el LLM) ──────────────────────────────────
def plan_defense(inv: dict, findings: list[dict]) -> list[tuple[str, str]]:
    plan: list[tuple[str, str]] = [
        ("sensores", "Activar osquery + auditd + Falco/eBPF: estado del sistema, syscalls y comportamiento en kernel."),
        ("baseline", "Aprender lo normal de procesos, red, usuarios y horarios (ventana conservadora) con integridad de arranque."),
    ]
    homes = [u["home"] for u in inv.get("users", {}).get("human_users", [])]
    plan.append(
        ("canarios", f"Plantar honeytokens en {len(homes) + 1} ubicaciones (homes + /root) y vigilar acceso con inotify.")
    )
    plan.append(
        ("integridad", "Vigilar cambios en authorized_keys, sudoers, cron y el conjunto SUID; alertar ante cualquier variación.")
    )
    exposed = [p for p in inv.get("ports") or [] if p.get("exposed") == "all"]
    if exposed:
        plan.append(
            ("perímetro", f"Monitorizar {len(exposed)} servicios expuestos; correlacionar orígenes y picos anómalos contra la base.")
        )
    if any(x["area"] == "firewall" for x in findings):
        plan.append(
            ("firewall", "Proponer política de firewall por defecto-denegar (Tier 2, requiere tu aprobación por ser potencialmente disruptivo).")
        )
    plan.append(
        ("motor", "El motor (LLM) revisará este inventario async y afinará el plan con contexto de amenazas actuales.")
    )
    return plan


# ── salida ───────────────────────────────────────────────────────────────────
def _line(label: str, value) -> str:
    return f"  {label:<16} {value}"


def render_console(inv: dict, findings: list[dict], plan: list[tuple[str, str]]) -> None:
    os_ = inv.get("os", {})
    hw = inv.get("hardware", {})
    net = inv.get("network", {})
    ports = inv.get("ports") or []
    users = inv.get("users", {})
    exposed = [p for p in ports if p.get("exposed") == "all"]
    highs = [f for f in findings if f["sev"] in ("crit", "high")]

    print("\n╔═ Arx · reconocimiento inicial " + "═" * 34)
    print(f"║ {os_.get('distro') or os_.get('platform')}  ·  kernel {os_.get('kernel')}  ·  {os_.get('arch')}")
    print(f"║ host {os_.get('hostname')}  ·  uptime {os_.get('uptime_h', '?')} h")
    print("╚" + "═" * 64)

    print("\n▸ Hardware")
    print(_line("CPU", f"{hw.get('cpu_count')} vCPU · {hw.get('cpu_model', 'n/d')}"))
    print(_line("Memoria", f"{hw.get('mem_total_gb', '?')} GB ({hw.get('mem_available_gb', '?')} GB libres)"))
    print(_line("Disco raíz", f"{hw.get('root_disk_gb', '?')} GB · {hw.get('root_used_pct', '?')}% usado"))

    print("\n▸ Red")
    for a in net.get("addresses", [])[:6]:
        print(_line("iface", a))
    if net.get("dns"):
        print(_line("DNS", ", ".join(net["dns"])))

    print(f"\n▸ Puertos en escucha ({len(ports)} · {len(exposed)} expuestos a todas las interfaces)")
    for p in ports[:15]:
        tag = _c("EXPUESTO", "high") if p["exposed"] == "all" else ("local" if p["exposed"] == "local" else "iface ")
        print(f"  [{tag}] {p['proto']:<4} {p['local']:<24} {p['process'][:40]}")
    if len(ports) > 15:
        print(f"  … (+{len(ports) - 15} más en el JSON)")

    svcs = inv.get("services")
    if svcs is not None:
        print(f"\n▸ Servicios activos ({len(svcs)})")
        print("  " + ", ".join(svcs[:12]) + (f" … (+{len(svcs) - 12})" if len(svcs) > 12 else ""))

    print("\n▸ Usuarios y accesos")
    print(_line("Humanos", ", ".join(u["user"] for u in users.get("human_users", [])) or "n/d"))
    if users.get("sudo_members"):
        print(_line("sudo", ", ".join(sorted(set(users["sudo_members"])))))
    if users.get("suid_binaries") is not None:
        print(_line("SUID", f"{len(users['suid_binaries'])} binarios"))

    cont = inv.get("containers")
    if cont:
        print(f"\n▸ Contenedores ({len(cont['running'])} en marcha)")
        for c in cont["running"][:8]:
            print("  " + c)

    print(f"\n▸ Superficie de ataque — {len(findings)} hallazgos ({len(highs)} de prioridad alta)")
    for x in findings:
        print(f"  {_c(SEV_LABEL[x['sev']].ljust(8), x['sev'])} [{x['area']}] {x['detail']}")
        print(f"           ↳ {x['why']}")
    if not findings:
        print("  (sin hallazgos deterministas; el motor hará la revisión fina)")

    print("\n▸ Plan de defensa propuesto")
    for area, action in plan:
        print(f"  • {area:<12} {action}")
    print()


def save_report(inv: dict, findings: list[dict], plan: list[tuple[str, str]], path: str | None) -> Path:
    from arx import config

    report = {**inv, "surface": findings, "defense_plan": [{"area": a, "action": c} for a, c in plan]}
    dest = Path(path) if path else config.state_dir() / f"recon-{inv['os'].get('hostname', 'host')}.json"
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return dest


# ── entrada ──────────────────────────────────────────────────────────────────
def run(json_path: str | None = None, save: bool = True) -> int:
    inv = collect()
    findings = analyze_surface(inv)
    plan = plan_defense(inv, findings)
    render_console(inv, findings, plan)
    if save:
        dest = save_report(inv, findings, plan, json_path)
        print(f"▸ Inventario completo guardado en: {dest}\n")
    return 0
