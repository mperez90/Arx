"""Arx · procedencia: ¿de dónde viene este programa? (decisión D, 2026-11-05)

Se decide por pruebas, no por la ruta. Un proceso queda *verificado* solo si se demuestra todo:
  · su binario es de un paquete (`dpkg-query -S`) y sigue intacto (md5 que guardó dpkg);
  · ese paquete vino de un repositorio firmado, no de un .deb suelto ni de uno `trusted=yes`;
  · lo arranca systemd con un unit del mismo paquete de origen, sin drop-ins que cambien qué se
    ejecuta ni como quién;
  · si el binario es un intérprete, el script también es de ese paquete.
Lo verificado solo avisa. Lo demás se contiene: lo que da señales de daño se suspende, y lo que no,
se confina sin red saliente para que siga funcionando (decisión E, en response).

Límite honesto: la prueba es la base de datos de dpkg. Un intruso que ya es root puede falsificarla,
y también puede parar a Arx. Un paquete malicioso dentro de un repositorio firmado pasa esta prueba:
eso es trabajo del perfil de comportamiento, no de la procedencia.
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
import shutil
import stat
import subprocess
import time

from arx.i18n import tr

DPKG_INFO = "/var/lib/dpkg/info"
CACHE_S = 300
MAX_HASH_BYTES = 1024 * 1024 * 1024
# El código real de un intérprete está en el script: verificar `python3` no dice nada del programa.
_INTERPRETER_RE = re.compile(r"^(?:python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node(?:js)?|php[0-9.]*|"
                             r"php-fpm[0-9.]*|java|bash|sh|dash|zsh|ksh|lua[0-9.]*|tclsh[0-9.]*|"
                             r"Rscript|pwsh|busybox)$")
# Lo que cambia qué se ejecuta, con qué entorno, como quién o con qué poderes. Relajar el aislamiento
# (`NoNewPrivileges=no`, `ProtectProc=`) no cambia el programa: es lo que hace LXC con TODOS los servicios
# (zzz-lxc-service.conf), y contarlo bloqueaba cualquier servicio nuevo en un contenedor (medido en Incus).
# Una asignación vacía solo vuelve al valor por defecto: tampoco cuenta.
_RISKY_DROPIN_KEYS = re.compile(r"^\s*(?:Exec[A-Za-z]*|Environment(?:File)?|User|Group|DynamicUser|"
                                r"WorkingDirectory|RootDirectory|RootImage|BindPaths|"
                                r"BindReadOnlyPaths|SupplementaryGroups|AmbientCapabilities|"
                                r"CapabilityBoundingSet)\s*=\s*\S", re.M)
_UNIT_RE = re.compile(r"^[A-Za-z0-9@_.:\\-]{1,200}\.service$")
_SUSPECT_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
# Quien atiende la red: un programa desconocido que nace de ellos es la firma de una webshell
_NET_USERS = {"www-data", "nginx", "apache", "http", "httpd", "nobody", "tomcat", "jetty", "caddy",
              "lighttpd", "nginx-unit", "php-fpm"}
_NET_PARENT_RE = re.compile(r"^(?:nginx|apache2|httpd|lighttpd|caddy|php-fpm[0-9.]*|php[0-9.]*|"
                            r"uwsgi|gunicorn|tomcat[0-9]*|java|node|unitd|haproxy|postgres|"
                            r"mysqld|mariadbd|redis-server|mongod)$")

_cache: dict = {}


def _cached(key, fn):
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and now - hit[0] < CACHE_S:
        return hit[1]
    value = fn()
    _cache[key] = (now, value)
    return value


def clear_cache() -> None:
    _cache.clear()


def _q(argv: list[str], timeout: int = 10) -> str | None:
    """Salida de un comando del sistema, siempre en inglés (se analiza) y sin shell."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout,
                           env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def available() -> bool:
    """¿Hay una base de paquetes contra la que probar algo? Sin ella, nada queda verificado."""
    return bool(shutil.which("dpkg-query") and shutil.which("apt-cache") and os.path.isdir(DPKG_INFO))


def _variants(path: str) -> list[str]:
    """La misma ruta antes y después de la fusión de /usr: dpkg puede conocer cualquiera."""
    out = [path]
    real = os.path.realpath(path)
    if real != path:
        out.append(real)
    for p in list(out):
        for short in ("/bin/", "/sbin/", "/lib/", "/lib64/"):
            if p.startswith("/usr" + short):
                out.append(p[4:])
            elif p.startswith(short):
                out.append("/usr" + p)
    return list(dict.fromkeys(out))


def package_of(path: str) -> str | None:
    """Paquete dueño de un fichero (`nginx`, o `libc6:arm64` en multiarch). None si no es de nadie."""
    def look():
        for p in _variants(path):
            out = _q(["dpkg-query", "-S", p])
            for line in (out or "").splitlines():
                if line.startswith(("diversion by", "local diversion")):
                    continue
                pkgs, sep, f = line.partition(": ")
                if sep and f.strip() == p:
                    return pkgs.split(",")[0].strip()
        return None
    return _cached(("pkg", path), look)


def _md5_file(path: str) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_HASH_BYTES:
            return None
        h = hashlib.md5()  # el resumen que guarda dpkg; aquí se compara, no se protege nada con él
        while chunk := os.read(fd, 1 << 20):
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def intact(path: str, pkg: str) -> bool | None:
    """¿El fichero es el que instaló dpkg? None si dpkg no guardó su resumen (no se puede probar)."""
    name, _, arch = pkg.partition(":")
    sums = [f"{DPKG_INFO}/{name}:{arch}.md5sums", f"{DPKG_INFO}/{name}.md5sums"] if arch else \
        [f"{DPKG_INFO}/{name}.md5sums", *glob.glob(f"{DPKG_INFO}/{glob.escape(name)}:*.md5sums")]
    wanted = {p.lstrip("/") for p in _variants(path)}
    for s in sums:
        try:
            with open(s, encoding="utf-8", errors="replace") as f:
                for line in f:
                    digest, _, rel = line.rstrip("\n").partition("  ")
                    if rel in wanted:
                        current = _md5_file(path)
                        return None if current is None else current == digest
        except OSError:
            continue
    return None


def _trusted_yes_urls() -> list[str]:
    """Repositorios sin firma (`trusted=yes`): lo que venga de ellos no cuenta como firmado."""
    urls = []
    for f in ["/etc/apt/sources.list", *glob.glob("/etc/apt/sources.list.d/*.list")]:
        try:
            for line in open(f, encoding="utf-8", errors="replace"):
                m = re.match(r"^\s*deb(?:-src)?\s+\[([^\]]*)\]\s+(\S+)", line)
                if m and re.search(r"trusted\s*=\s*yes", m.group(1)):
                    urls.append(m.group(2).rstrip("/"))
        except OSError:
            continue
    for f in glob.glob("/etc/apt/sources.list.d/*.sources"):
        try:
            text = open(f, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for stanza in re.split(r"\n\s*\n", text):
            if re.search(r"^Trusted:\s*yes", stanza, re.M | re.I):
                m = re.search(r"^URIs:\s*(.+)$", stanza, re.M | re.I)
                urls += [u.rstrip("/") for u in (m.group(1).split() if m else [])]
    return urls


def signed_origin(pkg: str) -> tuple[bool, str]:
    """¿La versión instalada está en un repositorio firmado? (sí/no, de dónde)."""
    def look():
        out = _q(["apt-cache", "policy", pkg.partition(":")[0]])
        if not out:
            return False, tr("apt does not know this package")
        sources, inside = [], False
        for line in out.splitlines():
            if line.startswith(" *** "):
                inside = True
                continue
            if inside:
                m = re.match(r"^ {8}\s*-?\d+\s+(\S+)", line)
                if not m:
                    break  # siguiente versión de la tabla
                sources.append(m.group(1))
        remote = [s for s in sources if s != "/var/lib/dpkg/status"]
        if not remote:
            return False, tr("installed from a local package, not from a repository")
        unsigned = _trusted_yes_urls()
        signed = [s for s in remote if not any(s.rstrip("/").startswith(u) for u in unsigned)]
        if not signed:
            return False, tr("its repository is marked trusted=yes: apt does not check its signature")
        return True, signed[0]
    return _cached(("origin", pkg), look)


def source_package(pkg: str) -> str:
    out = _q(["dpkg-query", "-W", "-f=${source:Package}", pkg])
    return (out or "").strip() or pkg.partition(":")[0]


def unit_of(pid: int) -> tuple[str, str] | None:
    """(ruta de cgroup del unit, nombre) si el proceso es de un servicio del sistema."""
    try:
        line = next((ln for ln in open(f"/proc/{pid}/cgroup", encoding="utf-8")
                     if ln.startswith("0::")), "")
    except OSError:
        return None
    return unit_from_cgroup(line.strip()[3:])


def system_root(cgroup_of_pid1: str | None = None) -> str:
    """Raíz de cgroups de este sistema: la del PID 1, que nadie puede mover. En un host es "".

    En un contenedor que comparte el árbol del host (`--cgroupns=host`) los servicios cuelgan de
    `…/docker-<id>.scope/`: anclarse aquí permite probarlos sin abrir la puerta a que un usuario se
    fabrique un cgroup llamado `system.slice/…` bajo su propia sesión."""
    if cgroup_of_pid1 is None:
        try:
            cgroup_of_pid1 = next((ln.strip()[3:] for ln in open("/proc/1/cgroup", encoding="utf-8")
                                   if ln.startswith("0::")), "")
        except OSError:
            return ""
    path = cgroup_of_pid1.strip("/")
    parent, _, last = path.rpartition("/")
    if last == "init.scope":
        return parent
    return "" if path in ("", "init.scope") else path


def unit_from_cgroup(path: str, root: str | None = None) -> tuple[str, str] | None:
    root = system_root() if root is None else root
    path = path.strip("/")
    if root:
        if not path.startswith(root + "/"):
            return None  # fuera de este sistema
        rel = path[len(root) + 1:]
    else:
        rel = path
    parts = rel.split("/")
    if not parts or parts[0] != "system.slice":
        return None  # un servicio de usuario, una sesión o un contenedor no son servicios del sistema
    for i, comp in enumerate(parts):
        if comp.endswith(".service"):
            if not all(p.endswith(".slice") for p in parts[:i]):
                return None
            return "/".join(([root] if root else []) + parts[:i + 1]), comp
    return None


def _unit_files(unit: str) -> tuple[str | None, list[str]]:
    out = _q(["systemctl", "show", "-p", "FragmentPath", "-p", "DropInPaths", unit]) or ""
    frag, drops = None, []
    for line in out.splitlines():
        key, _, value = line.partition("=")
        if key == "FragmentPath" and value:
            frag = value
        elif key == "DropInPaths":
            drops = value.split()
    return frag, drops


_ARX_CONFINE_DROPIN = re.compile(r"\A# Arx: confined without outbound network until you decide \(arx accept\)\.\n"
                                 r"\[Service\]\nExecStartPre=-/[\w/.-]+/nft add element inet arx confined[2-6] "
                                 r"'\{ \"[A-Za-z0-9@_.:\\/-]+\" \}'\n\Z")


def _is_arx_dropin(path: str, text: str) -> bool:
    """Los de Arx se reconocen por su contenido exacto: un nombre parecido no basta para colarse."""
    from arx.modules import profile  # perezoso: profile importa este módulo
    name, unit = os.path.basename(path), os.path.basename(os.path.dirname(path))[:-2]
    if name == profile.DROPIN:
        return text == profile.dropin_text(str(profile._files_dir() / f"{unit}.nft"))
    return name == "90-arx-confine.conf" and bool(_ARX_CONFINE_DROPIN.match(text))


def _risky_dropins(drops: list[str]) -> list[str]:
    """Drop-ins que cambian qué se ejecuta. Los de Arx (`systemctl set-property`) no cuentan."""
    bad = []
    for d in drops:
        if "/system.control/" in d:
            continue
        try:
            text = open(d, encoding="utf-8", errors="replace").read()
        except OSError:
            bad.append(d)  # sin poder leerlo, no se da por bueno
            continue
        if _RISKY_DROPIN_KEYS.search(text) and package_of(d) is None and not _is_arx_dropin(d, text):
            bad.append(d)
    return bad


def _exe(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None


def _argv(pid: int) -> list[str]:
    try:
        return open(f"/proc/{pid}/cmdline", "rb").read().decode("utf-8", "replace").split("\0")[:-1]
    except OSError:
        return []


def _script(pid: int) -> str | None:
    """El fichero que ejecuta un intérprete: el primer argumento que no es una opción."""
    args = _argv(pid)[1:]
    for i, a in enumerate(args):
        if a in ("-m", "-c", "-e", "-E", "--eval", "-r"):
            return None  # código en línea o un módulo: no hay fichero que probar
        if a.startswith("-"):
            continue
        if not a.startswith("/"):
            try:
                a = os.path.join(os.readlink(f"/proc/{pid}/cwd"), a)
            except OSError:
                return None
        return a if os.path.isfile(a) else None
    return None


def verify_file(path: str, deep: bool = False) -> dict:
    """¿Este binario es de un paquete firmado y está intacto? No dice nada de quién lo ejecuta."""
    if not available():
        return {"verified": False, "reason": tr("no package database to check it against")}
    pkg = package_of(path)
    if not pkg:
        return {"verified": False, "reason": tr("it does not belong to any package")}
    ok = intact(path, pkg)
    if ok is False:
        return {"verified": False, "package": pkg, "reason": tr("changed since its package installed it")}
    if ok is None:
        return {"verified": False, "package": pkg, "reason": tr("dpkg has no checksum for it: it cannot be proven intact")}
    signed, where = signed_origin(pkg)
    if not signed:
        return {"verified": False, "package": pkg, "reason": where}
    from arx.modules import trust  # perezoso: trust importa este módulo
    # sin esperar: si las pruebas de confianza aún no están, manda la procedencia, y el resultado llega
    # por la vigilancia del servicio (que confina lo que no pase)
    t = trust.assess_async(pkg, deep=deep)
    if t["state"] == "done" and not t["trusted"]:  # firmado pero envenenado: la procedencia sola no lo ve
        return {"verified": False, "package": pkg, "origin": where, "trust": t["score"], "reason": t["reason"]}
    return {"verified": True, "package": pkg, "origin": where, "trust": t.get("score"),
            "reason": tr("package {pkg} from a signed repository, intact", pkg=pkg)}


def verify_process(pid: int) -> dict:
    """La prueba completa para un proceso que atiende la red: paquete, firma, integridad y unit."""
    exe = _exe(pid)
    if not exe:
        return {"verified": False, "reason": tr("the process is gone or cannot be read")}
    if exe.endswith(" (deleted)"):
        return {"verified": False, "reason": tr("its executable was deleted from disk")}
    base = verify_file(exe, deep=True)  # atiende la red: la prueba completa, también contra el repositorio
    if not base["verified"]:
        return base
    pkg = base["package"]
    origin_src = source_package(pkg)
    if _INTERPRETER_RE.match(os.path.basename(exe)):
        script = _script(pid)
        spkg = package_of(script) if script else None
        if not script or not spkg:
            return {**base, "verified": False,
                    "reason": tr("an interpreter running code that is not from any package")}
        sv = verify_file(script)
        if not sv["verified"]:
            return {**sv, "verified": False}
        pkg, origin_src = spkg, source_package(spkg)
    unit = unit_of(pid)
    if not unit:
        return {**base, "verified": False, "reason": tr("not started by a system service")}
    cg_path, name = unit
    frag, drops = _unit_files(name)
    upkg = package_of(frag) if frag else None
    if not upkg:
        return {**base, "verified": False, "unit": name,
                "reason": tr("its unit {unit} is not from any package", unit=name)}
    if source_package(upkg) != origin_src:
        return {**base, "verified": False, "unit": name,
                "reason": tr("its unit and its binary come from different packages")}
    bad = _risky_dropins(drops)
    if bad:
        return {**base, "verified": False, "unit": name,
                "reason": tr("a drop-in changes what {unit} runs: {path}", unit=name, path=bad[0])}
    return {**base, "unit": name, "cgroup": cg_path,
            "reason": tr("{unit} from package {pkg}, signed repository, intact", unit=name, pkg=pkg)}


# ── señales de daño: deciden entre suspender y confinar ──────────────────────
def _user_of(pid: int) -> str | None:
    import pwd
    try:
        return pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except (OSError, KeyError):
        return None


def _ppid(pid: int) -> int | None:
    try:
        raw = open(f"/proc/{pid}/stat", "rb").read().decode("utf-8", "replace")
        return int(raw.rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return None


def _login_user(pid: int) -> str | None:
    import pwd
    try:
        uid = int(open(f"/proc/{pid}/loginuid").read().strip())
        return None if uid == 4294967295 else pwd.getpwuid(uid).pw_name
    except (OSError, ValueError, KeyError):
        return None


def harm_signals(exe: str, pids: list[int], finding: dict) -> list[str]:
    """Lo que hace pensar en daño local, más allá de la red: con cualquiera de estas, se suspende."""
    from arx.modules import response  # perezoso: response importa este módulo

    signals = []
    if exe.startswith(_SUSPECT_DIRS):
        signals.append(tr("runs from a temporary directory"))
    if any(part.startswith(".") for part in exe.split("/") if part):
        signals.append(tr("hidden path"))
    if (finding.get("sandbox") or {}).get("verdict") in ("malicious", "suspicious"):
        signals.append(tr("static analysis flagged it"))
    live = [p for p in pids if _exe(p)]
    if any((_exe(p) or "").endswith(" (deleted)") for p in live) or (live and not os.path.exists(exe)):
        signals.append(tr("its file was deleted while it runs"))
    for p in live:
        parent = _ppid(p)
        pexe = os.path.basename((_exe(parent) or "").removesuffix(" (deleted)")) if parent else ""
        if _user_of(p) in _NET_USERS or _NET_PARENT_RE.match(pexe):
            signals.append(tr("started by a network service (webshell pattern)"))
            break
    flagged = {str(e.get("item", "")).partition("@")[0]
               for e in response.load_findings().values()
               if e.get("kind") == "login_users" and not e.get("human_cleared")}
    if any(_login_user(p) in flagged for p in live):
        signals.append(tr("comes from a session the baseline does not know"))
    return signals


# ── enriquecer un hallazgo ───────────────────────────────────────────────────
def _listener_pids(proto: str, port: int) -> list[int]:
    from arx.modules import recon
    pids = []
    for p in recon.collect_ports():
        local = str(p.get("local", ""))
        if p.get("proto") == proto and local.rsplit(":", 1)[-1] == str(port):
            pids += [int(x) for x in re.findall(r"pid=(\d+)", str(p.get("process", "")))]
    return list(dict.fromkeys(pids))


def enrich(finding: dict) -> dict:
    """Añade al hallazgo `provenance` (y para un ejecutable, `harm`). Nunca lanza.

    Sin estos campos, response se comporta como antes: contener todo lo nuevo.
    """
    kind = finding.get("kind")
    target = finding.get("target") or {}
    f = dict(finding)
    if kind == "listen_ports" and target.get("port"):
        pids = _listener_pids(str(target.get("proto", "tcp")), int(target["port"]))
        if not pids:
            f["provenance"] = {"verified": False, "reason": tr("no owning process found")}
            return f
        results = [verify_process(p) for p in pids]
        bad = next((r for r in results if not r["verified"]), None)
        f["provenance"] = {**(bad or results[0]), "pids": pids}  # todos los que escuchan deben probarlo
        f["why"] = f"{f.get('why', '')} · {f['provenance']['reason']}"
        return f
    if kind in ("executables", "processes"):
        exe = str(target.get("exe") or target.get("process") or "")
        if not exe.startswith("/"):
            return f
        from arx.modules import response
        pids = [p for p in response._pids_for_exe(exe) if p > 1 and p != os.getpid()]
        prov = verify_file(exe)
        f["provenance"] = prov
        if prov["verified"]:
            return f
        f["harm"] = harm_signals(exe, pids, f)
        if f["harm"]:
            f["sev"] = "high"
            f["why"] = f"{f.get('why', '')} · " + "; ".join(f["harm"])
        elif f.get("sev") == "low":
            # en un directorio del sistema, pero de ningún paquete: la ruta ya no basta para fiarse
            f["sev"] = "med"
            f["why"] = f"{f.get('why', '')} · {prov['reason']}"
    return f
