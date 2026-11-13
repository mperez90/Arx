#!/usr/bin/env bash
# Lab del OOM de mantenimiento: los auxiliares nacen fuera de arx.service, comparten un presupuesto
# agregado y se recogen enteros al cerrar o agotar el tiempo. La presión de memoria solo corre en la VM.
#   ARX_LIMA_VICTIM=arx-deb13 bash lab/maintenance-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-victim}
WORD=palabra-del-lab
FAILED=0
LAB=/tmp/arx-maintenance-lab

step() { echo; echo "══ $1 ══"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
v() { limactl shell "$VM" sudo "$@"; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }
no_scopes() { local out; out=$(v systemctl list-units --type=scope --all --plain --no-legend 2>/dev/null); ! grep -q '^arx-maint-.*\.scope' <<<"$out"; }
valid_scope() {
  v python3 -c 'import json, sys
for name in sys.argv[1:]:
    d = json.load(open(name))
    assert d["cgroup"].startswith("/arx.slice/arx-maintenance.slice/arx-maint-"), d
    if "child_cgroup" in d:
        assert d["child_cgroup"] == d["cgroup"], d' "$@"
}
memory_report() {
  v python3 -c 'import json, sys
for name in sys.argv[1:]:
    d = json.load(open(name))
    print(name.rsplit("/", 1)[-1], d["cgroup"], "current=" + str(d.get("memory_current")),
          "peak=" + str(d.get("memory_peak")))' "$@"
}

inv() { v systemctl show arx -p InvocationID --value | tr -d '[:space:]'; }
incidents_count() { v sh -c 'test ! -f /var/lib/arx/incidents.jsonl || wc -l < /var/lib/arx/incidents.jsonl' | tr -d '[:space:]'; }
no_zip_errors() {  # $1 = InvocationID
  [ -n "$1" ] && ! limactl shell "$VM" sudo journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID="$1" 2>/dev/null \
    | grep -qE 'ZipImportError|bad local file header'
}
no_self_stopped_since() {  # $1 = líneas de incidents.jsonl antes de la operación
  v python3 - "${1:-0}" <<'PY'
import json, sys
try:
    with open("/var/lib/arx/incidents.jsonl") as f:
        rows = [json.loads(line) for line in f if line.strip()][int(sys.argv[1]):]
except FileNotFoundError:
    rows = []
assert not any("self_stopped" in (row.get("finding_kind"), row.get("kind")) for row in rows), rows
PY
}
pkg_status() { v dpkg-query -W -f='${Status}' arx 2>/dev/null; }
lab_dropin() {  # fallos inyectados solo en runtime (/run): desaparecen al reiniciar la VM
  if [ -n "${2:-}" ]; then
    v bash -c "mkdir -p /run/systemd/system/arx.service.d && printf '[Unit]\n%s\n' '$2' > /run/systemd/system/arx.service.d/zz-lab-$1.conf && systemctl daemon-reload"
  else
    v bash -c "rm -f /run/systemd/system/arx.service.d/zz-lab-$1.conf && systemctl daemon-reload"
  fi
}
clean_victim() {
  v bash -c 'rm -f /run/systemd/system/arx.service.d/zz-lab-*.conf; systemctl daemon-reload
  systemctl disable --now arx arx-firewall arx-revive.timer 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  systemctl list-units --type=scope --all --plain --no-legend 2>/dev/null | awk '\''$1 ~ /^arx-maint-.*\.scope$/ {print $1}'\'' | xargs -r systemctl stop
  dpkg --configure -a >/dev/null 2>&1; dpkg --purge arx-b71-other >/dev/null 2>&1
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arx-maintenance-lab /run/arx /etc/systemd/system/arx*.service \
    /etc/systemd/system/arx*.timer /etc/systemd/system/arx*.slice /etc/systemd/system/*.service.d/9[01]-arx-*.conf
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf 2>/dev/null | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload; systemctl reset-failed arx 2>/dev/null; true'
}
put_on_guard() {
  printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
  v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
  v arx service install --enforce >/dev/null 2>&1
}
watch_ready() { v python3 -c 'import json; w = json.load(open("/var/lib/arx/watch.json")); assert w["process"]["capture"]["running"] and w["sensitive_files"]["running"]' 2>/dev/null; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1
v sh -c 'echo "  vm: $(. /etc/os-release; echo "$PRETTY_NAME") · kernel $(uname -r) · $(python3 --version)"'
echo "  build: $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- src packaging || echo '+cambios-locales')"

step "construir la RC y la v0.0.8rc5 publicada (desde su tag)"
clean_victim
v bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq auditd >/dev/null'  # dependencia desde 0.0.9rc2
v bash -c "rm -rf /tmp/arxsrc && mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1"
check "el .deb de la RC está construido" v test -s /tmp/arxsrc/dist/arx_all.deb
git archive --format=tar v0.0.8rc5 src packaging | v bash -c 'rm -rf /tmp/arxold && mkdir -p /tmp/arxold && tar -x -C /tmp/arxold && cd /tmp/arxold && packaging/build-deb.sh >/dev/null 2>&1'
check "el .deb de v0.0.8rc5 está construido" v test -s /tmp/arxold/dist/arx_all.deb

step "actualizar desde v0.0.8rc5: su prerm no paraba nada; el preinst nuevo sí"
v dpkg -i /tmp/arxold/dist/arx_all.deb >/dev/null 2>&1
check "v0.0.8rc5 instalada" v sh -c 'dpkg-query -W -f="\${Version}" arx | grep -qx "0.0.8~rc5"'
put_on_guard
check "la v0.0.8rc5 está de guardia" wait_for 30 v systemctl is-active -q arx
INV_OLD=$(inv)
old_on_guard() { limactl shell "$VM" sudo journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID="$INV_OLD" 2>/dev/null | grep -q "Arx on guard"; }
check "la v0.0.8rc5 terminó de arrancar" wait_for 45 old_on_guard
sleep 5  # sus hilos ya importan de forma perezosa desde el archive viejo
INC_OLD=$(incidents_count)
check "la actualización a la RC termina" v dpkg -i /tmp/arxsrc/dist/arx_all.deb
RC_DEB=$(sed -nE 's/^__version__ = "(.*)"/\1/p' src/arx/__init__.py | sed -E 's/(a|b|rc)([0-9])/~\1\2/')
check "versión instalada $RC_DEB" v sh -c "dpkg-query -W -f='\${Version}' arx | grep -qx '$RC_DEB'"
check "Arx vuelve a estar activo" wait_for 30 v systemctl is-active -q arx
INV_NEW=$(inv)
check "el guardián viejo no siguió vivo con el archive nuevo" test -n "$INV_NEW" -a "$INV_NEW" != "$INV_OLD"
check "la invocación vieja terminó sin errores de zipimport" no_zip_errors "$INV_OLD"
check "la nueva tampoco los tiene" no_zip_errors "$INV_NEW"
check "la nueva publica readiness con los dos watchers" wait_for 45 watch_ready
check "la parada de la actualización no generó self_stopped espurio" no_self_stopped_since "$INC_OLD"
check "el postinst instaló y selló el slice de mantenimiento" v python3 - <<'PY'
import hashlib, json
path = "/etc/systemd/system/arx-maintenance.slice"
data = open(path, "rb").read()
assert b"MemoryMax=512M" in data, data
assert json.load(open("/var/lib/arx/self.json"))[path] == hashlib.sha256(data).hexdigest()
PY
check "no quedan marcas de la actualización" v sh -c 'test ! -e /run/arx/package-upgrade-active && test ! -e /run/arx/planned-stop'

step "una actualización desde v0.0.8rc5 que falla al desempaquetar deja a Arx en marcha (B71)"
clean_victim
v dpkg -i /tmp/arxold/dist/arx_all.deb >/dev/null 2>&1
put_on_guard
check "la v0.0.8rc5 está de guardia" wait_for 30 v systemctl is-active -q arx
INV_B71=$(inv)
check "y terminó de arrancar" wait_for 45 sh -c "limactl shell '$VM' sudo journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID='$INV_B71' | grep -q 'Arx on guard'"
INC_B71=$(incidents_count)
# Otro paquete posee un fichero que la RC también trae: dpkg aborta el unpack. El .deb de la RC se reempaqueta con
# ese fichero; sus maintainer scripts son los mismos.
v bash -c 'set -e; rm -rf /tmp/b71 && mkdir -p /tmp/b71/other/DEBIAN /tmp/b71/other/usr/share/arx-b71
  printf "Package: arx-b71-other\nVersion: 1\nArchitecture: all\nMaintainer: lab <lab@example.invalid>\nDescription: B71\n" \
    > /tmp/b71/other/DEBIAN/control
  echo other > /tmp/b71/other/usr/share/arx-b71/conflict
  dpkg-deb --root-owner-group -b /tmp/b71/other /tmp/b71/other.deb >/dev/null && dpkg -i /tmp/b71/other.deb >/dev/null
  dpkg-deb -R /tmp/arxsrc/dist/arx_all.deb /tmp/b71/arx && mkdir -p /tmp/b71/arx/usr/share/arx-b71
  echo arx > /tmp/b71/arx/usr/share/arx-b71/conflict
  dpkg-deb --root-owner-group -b /tmp/b71/arx /tmp/b71/arx.deb >/dev/null'
check "dpkg aborta la actualización (fichero de otro paquete)" \
  sh -c "! limactl shell '$VM' sudo dpkg -i /tmp/b71/arx.deb >/dev/null 2>&1"
check "sigue instalada la 0.0.8~rc5" \
  sh -c "limactl shell '$VM' sudo dpkg-query -W -f='\${Version} \${Status}' arx | grep -qx '0.0.8~rc5 install ok installed'"
check "Arx vuelve a estar activo tras el abort (antes se quedaba parado y sin aviso)" wait_for 30 v systemctl is-active -q arx
INV_B71B=$(inv)
check "es un proceso nuevo, del archive anterior y sin errores de zipimport" \
  sh -c "[ -n '$INV_B71B' ] && [ '$INV_B71B' != '$INV_B71' ] && ! limactl shell '$VM' sudo journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID='$INV_B71B' | grep -qE 'ZipImportError|bad local file header'"
check "no quedan marcas de la operación" v sh -c 'test ! -e /run/arx/package-upgrade-active && test ! -e /run/arx/planned-stop'
check "y la parada planeada no dejó un self_stopped espurio" no_self_stopped_since "$INC_B71"
v bash -c 'dpkg --purge arx-b71-other >/dev/null 2>&1; rm -rf /tmp/b71'

step "víctima limpia y paquete actual"
clean_victim
v dpkg -i /tmp/arxsrc/dist/arx_all.deb >/dev/null 2>&1
put_on_guard
check "Arx activo" wait_for 30 v systemctl is-active -q arx
check "el slice hermano está instalado y tiene límite agregado" v sh -c 'grep -q "^MemoryMax=512M" /etc/systemd/system/arx-maintenance.slice'

step "una actualización sella el slice y reinicia fuera de la ventana de zipimport"
check "los dos watchers publican readiness antes de actualizar" wait_for 45 v python3 -c 'import json; w = json.load(open("/var/lib/arx/watch.json")); assert w["process"]["capture"]["running"] and w["sensitive_files"]["running"]'
INV_BEFORE=$(v systemctl show arx -p InvocationID --value | tr -d '[:space:]')
WATCH_BEFORE=$(v python3 -c 'import os; print(os.stat("/var/lib/arx/watch.json").st_mtime_ns)')
INCIDENTS_BEFORE=$(v sh -c 'test ! -f /var/lib/arx/incidents.jsonl || wc -l < /var/lib/arx/incidents.jsonl' | tr -d '[:space:]')
v python3 - <<'PY'
import json
path = "/var/lib/arx/self.json"
with open(path) as f:
    sealed = json.load(f)
sealed.pop("/etc/systemd/system/arx-maintenance.slice", None)
with open(path, "w") as f:
    json.dump(sealed, f)
with open("/etc/systemd/system/arx-maintenance.slice", "w") as f:
    f.write("[Slice]\nMemoryMax=64G\n")
PY
check "reinstalar el .deb ejecuta el refresco de mantenimiento" \
  v dpkg -i /tmp/arxsrc/dist/arx_all.deb
check "el postinst restaura el presupuesto y su sello" v python3 - <<'PY'
import hashlib, json
path = "/etc/systemd/system/arx-maintenance.slice"
data = open(path, "rb").read()
assert b"MemoryMax=512M" in data and b"MemoryMax=64G" not in data
sealed = json.load(open("/var/lib/arx/self.json"))
assert sealed[path] == hashlib.sha256(data).hexdigest()
PY
check "Arx vuelve a estar activo tras la actualización" wait_for 30 v systemctl is-active -q arx
watch_reloaded() {
  local current
  current=$(v python3 -c 'import os; print(os.stat("/var/lib/arx/watch.json").st_mtime_ns)' 2>/dev/null) || return 1
  [ -n "$current" ] && [ "$current" != "$WATCH_BEFORE" ]
}
check "el nuevo proceso publica readiness con los dos watchers" wait_for 45 watch_reloaded
INV_AFTER=$(v systemctl show arx -p InvocationID --value | tr -d '[:space:]')
new_invocation() { [ -n "$INV_AFTER" ] && [ "$INV_AFTER" != "$INV_BEFORE" ]; }
check "la actualización reemplazó el proceso antes de cualquier import mezclado" new_invocation
check "el journal de la nueva invocación no tiene errores de zipimport" \
  sh -c "! limactl shell '$VM' sudo journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID='$INV_AFTER' 2>/dev/null | grep -qE 'ZipImportError|bad local file header'"
check "la parada de actualización no genera self_stopped espurio" \
  v python3 - "$INCIDENTS_BEFORE" <<'PY'
import json, sys
path = "/var/lib/arx/incidents.jsonl"
try:
    with open(path) as f:
        rows = [json.loads(line) for line in f if line.strip()][int(sys.argv[1]):]
except FileNotFoundError:
    rows = []
assert not any(row.get("finding_kind") == "self_stopped" or row.get("kind") == "self_stopped" for row in rows), rows
PY

step "una actualización con Arx detenido conserva ese estado"
v bash -c 'systemctl stop arx.service && rm -f /run/arx/package-upgrade-active /run/arx/planned-stop'
check "reinstalar con el guardián detenido termina correctamente" v dpkg -i /tmp/arxsrc/dist/arx_all.deb
check "postinst no arranca un Arx que ya estaba detenido" v sh -c '! systemctl is-active -q arx'
check "no queda una marca que provoque un arranque posterior" v test ! -e /run/arx/package-upgrade-active

step "una marca heredada no reanima un Arx que alguien arrancó y paró después"
v bash -c 'mkdir -p /run/arx && : > /run/arx/package-upgrade-active'
v systemctl start arx
check "el guardián borra la marca al arrancar como servicio" wait_for 30 v test ! -e /run/arx/package-upgrade-active
v systemctl stop arx
check "actualizar después termina correctamente" v dpkg -i /tmp/arxsrc/dist/arx_all.deb
check "y respeta la parada manual" v sh -c '! systemctl is-active -q arx'
v systemctl start arx
check "Arx activo de nuevo" wait_for 40 v systemctl is-active -q arx

step "un arranque fallido deja el paquete reintentable con dpkg --configure -a"
check "readiness antes de actualizar" wait_for 45 watch_ready
INC_R=$(incidents_count)
lab_dropin refuse-start "RefuseManualStart=yes"
check "dpkg informa del arranque rechazado" sh -c "! limactl shell '$VM' sudo dpkg -i /tmp/arxsrc/dist/arx_all.deb >/dev/null 2>&1"
check "el paquete queda a medio configurar" sh -c "limactl shell '$VM' sudo dpkg-query -W -f='\${Status}' arx | grep -q half-configured"
check "Arx sigue parado, sin arrancar a medias" v sh -c '! systemctl is-active -q arx'
check "la marca se conserva para el reintento" v test -e /run/arx/package-upgrade-active
check "la parada planeada no se queda viva" v test ! -e /run/arx/planned-stop
lab_dropin refuse-start
check "dpkg --configure -a completa la configuración" v dpkg --configure -a
check "y vuelve a arrancar a Arx" wait_for 30 v systemctl is-active -q arx
check "el paquete queda configurado" sh -c "limactl shell '$VM' sudo dpkg-query -W -f='\${Status}' arx | grep -qx 'install ok installed'"
check "sin marca tras el reintento" v test ! -e /run/arx/package-upgrade-active
check "readiness tras el reintento" wait_for 45 watch_ready
check "sin self_stopped espurio en todo el ciclo" no_self_stopped_since "$INC_R"
check "la invocación del reintento no tiene errores de zipimport" no_zip_errors "$(inv)"

step "una parada fallida aborta antes de reemplazar el zipapp"
INV_S=$(inv)
PYZ_S=$(v stat -c '%i.%Y' /usr/lib/arx/arx.pyz | tr -d '[:space:]')
lab_dropin refuse-stop "RefuseManualStop=yes"
check "dpkg aborta la actualización" sh -c "! limactl shell '$VM' sudo dpkg -i /tmp/arxsrc/dist/arx_all.deb >/dev/null 2>&1"
check "el guardián sigue vivo con la misma invocación" test "$(inv)" = "$INV_S"
check "el zipapp en uso no se reemplazó" test "$(v stat -c '%i.%Y' /usr/lib/arx/arx.pyz | tr -d '[:space:]')" = "$PYZ_S"
check "no quedan marcas de esa operación" v sh -c 'test ! -e /run/arx/package-upgrade-active && test ! -e /run/arx/planned-stop'
check "el paquete sigue instalado" sh -c "limactl shell '$VM' sudo dpkg-query -W -f='\${Status}' arx | grep -qx 'install ok installed'"
lab_dropin refuse-stop
check "Arx queda activo para el control OOM" wait_for 40 v systemctl is-active -q arx
v sh -c 'pid=$(systemctl show -p MainPID --value arx); echo "  guardián tras arrancar: $(grep VmRSS /proc/$pid/status) · hilos $(ls /proc/$pid/task | wc -l) · memcg $(cat /sys/fs/cgroup/system.slice/arx.service/memory.current) B"'

# Este wrapper solo existe en el lab. Su nombre hace que maintenance lo clasifique como auxiliar pesado;
# en «run» ejecuta el APT/dpkg real y conserva el cgroup de ambos; en «allocate» presiona el memcg.
v python3 - <<'PY'
import os
lab = "/tmp/arx-maintenance-lab"
os.makedirs(lab + "/downloads", mode=0o777, exist_ok=True)
os.chmod(lab + "/downloads", 0o777)
source = r'''#!/usr/bin/env python3
import json, os, shutil, subprocess, sys, time

def cgroup():
    with open("/proc/self/cgroup", encoding="utf-8") as f:
        return next(line.strip()[3:] for line in f if line.startswith("0::"))

def save(path, **extra):
    cg = cgroup()
    base = "/sys/fs/cgroup" + cg
    data = {"cgroup": cg}
    for key in ("current", "peak"):
        try:
            data["memory_" + key] = int(open(base + "/memory." + key).read())
        except OSError:
            pass
    data.update(extra)
    with open(path + ".tmp", "w") as f:
        json.dump(data, f)
    os.replace(path + ".tmp", path)

mode, output = sys.argv[1:3]
start = time.monotonic()
if mode == "run":
    program = shutil.which(sys.argv[3]) or sys.argv[3]
    proc = subprocess.Popen([program, *sys.argv[4:]])
    try:
        with open(f"/proc/{proc.pid}/cgroup", encoding="utf-8") as f:
            child = next(line.strip()[3:] for line in f if line.startswith("0::"))
    except OSError:
        child = "gone"
    rc = proc.wait()
    save(output, child_cgroup=child, returncode=rc, start=start, end=time.monotonic())
    raise SystemExit(rc)
if mode == "stream":
    save(output, start=start)
    os.execv(sys.argv[3], [sys.argv[3], *sys.argv[4:]])
if mode == "hold":
    save(output, start=start)
    time.sleep(float(sys.argv[3]))
    save(output, start=start, end=time.monotonic())
    raise SystemExit(0)
if mode == "allocate":
    save(output, start=start)
    data = bytearray(640 * 1024 * 1024)
    for i in range(0, len(data), 4096):
        data[i] = 1
    time.sleep(2)
    save(output, start=start, end=time.monotonic())
    raise SystemExit(0)
raise SystemExit("unknown lab mode")
'''
for name in ("dpkg", "apt-get", "apt-cache"):
    path = lab + "/" + name
    with open(path, "w") as f:
        f.write(source)
    os.chmod(path, 0o755)
PY

step "control: la misma presión dentro de arx.service agota su memcg"
CONTROL_START=$(v date +%s | tr -d '[:space:]')
svc_high() { v awk '$1 == "high" {print $2}' /sys/fs/cgroup/system.slice/arx.service/memory.events 2>/dev/null | tr -d '[:space:]'; }
H0=$(svc_high)
# Con plazo: en Debian 6.12 el kernel mata a los ~2 min; en Ubuntu 6.8 MemoryHigh la estrangula durante decenas de
# minutos sin llegar a MemoryMax. Ambos son el modo de fallo antiguo: el guardián comparte esa presión.
v timeout -s KILL 240 python3 - control >/tmp/arx-maintenance-control.log 2>&1 <<'PY' || true
import os, sys, time
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
data = bytearray(640 * 1024 * 1024)
for i in range(0, len(data), 4096):
    data[i] = 1
time.sleep(2)
PY
kernel_oom() { v sh -c "journalctl -k --no-pager --since '@$CONTROL_START'" | grep -q 'Memory cgroup out of memory'; }
throttled() { local h1; h1=$(svc_high); [ $(( ${h1:-0} - ${H0:-0} )) -ge 1000 ]; }
if wait_for 30 kernel_oom; then
  pass "la presión dentro de arx.service la mata el kernel en el memcg de Arx (OOM)"
elif throttled; then
  pass "la presión dentro de arx.service queda estrangulada en el memcg de Arx ($(( $(svc_high) - ${H0:-0} )) eventos high, sin OOM en 240 s)"
else
  fail "la presión de control no afectó al memcg de Arx"
fi
# El control puede haber dejado al guardián estrangulado o caído: las mediciones parten de uno limpio.
v systemctl reset-failed arx >/dev/null 2>&1
v systemctl restart arx >/dev/null 2>&1
check "Arx queda activo para las mediciones" wait_for 40 v systemctl is-active -q arx
check "con los dos watchers otra vez en marcha" wait_for 45 watch_ready
INV=$(v systemctl show arx -p InvocationID --value | tr -d '[:space:]')

step "APT/dpkg reales nacen en el slice hermano"
check "dpkg --verify real termina en su scope aislado" v python3 - real <<'PY'
import sys
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(__import__("os").getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
r = maintenance.run(["/tmp/arx-maintenance-lab/dpkg", "run", "/tmp/arx-maintenance-lab/real.json",
                     "dpkg", "--verify", "arx"], capture_output=True, text=True, timeout=30)
print("returncode=", r.returncode)
raise SystemExit(r.returncode)
PY
check "wrapper y dpkg real comparten arx-maintenance.slice, no arx.service" valid_scope "$LAB/real.json"
memory_report "$LAB/real.json"

PKG=$(v sh -c 'for meta in linux-image-amd64 linux-image-generic linux-image-cloud-arm64; do
  p=$(apt-cache depends "$meta" 2>/dev/null | awk "/Depends: linux-image-/ {print \$2; exit}")
  [ -n "$p" ] && { echo "$p"; break; }; done' | tr -d '[:space:]')
check "hay un paquete grande de kernel para medir" test -n "$PKG"
if [ -n "$PKG" ]; then
  check "apt-get download real termina fuera de Arx" v python3 - "$PKG" <<'PY'
import os, sys
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
r = maintenance.run(["/tmp/arx-maintenance-lab/apt-get", "run", "/tmp/arx-maintenance-lab/apt.json",
                     "apt-get", "download", "-q", sys.argv[1]], cwd="/tmp/arx-maintenance-lab/downloads",
                    capture_output=True, text=True, timeout=240)
print("package=", sys.argv[1], "returncode=", r.returncode)
raise SystemExit(r.returncode)
PY
  check "APT y su descarga quedan en el mismo scope hermano" valid_scope "$LAB/apt.json"
  check "apt-cache policy/show reales (los del OOM de d13) también nacen fuera de Arx" v python3 - "$PKG" <<'PY2'
import os, sys
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
for i, argv in enumerate((["apt-cache", "policy", sys.argv[1]], ["apt-cache", "show", sys.argv[1]])):
    r = maintenance.run(["/tmp/arx-maintenance-lab/apt-cache", "run", f"/tmp/arx-maintenance-lab/cache-{i}.json", *argv],
                        capture_output=True, text=True, timeout=60)
    print(" ".join(argv[:2]), "returncode=", r.returncode)
    assert r.returncode == 0, r.returncode
PY2
  check "apt-cache: cada uno en su scope hermano" valid_scope "$LAB/cache-0.json" "$LAB/cache-1.json"
  memory_report "$LAB/real.json" "$LAB/apt.json" "$LAB/cache-0.json" "$LAB/cache-1.json"
  check "el mayor pico real cabe holgado bajo MemoryHigh=384M del slice" v python3 - <<'PY2'
import json
rows = {n: json.load(open(f"/tmp/arx-maintenance-lab/{n}.json")) for n in ("real", "apt", "cache-0", "cache-1")}
peak = max(r["memory_peak"] for r in rows.values())
print(f"max_real_helper_peak_mib= {peak / 2**20:.1f} · margen bajo 384 MiB = {384 * 2**20 / peak:.1f}x")
assert peak * 3 <= 384 * 2**20, peak
PY2
  DEB=$(v sh -c "ls $LAB/downloads/*.deb 2>/dev/null | head -1")
  check "el paquete grande se descargó" test -n "$DEB"
  if [ -n "$DEB" ]; then
    check "dpkg-deb en streaming se cierra y recoge su scope" v python3 - "$DEB" <<'PY'
import os, subprocess, sys
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
proc = maintenance.Popen(["/tmp/arx-maintenance-lab/dpkg", "stream", "/tmp/arx-maintenance-lab/stream.json",
                          "/usr/bin/dpkg-deb", "--fsys-tarfile", sys.argv[1]], stdout=subprocess.PIPE)
chunk = proc.stdout.read(1024 * 1024)
proc.close()
assert chunk
PY
    check "streaming: el ejecutable estaba en el slice" valid_scope "$LAB/stream.json"
    check "streaming: no queda ningún scope" wait_for 20 no_scopes
  fi
fi

step "timeout, serialización y ausencia de fallback"
check "un timeout detiene el scope completo" v python3 - <<'PY'
import os, subprocess, sys, time
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
start = time.monotonic()
try:
    maintenance.run(["/tmp/arx-maintenance-lab/dpkg", "hold", "/tmp/arx-maintenance-lab/timeout.json", "60"],
                    timeout=1)
except subprocess.TimeoutExpired:
    elapsed = time.monotonic() - start
    print("timeout_cleanup_s=", round(elapsed, 2))
    assert elapsed < 25, elapsed
else:
    raise AssertionError("the heavy helper was not timed out")
PY
check "timeout: no queda ningún scope" wait_for 20 no_scopes
check "tres auxiliares pesados se ejecutan de uno en uno" v python3 - <<'PY'
import json, os, sys, threading
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
errors = []
def one(i):
    try:
        r = maintenance.run(["/tmp/arx-maintenance-lab/dpkg", "hold",
                             f"/tmp/arx-maintenance-lab/serial-{i}.json", "0.4"], timeout=15)
        assert r.returncode == 0, r.returncode
    except Exception as exc:
        errors.append(exc)
threads = [threading.Thread(target=one, args=(i,)) for i in range(3)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join(20)
assert not errors, errors
assert not any(thread.is_alive() for thread in threads)
rows = [json.load(open(f"/tmp/arx-maintenance-lab/serial-{i}.json")) for i in range(3)]
rows.sort(key=lambda row: row["start"])
for previous, current in zip(rows, rows[1:]):
    assert previous["end"] <= current["start"], rows
print("serialized_intervals=", [(round(row["start"], 3), round(row["end"], 3)) for row in rows])
PY
check "sin systemd-run no se ejecuta nada dentro de Arx" v python3 - <<'PY'
import os, sys
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
report = "/tmp/arx-maintenance-lab/no-fallback.json"
original = maintenance.shutil.which
maintenance.shutil.which = lambda name: None
try:
    try:
        maintenance.run(["/tmp/arx-maintenance-lab/dpkg", "hold", report, "1"])
    except maintenance.MaintenanceUnavailable:
        pass
    else:
        raise AssertionError("missing isolation did not fail closed")
finally:
    maintenance.shutil.which = original
assert not os.path.exists(report), "the helper ran without isolation"
PY
check "un lock ocupado devuelve unavailable sin bloquear la guardia" v python3 - <<'PY'
import os, sys, time
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
maintenance.LOCK_WAIT_S = 0.05
maintenance._heavy_lock.acquire()
try:
    start = time.monotonic()
    try:
        maintenance.run(["/tmp/arx-maintenance-lab/dpkg", "hold",
                         "/tmp/arx-maintenance-lab/busy.json", "1"], timeout=30)
    except maintenance.MaintenanceUnavailable:
        pass
    else:
        raise AssertionError("a busy lock did not fail explicitly")
    elapsed = time.monotonic() - start
    print("busy_lock_wait_s=", round(elapsed, 3))
    assert elapsed < 1, elapsed
    assert not os.path.exists("/tmp/arx-maintenance-lab/busy.json")
finally:
    maintenance._heavy_lock.release()
PY
check "una librería repetida se investiga una vez por paquete+versión, con un solo worker" v python3 - <<'PY'
import os, sys, threading
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance, profile, trust
runs = []
def investigate(pkg, why, cfg, ask=None):  # el auxiliar real de la investigación, sin modelo
    n = len(runs)
    runs.append((pkg, threading.current_thread().name))
    r = maintenance.run(["/tmp/arx-maintenance-lab/dpkg", "hold", f"/tmp/arx-maintenance-lab/inv-{n}.json", "0.3"],
                        timeout=15)
    assert r.returncode == 0, r.returncode
    return []
trust.investigate = investigate
for _ in range(5):  # cinco servicios que cargan la misma librería actualizada
    assert profile._investigate_later("libfoo", "lab", {}, "1.0")
assert profile._investigate_later("libfoo", "lab", {}, "2.0")
profile._investigate_queue.join()
print("investigations=", runs)
assert [pkg for pkg, _ in runs] == ["libfoo", "libfoo"], runs
assert {name for _, name in runs} == {"arx-investigate"}, runs
assert sum(t.name == "arx-investigate" for t in threading.enumerate()) == 1
PY
check "investigación: cada auxiliar nació en el slice hermano" valid_scope "$LAB/inv-0.json" "$LAB/inv-1.json"
check "investigación: no queda ningún scope" wait_for 20 no_scopes

step "la presión aislada mata al auxiliar, no al guardián"
guard_oom() { v awk '$1 == "oom_kill" {print $2}' /sys/fs/cgroup/system.slice/arx.service/memory.events 2>/dev/null | tr -d '[:space:]'; }
maint_oom() { v awk '$1 == "oom_kill" {print $2}' /sys/fs/cgroup/arx.slice/arx-maintenance.slice/memory.events 2>/dev/null | tr -d '[:space:]'; }
maint_high() { v awk '$1 == "high" {print $2}' /sys/fs/cgroup/arx.slice/arx-maintenance.slice/memory.events 2>/dev/null | tr -d '[:space:]'; }
INV=$(inv)
G0=$(guard_oom); M0=$(maint_oom); MH0=$(maint_high)
check "640 MiB no caben: el presupuesto del slice para al auxiliar (OOM o, estrangulado, su timeout)" v python3 - <<'PY'
import os, subprocess, sys, time
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
start = time.monotonic()
try:
    r = maintenance.run(["/tmp/arx-maintenance-lab/dpkg", "allocate", "/tmp/arx-maintenance-lab/isolated-oom.json"],
                        timeout=300)
    print("isolated_returncode=", r.returncode, "elapsed_s=", round(time.monotonic() - start, 1))
    assert r.returncode != 0, "the memory limit did not stop the allocator"
except subprocess.TimeoutExpired:
    print("isolated_timeout_s=", round(time.monotonic() - start, 1), "(estrangulado bajo MemoryHigh; scope detenido)")
PY
G1=$(guard_oom); M1=$(maint_oom); MH1=$(maint_high)
echo "  oom_kill arx.service: ${G0:-0} → ${G1:-0} · arx-maintenance.slice: ${M0:-0} → ${M1:-0} · high del slice: ${MH0:-0} → ${MH1:-0}"
check "la presión cayó en el slice de mantenimiento (OOM o estrangulamiento allí)" \
  test "${M1:-0}" -gt "${M0:-0}" -o $(( ${MH1:-0} - ${MH0:-0} )) -ge 1000
check "no suma otro OOM al memcg de Arx" test "${G1:-0}" = "${G0:-0}"
check "el guardián conserva el mismo InvocationID" test "$(v systemctl show arx -p InvocationID --value | tr -d '[:space:]')" = "$INV"
check "y sigue activo" v systemctl is-active -q arx
check "sin scopes huérfanos al terminar" wait_for 20 no_scopes
check "el guardián sigue vigilando con los dos watchers" watch_ready
v sh -c 'pid=$(systemctl show -p MainPID --value arx); s=/sys/fs/cgroup/system.slice/arx.service; m=/sys/fs/cgroup/arx.slice/arx-maintenance.slice
  echo "  guardián: $(grep VmRSS /proc/$pid/status) · hilos $(ls /proc/$pid/task | wc -l) · arx.service memory.current $(cat $s/memory.current) B"
  echo "  arx-maintenance.slice: memory.current $(cat $m/memory.current) B · $(grep -E "^Memory(High|Max)=" /etc/systemd/system/arx-maintenance.slice | tr "\n" " ")"
  echo "  (los memory.peak de ambos incluyen las presiones deliberadas de 640 MiB del lab: $(cat $s/memory.peak) / $(cat $m/memory.peak) B)"'

[ "$FAILED" = 0 ] && v rm -rf "$LAB"
echo
[ "$FAILED" = 0 ] && echo "══ LAB DE MANTENIMIENTO COMPLETO ══" || echo "══ LAB DE MANTENIMIENTO CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
