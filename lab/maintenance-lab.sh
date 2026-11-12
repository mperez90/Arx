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
    assert d["cgroup"].startswith("/arx-maintenance.slice/arx-maint-"), d
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

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia y paquete actual"
v bash -c 'systemctl disable --now arx arx-firewall arx-revive.timer 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  systemctl list-units --type=scope --all --plain --no-legend 2>/dev/null | awk '\''$1 ~ /^arx-maint-.*\.scope$/ {print $1}'\'' | xargs -r systemctl stop
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /tmp/arx-maintenance-lab /etc/systemd/system/arx*.service \
    /etc/systemd/system/arx*.timer /etc/systemd/system/arx*.slice /etc/systemd/system/*.service.d/9[01]-arx-*.conf
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf 2>/dev/null | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload'
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v arx service install --enforce >/dev/null 2>&1
check "Arx activo" wait_for 30 v systemctl is-active -q arx
check "el slice hermano está instalado y tiene límite agregado" v sh -c 'grep -q "^MemoryMax=512M" /etc/systemd/system/arx-maintenance.slice'

step "una actualización instala y sella el slice sin rearrancar Arx"
INV_BEFORE=$(v systemctl show arx -p InvocationID --value | tr -d '[:space:]')
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
check "la actualización no rearranca el guardián" \
  test "$(v systemctl show arx -p InvocationID --value | tr -d '[:space:]')" = "$INV_BEFORE"

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
for name in ("dpkg", "apt-get"):
    path = lab + "/" + name
    with open(path, "w") as f:
        f.write(source)
    os.chmod(path, 0o755)
PY

step "control: la misma presión dentro de arx.service agota su memcg"
CONTROL_START=$(v date +%s | tr -d '[:space:]')
v python3 - control >/tmp/arx-maintenance-control.log 2>&1 <<'PY' || true
import os, sys, time
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
data = bytearray(640 * 1024 * 1024)
for i in range(0, len(data), 4096):
    data[i] = 1
time.sleep(2)
PY
kernel_oom() { v sh -c "journalctl -k --no-pager --since '@$CONTROL_START'" | grep -q 'Memory cgroup out of memory'; }
check "el kernel registra el OOM de control en el memcg de Arx" wait_for 30 kernel_oom
v systemctl reset-failed arx >/dev/null 2>&1
v systemctl start arx >/dev/null 2>&1
check "Arx queda activo para las mediciones" wait_for 40 v systemctl is-active -q arx
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
  memory_report "$LAB/real.json" "$LAB/apt.json"
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

step "la presión aislada mata al auxiliar, no al guardián"
guard_oom() { v awk '$1 == "oom_kill" {print $2}' /sys/fs/cgroup/system.slice/arx.service/memory.events 2>/dev/null | tr -d '[:space:]'; }
maint_oom() { v awk '$1 == "oom_kill" {print $2}' /sys/fs/cgroup/arx-maintenance.slice/memory.events 2>/dev/null | tr -d '[:space:]'; }
G0=$(guard_oom); M0=$(maint_oom)
check "640 MiB exceden el presupuesto del auxiliar aislado" v python3 - <<'PY'
import os, sys
with open("/sys/fs/cgroup/system.slice/arx.service/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import maintenance
r = maintenance.run(["/tmp/arx-maintenance-lab/dpkg", "allocate", "/tmp/arx-maintenance-lab/isolated-oom.json"],
                    timeout=30)
print("isolated_oom_returncode=", r.returncode)
assert r.returncode != 0, "the memory limit did not stop the allocator"
PY
G1=$(guard_oom); M1=$(maint_oom)
echo "  oom_kill arx.service: ${G0:-0} → ${G1:-0} · arx-maintenance.slice: ${M0:-0} → ${M1:-0}"
check "el OOM pertenece al slice de mantenimiento" test "${M1:-0}" -gt "${M0:-0}"
check "no suma otro OOM al memcg de Arx" test "${G1:-0}" = "${G0:-0}"
check "el guardián conserva el mismo InvocationID" test "$(v systemctl show arx -p InvocationID --value | tr -d '[:space:]')" = "$INV"
check "y sigue activo" v systemctl is-active -q arx
check "sin scopes huérfanos al terminar" wait_for 20 no_scopes
v sh -c 'echo "  arx.service:"; cat /sys/fs/cgroup/system.slice/arx.service/memory.current /sys/fs/cgroup/system.slice/arx.service/memory.peak
  echo "  arx-maintenance.slice:"; cat /sys/fs/cgroup/arx-maintenance.slice/memory.current /sys/fs/cgroup/arx-maintenance.slice/memory.peak'

[ "$FAILED" = 0 ] && v rm -rf "$LAB"
echo
[ "$FAILED" = 0 ] && echo "══ LAB DE MANTENIMIENTO COMPLETO ══" || echo "══ LAB DE MANTENIMIENTO CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
