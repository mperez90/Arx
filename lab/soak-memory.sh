#!/usr/bin/env bash
# Soak de memoria del guardián (B47): muestrea RSS, hilos, fds y memcg mientras el host hace su trabajo
# normal (logins SSH, reinicios de servicios, apt instala y quita un paquete). Nada de esto es un ataque.
# Requiere Arx ya instalado y activo en la VM (por ejemplo, tras exec-lab).
#   ARX_LIMA_VICTIM=arx-deb13-rc9 SOAK_MIN=180 bash lab/soak-memory.sh
# Salida: una línea TSV por muestra y, al final, el crecimiento por tramos.
set -uo pipefail
VM=${ARX_LIMA_VICTIM:-arx-victim}
MIN=${SOAK_MIN:-120}
EVERY=${SOAK_EVERY_S:-60}
PKG=${SOAK_PKG:-sl}
OUT=${SOAK_OUT:-/dev/stdout}
v() { limactl shell "$VM" sudo "$@"; }

sample() {
  v python3 - <<'PY'
import os, subprocess, time
def show(prop):
    return subprocess.run(["systemctl", "show", "arx", "-p", prop, "--value"], capture_output=True, text=True).stdout.strip()
def read(path):
    try:
        return open(path).read().strip()
    except OSError:
        return "-"
pid = show("MainPID")
status = dict(line.split(":", 1) for line in read(f"/proc/{pid}/status").splitlines() if ":" in line)
kb = lambda key: status.get(key, "- kB").split()[0]
try:
    fds = len(os.listdir(f"/proc/{pid}/fd"))
except OSError:
    fds = "-"
svc, maint = "/sys/fs/cgroup/system.slice/arx.service", "/sys/fs/cgroup/arx.slice/arx-maintenance.slice"
try:
    incidents = sum(1 for _ in open("/var/lib/arx/incidents.jsonl"))
except OSError:
    incidents = 0
print("\t".join(map(str, [int(time.time()), show("InvocationID")[:8], show("NRestarts"), kb("VmRSS"), kb("VmHWM"),
                          status.get("Threads", "-").strip(), fds, read(f"{svc}/memory.current"),
                          read(f"{svc}/memory.peak"), read(f"{maint}/memory.current"), read(f"{maint}/memory.peak"),
                          incidents])))
PY
}

activity() {  # $1 = minuto
  local m=$1
  v true  # cada orden de Lima es un login SSH real
  if [ $((m % 5)) = 0 ]; then v systemctl restart cron >/dev/null 2>&1; fi
  if [ $((m % 15)) = 7 ]; then
    v bash -c "export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=120 install -y -qq $PKG >/dev/null 2>&1 \
      && apt-get -o DPkg::Lock::Timeout=120 purge -y -qq $PKG >/dev/null 2>&1"
  fi
  if [ $((m % 30)) = 13 ]; then v bash -c 'apt-get -o DPkg::Lock::Timeout=120 update -qq >/dev/null 2>&1'; fi
}

v systemctl is-active -q arx || { echo "Arx no está activo en $VM: instálalo antes (p. ej. con exec-lab)" >&2; exit 2; }
{
  echo "# soak $VM · $(v sh -c '. /etc/os-release; echo "$PRETTY_NAME · kernel $(uname -r) · $(python3 --version)"') · ${MIN} min cada ${EVERY} s"
  printf 'ts\tinvocation\trestarts\trss_kb\thwm_kb\tthreads\tfds\tsvc_current\tsvc_peak\tmaint_current\tmaint_peak\tincidents\n'
} > "$OUT"
END=$(( $(date +%s) + MIN * 60 ))
m=0
while [ "$(date +%s)" -lt "$END" ]; do
  activity "$m"
  sample >> "$OUT"
  m=$((m + 1))
  sleep "$EVERY"
done

# Crecimiento: mediana de RSS del primer y último cuarto, y pendiente del último tramo.
python3 - "$OUT" <<'PY' | tee -a "${SOAK_SUMMARY:-/dev/stderr}"
import statistics, sys
rows = [line.rstrip("\n").split("\t") for line in open(sys.argv[1]) if line[:1].isdigit()]
if len(rows) < 8:
    sys.exit("too few samples")
inv = {r[1] for r in rows}
rss = [int(r[3]) for r in rows if r[3].isdigit()]
thr = [int(r[5]) for r in rows if r[5].isdigit()]
fds = [int(r[6]) for r in rows if str(r[6]).isdigit()]
q = max(2, len(rss) // 4)
first, last = statistics.median(rss[:q]), statistics.median(rss[-q:])
span_h = (int(rows[-1][0]) - int(rows[-q][0])) / 3600 or 1
tail = rss[-q:]
slope = (tail[-1] - tail[0]) / span_h
print(f"samples={len(rows)} invocations={len(inv)} restarts={rows[-1][2]}")
print(f"rss_kb first_quarter_median={first:.0f} last_quarter_median={last:.0f} max={max(rss)} "
      f"growth={last - first:+.0f} kB · last_quarter_slope={slope:+.0f} kB/h")
print(f"threads min={min(thr)} max={max(thr)} · fds min={min(fds)} max={max(fds)}")
PY
