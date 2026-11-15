#!/usr/bin/env bash
# Presupuesto en reposo (B78): con Arx activo y el host quieto, ¿cuántos scopes de mantenimiento abre, cuánta CPU
# gasta y cuántas líneas deja en el journal? Nada de esto es un ataque ni toca el host: solo mira.
# Requiere Arx ya instalado y activo en la VM, con el servicio y la guardia en marcha (p. ej. tras exec-lab).
#   ARX_LIMA_VICTIM=arx-victim IDLE_MIN=30 SETTLE_MIN=5 bash lab/idle-budget-lab.sh
# Durante la ventana NO se abre ninguna sesión en la VM (cada orden de Lima es un login SSH real): se mide al
# empezar y al acabar. Los primeros SETTLE_MIN minutos no cuentan (el primer barrido aprende y consulta a dpkg).
# Criterios (plan 0.0.9, B78): < 5 scopes en 30 min, CPU de Arx < 0,5 %, < 30 líneas/h de journal por Arx,
# sin reinicios. La latencia de detección de actualizaciones la prueban los labs maintenance y supply-chain.
set -uo pipefail
VM=${ARX_LIMA_VICTIM:-arx-victim}
IDLE_MIN=${IDLE_MIN:-30}
SETTLE_MIN=${SETTLE_MIN:-5}
MAX_SCOPES=${MAX_SCOPES:-5}
MAX_CPU_PCT=${MAX_CPU_PCT:-0.5}
MAX_LINES_H=${MAX_LINES_H:-30}
FAILED=0
OUT=${IDLE_OUT:-/dev/stderr}

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
v() { limactl shell "$VM" sudo "$@"; }

# Una muestra: instante, reinicios, CPU acumulada (µs) de arx.service y del slice de mantenimiento, y el diario de
# lo que Arx dejó en el journal desde $1 (epoch; 0 = no contar). Una línea JSON.
sample() {
  local since=$1
  v python3 - "$since" <<'PY'
import json, re, subprocess, sys, time
since = int(sys.argv[1])
def show(prop):
    return subprocess.run(["systemctl", "show", "arx", "-p", prop, "--value"], capture_output=True, text=True).stdout.strip()
def cpu(path):
    try:
        for line in open(path + "/cpu.stat"):
            key, _, value = line.partition(" ")
            if key == "usage_usec":
                return int(value)
    except OSError:
        pass
    return None
def journal(*args):
    out = subprocess.run(["journalctl", "--no-pager", "-o", "cat", f"--since=@{since}", *args],
                         capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if line.strip()]
row = {"ts": time.time(), "restarts": show("NRestarts"), "invocation": show("InvocationID")[:8],
       "svc_us": cpu("/sys/fs/cgroup/system.slice/arx.service"),
       "maint_us": cpu("/sys/fs/cgroup/arx.slice/arx-maintenance.slice")}
if since:
    own = journal("_SYSTEMD_UNIT=arx.service")
    scope = [line for line in journal() if re.search(r"arx-maint-\S+\.scope", line)]
    row.update(scopes=sum(1 for line in scope if line.startswith("Started ")), scope_lines=len(scope),
               arx_lines=len(own), sample_scope_lines=scope[:6], sample_arx_lines=own[:6])
print(json.dumps(row))
PY
}

v systemctl is-active -q arx || { echo "Arx no está activo en $VM: instálalo antes (p. ej. con exec-lab)" >&2; exit 2; }
echo "# reposo en $VM · asentamiento ${SETTLE_MIN} min + ventana ${IDLE_MIN} min · $(v sh -c '. /etc/os-release; echo "$PRETTY_NAME · $(python3 --version)"')"
sleep $((SETTLE_MIN * 60))
T0=$(date +%s)
A=$(sample 0)
sleep $((IDLE_MIN * 60))
B=$(sample "$T0")
printf '%s\n%s\n' "$A" "$B" > "$OUT"

# Resumen y veredicto: el cálculo vive aquí para poder comprobarlo sin una VM.
RESULT=$(python3 - "$A" "$B" "$MAX_SCOPES" "$MAX_CPU_PCT" "$MAX_LINES_H" "$IDLE_MIN" <<'PY'
import json, sys
a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
max_scopes, max_cpu, max_lines_h, minutes = int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]), float(sys.argv[6])
wall_us = (b["ts"] - a["ts"]) * 1e6
cpu_us = sum((b[k] or 0) - (a[k] or 0) for k in ("svc_us", "maint_us"))
cpu_pct = 100 * cpu_us / wall_us if wall_us > 0 else 0.0
hours = (b["ts"] - a["ts"]) / 3600 or 1
real_min = hours * 60  # la ventana REAL entre las dos muestras (si el host se suspende, no son los minutos pedidos)
per_hour = b["scopes"] / hours
lines_h = (b["arx_lines"] + b["scope_lines"]) / hours
print(f"window={wall_us / 6e7:.1f} min scopes={b['scopes']} scope_lines={b['scope_lines']} arx_lines={b['arx_lines']} "
      f"lines_per_h={lines_h:.1f} cpu_pct={cpu_pct:.3f} restarts={a['restarts']}->{b['restarts']} "
      f"invocation={a['invocation']}->{b['invocation']}")
verdicts = [
    ("scopes por cada 30 min < %d (%d en %.0f min = %.1f/h)" % (max_scopes, b["scopes"], real_min, per_hour),
     per_hour * 0.5 < max_scopes),
    ("CPU de Arx < %.1f %% (%.3f %%)" % (max_cpu, cpu_pct), cpu_pct < max_cpu),
    ("líneas de journal por hora < %d (%.1f)" % (max_lines_h, lines_h), lines_h < max_lines_h),
    ("sin reinicios de Arx", a["restarts"] == b["restarts"] and a["invocation"] == b["invocation"]),
]
for text, ok in verdicts:
    print(("PASS " if ok else "FAIL ") + text)
for line in b.get("sample_scope_lines", []) + b.get("sample_arx_lines", []):
    print("  · " + line[:160])
PY
)
echo "$RESULT" | head -1
while IFS= read -r line; do
  case "$line" in
    "PASS "*) pass "${line#PASS }" ;;
    "FAIL "*) fail "${line#FAIL }" ;;
    "  ·"*) echo "$line" ;;
  esac
done < <(echo "$RESULT" | tail -n +2)
[ "$FAILED" = 0 ] && echo "RESULT: ok" || echo "RESULT: FAIL"
exit "$FAILED"
