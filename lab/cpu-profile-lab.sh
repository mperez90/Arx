#!/usr/bin/env bash
# ¿En qué gasta CPU Arx en reposo? (B78: el lab de reposo midió 2,6 % en arx.service con el slice de mantenimiento a 0).
# Dos medidas, sin tocar el estado real:
#   1. CPU por hilo del arx.service vivo durante una ventana (el hilo principal es el barrido; el resto, los
#      vigilantes de exec, ficheros y DNS).
#   2. cProfile de N barridos de `guard.sweep` sobre una COPIA del estado y de la configuración (modo observación:
#      no toca nft ni el estado real) con las funciones que más CPU propia y acumulada gastan.
#   ARX_LIMA_VICTIM=arx-victim PROFILE_S=120 SWEEPS=12 bash lab/cpu-profile-lab.sh
set -uo pipefail
VM=${ARX_LIMA_VICTIM:-arx-victim}
v() { limactl shell "$VM" sudo "$@"; }

v systemctl is-active -q arx || { echo "Arx no está activo en $VM" >&2; exit 2; }
echo "# perfil de CPU en $VM · $(v sh -c '. /etc/os-release; echo "$PRETTY_NAME · $(python3 --version)"')"
v env PROFILE_S="${PROFILE_S:-120}" SWEEPS="${SWEEPS:-12}" python3 - <<'PY'
import cProfile, io, os, pstats, shutil, subprocess, sys, tempfile, time

secs, sweeps = int(os.environ["PROFILE_S"]), int(os.environ["SWEEPS"])
pid = subprocess.run(["systemctl", "show", "arx", "-p", "MainPID", "--value"], capture_output=True, text=True).stdout.strip()
hz = os.sysconf("SC_CLK_TCK")


def threads():
    out = {}
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            raw = open(f"/proc/{pid}/task/{tid}/stat").read()
            comm = raw[raw.index("(") + 1:raw.rindex(")")]
            f = raw[raw.rindex(")") + 2:].split()
            out[tid] = (comm, int(f[11]) + int(f[12]))  # utime + stime en ticks
        except (OSError, ValueError, IndexError):
            continue
    return out


print(f"\n== 1. CPU por hilo de arx.service (pid {pid}) durante {secs} s ==")
a, t0 = threads(), time.time()
time.sleep(secs)
b, wall = threads(), time.time() - t0
rows = sorted(((b[t][1] - a.get(t, ("", b[t][1]))[1]) / hz, t, b[t][0]) for t in b)
total = sum(r[0] for r in rows)
for cpu, tid, comm in reversed(rows):
    if cpu > 0:
        main = " (principal: el barrido)" if tid == pid else ""
        print(f"  tid {tid:>7} {comm:<14} {cpu:7.2f} s  {100 * cpu / wall:5.2f} %{main}")
print(f"  total {total:.2f} s en {wall:.0f} s = {100 * total / wall:.2f} % de un núcleo · {len(b)} hilos")

print(f"\n== 2. cProfile de {sweeps} barridos sobre una copia del estado ==")
tmp = tempfile.mkdtemp()
shutil.copytree("/var/lib/arx", f"{tmp}/state", symlinks=True)
shutil.copytree("/etc/arx", f"{tmp}/cfg", symlinks=True)
os.environ["ARX_STATE_DIR"], os.environ["ARX_CONFIG_DIR"] = f"{tmp}/state", f"{tmp}/cfg"
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
try:
    from arx import config
    from arx.modules import baseline, guard
    cfg, base = config.load_config(), baseline.load()
    guard.sweep(base, enforce=False, include_suid=False, cfg=cfg)  # el primero aprende y calienta cachés
    pr = cProfile.Profile()
    c0 = time.process_time()
    pr.enable()
    for _ in range(sweeps):
        guard.sweep(base, enforce=False, include_suid=False, cfg=cfg)
    pr.disable()
    cpu = time.process_time() - c0
    print(f"  {cpu / sweeps * 1000:.0f} ms de CPU por barrido (con el perfilador encima) → "
          f"{100 * cpu / sweeps / 30:.2f} % a un barrido cada 30 s")
    for key, title in (("tottime", "CPU propia"), ("cumulative", "CPU acumulada")):
        buf = io.StringIO()
        pstats.Stats(pr, stream=buf).strip_dirs().sort_stats(key).print_stats(18)
        print(f"\n  -- más {title} --")
        print("\n".join("  " + line for line in buf.getvalue().splitlines()[4:] if line.strip())[:3800])
finally:
    shutil.rmtree(tmp, ignore_errors=True)
PY
