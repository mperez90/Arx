#!/usr/bin/env bash
# ¿Se pueden silenciar «Started …scope» y «Deactivated successfully» de los scopes de consulta? (B78)
# Lanza scopes triviales con las mismas opciones que maintenance._scope_launch, con y sin
# `--property=LogLevelMax=`, y cuenta las líneas del journal de cada uno. Es un experimento, no una prueba de
# Arx: informa de tres resultados posibles y solo falla si la VM no está lista.
#   silences   → el scope acepta la propiedad y no deja líneas: se puede aplicar a los scopes de consulta
#   no-effect  → la acepta y deja las mismas líneas: no sirve
#   rejected   → systemd-run la rechaza para scopes (LogLevelMax es de unidades con ExecContext): no se aplica
#   ARX_LIMA_VICTIM=arx-victim bash lab/scope-loglevel-lab.sh
set -uo pipefail
VM=${ARX_LIMA_VICTIM:-arx-victim}
v() { limactl shell "$VM" sudo "$@"; }

v true >/dev/null 2>&1 || { echo "la VM $VM no responde" >&2; exit 2; }
echo "# scopes y LogLevelMax en $VM · $(v sh -c '. /etc/os-release; echo "$PRETTY_NAME · $(systemctl --version | head -1)"')"
v python3 - <<'PY'
import json, subprocess, time, uuid

def run(argv):
    return subprocess.run(argv, capture_output=True, text=True)

slice_ok = run(["systemctl", "show", "arx-maintenance.slice", "-p", "LoadState", "--value"]).stdout.strip() == "loaded"
variants = [("base", []), ("notice", ["--property=LogLevelMax=notice"]), ("warning", ["--property=LogLevelMax=warning"])]
tag = uuid.uuid4().hex[:6]
report = {}
for name, extra in variants:
    rcs, lines, errors = [], [], []
    for n in range(3):
        unit = f"arx-lab-{tag}-{name}-{n}.scope"
        argv = ["systemd-run", "--system", "--scope", "--quiet", "--collect", f"--unit={unit}",
                "--property=TimeoutStopSec=15", *extra, "--", "true"]
        if slice_ok:
            argv[argv.index("--collect") + 1:argv.index("--collect") + 1] = ["--slice=arx-maintenance.slice"]
        r = run(argv)
        rcs.append(r.returncode)
        if r.returncode:
            errors.append(r.stderr.strip().splitlines()[0] if r.stderr.strip() else "")
        time.sleep(1.5)
        out = run(["journalctl", "--no-pager", "-o", "cat", "--since=-30s", f"UNIT={unit}"]).stdout
        out += run(["journalctl", "--no-pager", "-o", "cat", "--since=-30s", f"_SYSTEMD_UNIT={unit}"]).stdout
        lines += [line for line in out.splitlines() if line.strip()]
    report[name] = {"rc": rcs, "lines": len(lines), "sample": lines[:4], "errors": errors[:1]}

base, notice = report["base"], report["notice"]
if any(report["notice"]["rc"]):
    verdict = "rejected"
elif notice["lines"] == 0 and base["lines"] > 0:
    verdict = "silences"
elif base["lines"] == 0:
    verdict = "no-lines-to-compare"
else:
    verdict = "no-effect"
print("slice arx-maintenance:", "sí" if slice_ok else "no (se usó el de por defecto)")
for name, r in report.items():
    note = ("· " + r["errors"][0]) if r["errors"] else ""
    print("  %-8s rc=%s líneas_de_journal=%d %s" % (name, r["rc"], r["lines"], note))
    for line in r["sample"]:
        print("      " + line[:150])
print("RESULT:", verdict)
PY
