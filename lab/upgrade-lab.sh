#!/usr/bin/env bash
# Actualización de rc2 a la rama actual en una VM con la base sellada y el servicio en marcha (R4): ¿sale alguna
# alarma que no se debe a un cambio real? Construye los dos .deb dentro de la VM (el Mac no tiene dpkg-deb), deja la VM
# como la dejaría un usuario de rc2 (reinstala rc2, aprende, sella, instala el servicio y espera a que haya perfiles),
# actualiza con `packaging/install.sh` (el camino real) y lista TODO lo que Arx registró desde entonces.
# DESTRUYE el estado de Arx de la VM (guarda una copia en /root/arx-state-before-upgrade-lab.tgz); no es para un host real.
#   ARX_LIMA_VICTIM=arx-victim RC2_REF=055f12f NEW_REF=HEAD bash lab/upgrade-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-victim}
RC2_REF=${RC2_REF:-055f12f}
NEW_REF=${NEW_REF:-HEAD}
SETTLE_S=${SETTLE_S:-150}   # tras sellar y poner el servicio: que el perfil de comportamiento cree sus sujetos
AFTER_S=${AFTER_S:-120}     # tras actualizar: al menos tres barridos
FAILED=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

v() { limactl shell "$VM" sudo "$@"; }
step() { echo; echo "══ $1 ══"; }

step "construir los dos .deb en $VM ($RC2_REF → $NEW_REF)"
git archive --format=tar "$RC2_REF" src packaging > "$WORK/rc2.tar" || exit 2
git archive --format=tar "$NEW_REF" src packaging > "$WORK/new.tar" || exit 2
limactl cp "$WORK/rc2.tar" "$VM:/tmp/upg-rc2.tar" && limactl cp "$WORK/new.tar" "$VM:/tmp/upg-new.tar" || exit 2
v sh -c 'rm -rf /tmp/upg && mkdir -p /tmp/upg/rc2 /tmp/upg/new &&
  (cd /tmp/upg/rc2 && tar xf /tmp/upg-rc2.tar && bash packaging/build-deb.sh "0.0.9~rc2" >/dev/null 2>&1 &&
    cp dist/arx_0.0.9~rc2_all.deb /tmp/upg/rc2.deb) &&
  (cd /tmp/upg/new && tar xf /tmp/upg-new.tar && bash packaging/build-deb.sh "0.0.9~rc2+upg" >/dev/null 2>&1 &&
    cp dist/arx_0.0.9~rc2+upg_all.deb /tmp/upg/new.deb) && ls -l /tmp/upg/*.deb' || { echo "[FAIL] no se pudieron construir los .deb"; exit 1; }

step "dejar la VM como un usuario de rc2"
v sh -c 'tar czf /root/arx-state-before-upgrade-lab.tgz /var/lib/arx /etc/arx 2>/dev/null; systemctl stop arx 2>/dev/null;
  arx service uninstall >/dev/null 2>&1; rm -rf /var/lib/arx/*;
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades /tmp/upg/rc2.deb >/dev/null 2>&1; dpkg -l arx | tail -1'
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v arx service install --enforce >/dev/null 2>&1
echo "esperando ${SETTLE_S} s a que el perfil de comportamiento cree sus sujetos…"
sleep "$SETTLE_S"
v sh -c 'arx status 2>&1 | grep -E "baseline|service|observation|mode"'
N0=$(v sh -c 'test -f /var/lib/arx/incidents.jsonl && wc -l < /var/lib/arx/incidents.jsonl || echo 0' | tr -d '[:space:]')
T0=$(v date +%s)
echo "incidentes antes de actualizar: $N0"

step "actualizar con install.sh (el camino real)"
v sh -c 'cd /tmp/upg/new && ARX_DEB_PATH=/tmp/upg/new.deb sh packaging/install.sh 2>&1 | head -3; dpkg -l arx | tail -1; systemctl is-active arx'
echo "esperando ${AFTER_S} s (≥ 3 barridos)…"
sleep "$AFTER_S"

step "lo que Arx registró desde la actualización"
OUT=$(v python3 - "$N0" "$T0" <<'PY'
import json, sys
n0, t0 = int(sys.argv[1]), int(sys.argv[2])
rows = []
try:
    with open("/var/lib/arx/incidents.jsonl") as f:
        rows = [json.loads(line) for line in f if line.strip()][n0:]
except FileNotFoundError:
    pass
noisy = [r for r in rows if r.get("kind") == "incident" and r.get("new")]
high = [r for r in noisy if r.get("sev") in ("high", "crit")]
for r in noisy:
    print(f"  [{r.get('sev', '?'):>4}] {r.get('finding_kind') or r.get('kind')}: {str(r.get('detail'))[:110]}")
print(f"TOTAL nuevos={len(noisy)} high_o_crit={len(high)}")
PY
)
echo "$OUT"
v sh -c 'arx status 2>&1 | grep -E "service|observation|findings|Tier 2 pending"'
HIGH=$(sed -n 's/.*high_o_crit=\([0-9]*\).*/\1/p' <<<"$OUT" | tail -1)
if [ "${HIGH:-1}" = 0 ]; then echo "[PASS] la actualización no levantó ninguna alarma high/crit"; else echo "[FAIL] alarmas high/crit tras actualizar: ${HIGH:-?}"; FAILED=1; fi
[ "$FAILED" = 0 ] && echo "RESULT: ok" || echo "RESULT: FAIL"
exit "$FAILED"
