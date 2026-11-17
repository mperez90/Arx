#!/usr/bin/env bash
# B78-b Parte 1 · lo aprendido de un servicio muy variable, por puertos, con nft REAL.
#
# Instala la versión de antes (OLD_REF, por defecto dev/0.0.9), deja que un servicio de prueba abra 300 destinos UDP
# distintos (150 redes /24, 3 puertos: lo que hace tailscaled con sus STUN) y mide cuánto llena `seen4` y cuánto cuesta
# listarlo. Actualiza a esta versión (NEW_REF, por defecto HEAD) y comprueba, con nft de verdad:
#   · la regla nueva se acepta (sintaxis `socket cgroupv2 level 2 != @seen_ports`), la vieja se sustituye POR HANDLE una
#     sola vez, y en ningún instante el kernel se queda sin regla de aprendizaje (se muestrea mientras migra);
#   · el servicio por puertos entra en `seen_ports`, deja de llenar `seen4` (≤ 10 elementos suyos) y sus puertos
#     aparecen en `seenp4`; lo aprendido pasa a su perfil como `udp|0.0.0.0/0|<puerto>`;
#   · tras reiniciar el servicio (otro cgroup) vuelve a estar en `seen_ports`; un reinicio de Arx no duplica reglas;
#   · desinstalar lo quita todo.
#   ARX_LIMA_VICTIM=arx-victim bash lab/seen-ports-lab.sh      (y arx-deb13-rc9)
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-victim}
OLD_REF=${OLD_REF:-dev/0.0.9}
NEW_REF=${NEW_REF:-HEAD}
SVC=arx-udp-test
FAILED=0
WORK=$(mktemp -d)
v() { limactl shell "$VM" sudo "$@"; }
vb() { limactl shell "$VM" sudo bash -c "$1"; }
step() { echo; echo "══ $1 ══"; }
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }
trap 'rm -rf "$WORK"; clean' EXIT

clean() {
  vb "systemctl disable --now $SVC 2>/dev/null; rm -f /etc/systemd/system/$SVC.service /usr/local/bin/$SVC.py
    systemctl disable --now arx arx-firewall 2>/dev/null; pkill -9 -f '[a]rx.pyz' 2>/dev/null
    apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
    rm -rf /etc/arx /var/lib/arx /tmp/arxold /tmp/arxnew /tmp/arx-old.tar /tmp/arx-new.tar /tmp/seenports-*.txt \
      /etc/systemd/system/arx*.service /etc/systemd/system/arx*.timer /etc/systemd/system/arx-maintenance.slice \
      /etc/systemd/system/*.service.d/9[01]-arx-*.conf
    nft delete table inet arx 2>/dev/null; systemctl daemon-reload; true" >/dev/null 2>&1
}

# elementos de `$2` (seen4, seenp4…) que son del servicio de prueba
mine() { vb "nft list set inet arx $1 2>/dev/null | grep -o '$SVC[.]service\"* \. [^,}]*' | wc -l"; }
# CPU (usuario + sistema, ms) de listar un set, media de 5
list_ms() { vb "python3 - $1 <<'PY'
import resource, subprocess, sys
n = 5
r0 = resource.getrusage(resource.RUSAGE_CHILDREN)
for _ in range(n):
    subprocess.run(['nft', 'list', 'set', 'inet', 'arx', sys.argv[1]], capture_output=True)
r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
print(round(1000 * ((r1.ru_utime + r1.ru_stime) - (r0.ru_utime + r0.ru_stime)) / n))
PY"; }
seen_rules() { vb "nft -a list chain inet arx output | grep -c 'add @seen$1\\b'"; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1
echo "# $VM · $(v sh -c '. /etc/os-release; echo "$PRETTY_NAME · nft $(nft --version | head -1)"')"

step "construir OLD ($OLD_REF) y NEW ($NEW_REF) dentro de la VM"
git archive --format=tar "$OLD_REF" src packaging > "$WORK/old.tar" || exit 2
git archive --format=tar "$NEW_REF" src packaging > "$WORK/new.tar" || exit 2
clean
limactl cp "$WORK/old.tar" "$VM:/tmp/arx-old.tar" && limactl cp "$WORK/new.tar" "$VM:/tmp/arx-new.tar" || exit 2
vb 'export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 install -y -qq nftables python3 auditd >/dev/null 2>&1
  systemctl enable --now auditd >/dev/null 2>&1
  rm -rf /tmp/arxold /tmp/arxnew; mkdir /tmp/arxold /tmp/arxnew
  (cd /tmp/arxold && tar xf /tmp/arx-old.tar && bash packaging/build-deb.sh "0.0.9~rc8+old" >/dev/null 2>&1)
  (cd /tmp/arxnew && tar xf /tmp/arx-new.tar && bash packaging/build-deb.sh "0.0.9~rc9+ports" >/dev/null 2>&1)
  ls -l /tmp/arxold/dist/arx_all.deb /tmp/arxnew/dist/arx_all.deb' || { fail "no se pudieron construir los .deb"; exit 1; }

step "instalar OLD, base sellada y --enforce"
vb 'dpkg -i /tmp/arxold/dist/arx_all.deb >/dev/null 2>&1; arx --version'
printf '%s\n' "en" "" "" "" "palabra-del-lab" "palabra-del-lab" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
vb 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v arx service install --enforce >/dev/null 2>&1
v systemctl is-active -q arx || { fail "Arx no quedó en guardia"; exit 1; }
sleep 40
echo "  reglas de seen4 (OLD): $(seen_rules 4) · seen_ports existe: $(vb 'nft list set inet arx seen_ports >/dev/null 2>&1 && echo sí || echo no')"
[ "$(seen_rules 4)" = 1 ] && pass "OLD: una regla de seen4, sin seen_ports (como en todas las instalaciones)" || fail "OLD: reglas de seen4 inesperadas"

step "servicio de prueba: 300 destinos UDP distintos (150 redes /24) en 3 puertos"
vb "cat > /usr/local/bin/$SVC.py <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ports = (3478, 3479, 41641)
while True:
    for i in range(150):
        for j in (1, 2):
            try:
                s.sendto(b'x', ('198.18.%d.%d' % (i, j), ports[(i + j) % 3]))
            except OSError:
                pass
    time.sleep(20)
PY
cat > /etc/systemd/system/$SVC.service <<EOF
[Unit]
Description=Arx lab: 300 UDP destinations
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/$SVC.py
EOF
systemctl daemon-reload; systemctl start $SVC"
for _ in $(seq 18); do [ "$(mine seen4)" -ge 100 ] && break; sleep 5; done  # hasta 90 s: depende de cuándo arranque el servicio
OLDN=$(mine seen4); OLDMS=$(list_ms seen4)
echo "  seen4 con OLD: $OLDN elementos del servicio · listar seen4 = ${OLDMS} ms de CPU"
[ "${OLDN:-0}" -ge 100 ] && pass "OLD llena seen4 con sus destinos ($OLDN)" || fail "el servicio de prueba no llenó seen4 ($OLDN)"

step "actualizar a NEW mientras se muestrea que nunca falte la regla de aprendizaje"
vb 'rm -f /tmp/seenports-min.txt; ( min=99; end=$((SECONDS+75)); while [ $SECONDS -lt $end ]; do
    n=$(nft -a list chain inet arx output 2>/dev/null | grep -c "add @seen4\b"); [ "$n" -lt "$min" ] && min=$n; sleep 0.02; done
    echo $min > /tmp/seenports-min.txt ) >/dev/null 2>&1 &'
# un dpkg -i no reinicia el proceso que ya corre con el código de antes: se reinicia, como al actualizar de verdad
vb 'dpkg -i /tmp/arxnew/dist/arx_all.deb >/dev/null 2>&1; systemctl restart arx; arx --version; systemctl is-active arx'
sleep 80
echo "  mínimo de reglas de seen4 durante la migración: $(vb 'cat /tmp/seenports-min.txt 2>/dev/null')"
[ "$(vb 'cat /tmp/seenports-min.txt 2>/dev/null')" -ge 1 ] 2>/dev/null && pass "nunca sin regla de aprendizaje" || fail "hubo un instante sin regla de seen4"
for fam in 4 6; do
  [ "$(seen_rules $fam)" = 1 ] && pass "seen$fam: UNA regla (la vieja se sustituyó, no se duplicó)" || fail "seen$fam: $(seen_rules $fam) reglas"
  vb "nft list chain inet arx output | grep 'add @seen$fam\\b' | grep -q '!= @seen_ports'" && pass "la regla de seen$fam deja fuera @seen_ports (nft real la aceptó)" || fail "la regla de seen$fam no lleva la exclusión"
  vb "nft list chain inet arx output | grep -c 'add @seenp$fam'" | grep -qx 1 && pass "una regla de seenp$fam" || fail "reglas de seenp$fam inesperadas"
done
vb 'nft -a list chain inet arx output | grep -E "@seen|@denied" | sed "s/meta oifname.*socket cgroupv2 level 1/…/" | cut -c1-150' | sed 's/^/    /'

step "el servicio por puertos entra en seen_ports y deja de llenar seen4"
sleep 70
vb 'nft list set inet arx seen_ports 2>&1 | tr "\n" " " | cut -c1-200'
vb "nft list set inet arx seen_ports 2>/dev/null | grep -q '$SVC.service'" && pass "$SVC está en seen_ports" || fail "$SVC no está en seen_ports"
NEWN=$(mine seen4); PN=$(mine seenp4)
echo "  seen4 tras NEW: $NEWN elementos del servicio · seenp4: $PN"
[ "${NEWN:-99}" -le 10 ] && pass "seen4 ≤ 10 elementos del servicio (antes $OLDN)" || fail "seen4 sigue lleno ($NEWN)"
[ "${PN:-0}" -ge 1 ] && [ "${PN:-9}" -le 3 ] && pass "seenp4 trae sus puertos ($PN ≤ 3)" || fail "seenp4 inesperado ($PN)"
NEWMS=$(list_ms seen4)
echo "  listar seen4: ${OLDMS} ms con ${OLDN} elementos suyos → ${NEWMS} ms con ${NEWN} (en esta VM, con pocos cgroups, listar es barato:"
echo "  el coste de ~8 ms por elemento del piloto A depende de cuántos cgroups tenga el host; aquí se mide cuántos elementos quedan)"

step "lo aprendido pasa a su perfil como cualquier dirección en ese puerto"
v systemctl restart arx; sleep 50
vb 'python3 - <<PY
import json
st = json.load(open("/var/lib/arx/profiles.json"))
s = st["subjects"].get("system.slice/arx-udp-test.service") or {}
d = s.get("dest", {})
ports = sorted(k for k in d if "|0.0.0.0/0|" in k)
nets = {k.split("|")[1] for k in d}
print("  estado:", s.get("status"), "· redes:", len(nets), "· puertos aprendidos:", ports)
PY'
vb "python3 -c \"
import json
d = json.load(open('/var/lib/arx/profiles.json'))['subjects'].get('system.slice/$SVC.service', {}).get('dest', {})
raise SystemExit(0 if {'udp|0.0.0.0/0|3478', 'udp|0.0.0.0/0|3479', 'udp|0.0.0.0/0|41641'} <= set(d) else 1)\"" \
  && pass "sus 3 puertos están en el perfil como udp|0.0.0.0/0|puerto" || fail "los puertos no llegaron al perfil"

step "un reinicio del servicio (otro cgroup) vuelve a ponerlo en seen_ports; un reinicio de Arx no duplica reglas"
OLDCG=$(vb "nft list set inet arx seen_ports 2>/dev/null | grep -o '$SVC.service' | head -1")
v systemctl restart $SVC; sleep 45
vb "nft list set inet arx seen_ports 2>/dev/null | grep -q '$SVC.service'" && pass "tras reiniciar el servicio, sigue en seen_ports" || fail "el servicio reiniciado no está en seen_ports"
v systemctl restart arx; sleep 40
for fam in 4 6; do
  [ "$(seen_rules $fam)" = 1 ] && [ "$(vb "nft list chain inet arx output | grep -c 'add @seenp$fam'")" = 1 ] \
    && pass "tras reiniciar Arx: seen$fam y seenp$fam siguen con UNA regla" || fail "reglas duplicadas o ausentes en $fam"
done

step "desinstalar lo quita todo"
v arx service uninstall >/dev/null 2>&1
vb 'nft list table inet arx >/dev/null 2>&1' && fail "la tabla de Arx sigue ahí tras desinstalar" || pass "la tabla (sets y reglas incluidos) ya no existe"

echo
[ "$FAILED" = 0 ] && echo "══ B78-b P1 REAL: regla sustituida sin hueco, seen_ports/seenp funcionan, seen ya no se llena (${OLDN}→${NEWN} elementos del servicio) ══" \
  || echo "══ B78-b P1 REAL: HAY FALLOS (ver [FAIL]) ══"
exit "$FAILED"
