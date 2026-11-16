#!/usr/bin/env bash
# P0 de B78/A#4: ¿cuánto tarda Arx en avisar de un destino NUEVO de un servicio ya vigilado? En observar (sin
# --enforce) debe ser ≤ 1 barrido (rc2: 30 s), no los 300 s con que se lee lo aprendido; en enforce, también (el corte
# va por `denied`). Se mide con el nft del kernel real: la sintaxis de las reglas nuevas (`novel4/6`, `watched_obs`) solo
# se comprueba aquí.
# El destino está en un espacio de red con un par veth (el tráfico por `lo` no pasa por la regla de salida).
#   ARX_LIMA_VICTIM=arx-victim bash lab/observe-latency-lab.sh
# DESTRUYE el estado de Arx de la VM (copia en /root/arx-state-before-latency-lab.tgz). Tarda unos 15 minutos.
set -uo pipefail
VM=${ARX_LIMA_VICTIM:-arx-victim}
MAX_S=${MAX_LATENCY_S:-45}   # un barrido (30 s) más el margen de la propia medición
FAILED=0

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
step() { echo; echo "══ $1 ══"; }
v() { limactl shell "$VM" sudo "$@"; }
mode_is() { v sh -c "arx status 2>/dev/null | grep -q 'mode .*$1'"; }
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 2; done; return 1; }

v systemctl is-active -q arx || { echo "Arx no está activo en $VM" >&2; exit 2; }
echo "# latencia de un destino nuevo en $VM · $(v sh -c '. /etc/os-release; echo "$PRETTY_NAME · $(nft --version)"')"

step "montar el destino (netns + veth) y un servicio que lo usa"
v bash -c '
set -e
ip netns del arxlat 2>/dev/null || true; ip link del vlat0 2>/dev/null || true
ip netns add arxlat
ip link add vlat0 type veth peer name vlat1
ip link set vlat1 netns arxlat
ip addr add 10.77.0.1/24 dev vlat0; ip link set vlat0 up
ip netns exec arxlat ip addr add 10.77.0.2/24 dev vlat1
ip netns exec arxlat ip link set vlat1 up; ip netns exec arxlat ip link set lo up
cat > /usr/local/lib/arxlat-listen.py <<PY
import socket, sys, threading
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.77.0.2", port)); s.listen(50)
    while True:
        c, _ = s.accept(); open(f"/tmp/arxlat-hits-{port}", "a").write("x\n"); c.close()
for p in (9101, 9102, 9103):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
PY
cat > /usr/local/lib/arxlat.py <<PY
import os, socket, time
while True:
    extra = open("/run/arxlat.ports").read().split() if os.path.exists("/run/arxlat.ports") else []
    for port in [9101] + [int(p) for p in extra]:
        try:
            socket.create_connection(("10.77.0.2", port), timeout=1).close()
        except OSError:
            pass
    time.sleep(2)
PY
rm -f /tmp/arxlat-hits-* /run/arxlat.ports
setsid nohup ip netns exec arxlat python3 /usr/local/lib/arxlat-listen.py >/dev/null 2>&1 < /dev/null &
printf "[Service]\nExecStart=/usr/bin/python3 /usr/local/lib/arxlat.py\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/arxlat.service
systemctl daemon-reload
'
sleep 2
check "el destino contesta desde la VM" v bash -c 'timeout 3 bash -c "echo > /dev/tcp/10.77.0.2/9101"'

step "Arx en observar, con la observación acortada (solo para el lab)"
# también la tabla del kernel: sus conjuntos (1 d) sobreviven al estado de Arx, y un corte de una pasada anterior
# salía como hallazgo «nuevo» y daba latencia 0,0 s
v sh -c 'tar czf /root/arx-state-before-latency-lab.tgz /var/lib/arx /etc/arx 2>/dev/null; systemctl stop arx; rm -rf /var/lib/arx/*; nft delete table inet arx 2>/dev/null; true'
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v systemctl enable --now arxlat >/dev/null 2>&1
v arx service install >/dev/null 2>&1       # sin --enforce: observar
check "el servicio de Arx queda activo en observar" wait_for 45 mode_is observe
watching() { v python3 -c "
import json, sys
try:
    st = json.load(open('/var/lib/arx/profiles.json')).get('subjects', {})
except (OSError, ValueError):
    sys.exit(1)
s = st.get('system.slice/arxlat.service')
sys.exit(0 if s and s.get('status') == 'watching' else 1)" 2>/dev/null; }
echo "esperando a que arxlat.service pase a vigilado (~5 min)…"
for i in $(seq 60); do watching && break; sleep 10; done
check "arxlat.service pasó a «vigilado»" watching
sleep 75   # que el barrido lo cargue en el kernel
check "el kernel conoce el servicio en watched_obs (la sintaxis de las reglas nuevas es válida)" \
  v sh -c 'nft list set inet arx watched_obs | grep -q arxlat'
check "existen las reglas y los conjuntos de lo nuevo" v sh -c 'nft list table inet arx | grep -q "add @novel4" && nft list table inet arx | grep -q "set novel4"'
check "y no cortan: ninguna regla de lo nuevo lleva drop" v sh -c '! nft list table inet arx | grep "@novel" | grep -q drop'

# Mide cuánto tarda en aparecer el hallazgo de un puerto nuevo: dentro de la VM, a 0,5 s de resolución.
measure() {  # $1 = puerto nuevo; imprime «latencia_s» o «none»
  v python3 - "$1" <<'PY'
import json, os, sys, time
from datetime import datetime
port = sys.argv[1]
t0 = time.time()
open("/run/arxlat.ports", "a").write(port + "\n")       # el servicio empieza a abrir un destino que no conoce
end = t0 + 120
while time.time() < end:
    try:
        with open("/var/lib/arx/incidents.jsonl") as f:
            for line in f:
                e = json.loads(line)
                try:  # solo lo de esta medición (resolución de 1 s en `at`)
                    fresh = datetime.fromisoformat(e.get("at")).timestamp() >= int(t0)
                except (TypeError, ValueError):
                    fresh = False
                if fresh and e.get("finding_kind") == "egress_profile" and f"10.77.0.2:{port}" in str(e.get("detail")):
                    print(f"{max(0.0, time.time() - t0):.1f}")
                    sys.exit(0)
    except (OSError, ValueError):
        pass
    time.sleep(0.5)
print("none")
PY
}

step "OBSERVAR: un destino nuevo del servicio vigilado (puerto 9102)"
L=$(measure 9102 | tail -1)
echo "  latencia: ${L} s (rc2: ≤ 30 s; lectura de lo aprendido: 300 s)"
if [ "$L" != "none" ] && awk -v l="$L" -v m="$MAX_S" 'BEGIN{exit !(l <= m)}'; then pass "observar: el destino nuevo se avisó en ${L} s (≤ ${MAX_S} s)"; else fail "observar: el destino nuevo no se avisó en ≤ ${MAX_S} s (${L})"; fi
check "observar no cortó nada: el destino sigue contestando" v sh -c 'test "$(wc -l < /tmp/arxlat-hits-9102)" -gt 3'

step "ENFORCE: otro destino nuevo (puerto 9103) se corta y se avisa a tiempo"
v arx service install --enforce >/dev/null 2>&1
v systemctl restart arx   # `install` sobre un servicio activo reescribe la unit pero no lo reinicia
check "el servicio de Arx pasó a enforce (protect)" wait_for 45 mode_is protect
sleep 100   # que el barrido lo cargue con corte
H0=$(v sh -c 'cat /tmp/arxlat-hits-9103 2>/dev/null | wc -l' | tr -d ' ')
L2=$(measure 9103 | tail -1)
echo "  latencia: ${L2} s"
if [ "$L2" != "none" ] && awk -v l="$L2" -v m="$MAX_S" 'BEGIN{exit !(l <= m)}'; then pass "enforce: el corte se avisó en ${L2} s (≤ ${MAX_S} s)"; else fail "enforce: el corte no se avisó en ≤ ${MAX_S} s (${L2})"; fi
sleep 6
H1=$(v sh -c 'cat /tmp/arxlat-hits-9103 2>/dev/null | wc -l' | tr -d ' ')
check "y el destino nuevo ya no recibe conexiones (llegaron ${H0}→${H1})" test "$((H1 - H0))" -le 3

step "limpieza"
v bash -c 'systemctl disable --now arxlat >/dev/null 2>&1; rm -f /etc/systemd/system/arxlat.service /run/arxlat.ports; pkill -f arxlat-listen.py; ip netns del arxlat 2>/dev/null; ip link del vlat0 2>/dev/null; systemctl daemon-reload; true'
echo
[ "$FAILED" = 0 ] && echo "RESULT: ok" || echo "RESULT: FAIL"
exit "$FAILED"
