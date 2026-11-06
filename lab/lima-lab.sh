#!/usr/bin/env bash
# D + E en un kernel real: procedencia y confinamiento, medidos desde una segunda máquina.
#   bash lab/lima-lab.sh                       # víctima Ubuntu 24.04 (systemd 255: NFTSet=)
#   ARX_LIMA_VICTIM=arx-u22 bash lab/lima-lab.sh   # víctima Ubuntu 22.04 (systemd 249: drop-in)
# Dos VM de Lima en la misma red (lima:user-v2): arx-victim (Ubuntu 24.04, systemd 255) y
# arx-attacker. Lo que un contenedor no da: kernel propio, cgroups de verdad, NFTSet= de systemd y
# un reinicio real. La víctima solo LEE este repositorio (Lima monta el home en solo lectura).
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-victim}
# Puertos propios por víctima: un agente aceptado en otra VM seguiría llamando al mismo contador
case "$VM" in arx-victim) P1=9000; P2=9001 ;; *) P1=9100; P2=9101 ;; esac
ATT=arx-attacker
WORD=palabra-del-lab
FAILED=0

step() { echo; echo "══ $1 ══"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
v() { limactl shell "$VM" sudo "$@"; }
a() { limactl shell "$ATT" "$@"; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }

for m in "$VM" "$ATT"; do
  limactl list -q 2>/dev/null | grep -qx "$m" || { echo "falta la VM $m (ver lab/README.md)"; exit 2; }
  limactl list --format '{{.Status}}' "$m" | grep -q Running || limactl start "$m" >/dev/null 2>&1
done
V=$(limactl shell "$VM" hostname -I | awk '{print $1}')
A=$(limactl shell "$ATT" hostname -I | awk '{print $1}')
echo "víctima $V · atacante $A"
printf '%s\n' 'import socket, sys' 'port = int(sys.argv[1])' \
  's = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)' \
  "s.bind(('0.0.0.0', port)); s.listen(50)" 'while True:' \
  "    c, _ = s.accept(); open(f'/tmp/hits-{port}', 'a').write('x\\n'); c.close()" \
  | limactl shell "$ATT" sh -c 'cat > /tmp/counter.py'

# El atacante cuenta cada conexión que le llega: así se mide si un programa confinado sale o no
hits() { a sh -c "cat /tmp/hits-$1 2>/dev/null | wc -l" | tr -d ' '; }
listen() {
  # `[c]` para que pkill no se encuentre a sí mismo en su propia línea de órdenes
  # aparte: en el mismo `sh -c` que lo arranca, el texto «counter.py N» también estaría y pkill lo mataría
  a pkill -f "[c]ounter.py $1"
  a sh -c "rm -f /tmp/hits-$1; setsid nohup python3 /tmp/counter.py $1 > /dev/null 2>&1 < /dev/null &"
  wait_for 10 a sh -c "ss -ltn | grep -q ':$1 '" || { echo "  el contador del atacante no arrancó"; FAILED=1; }
}
# ¿Dejan de llegar? Ventana de 10 s (el programa llama cada 2 s), con control negativo: en la misma
# ventana, un proceso NO confinado de la víctima sí debe llegar una vez. Si el contador estuviera
# muerto, «no llega nada» se cumpliría solo y no mediría nada.
CONTROL=0
quiet() {
  local h1 h2; h1=$(hits "$1")
  limactl shell "$VM" sh -c "nc -z -w 3 $A $1" >/dev/null 2>&1
  CONTROL=$((CONTROL + 1))
  sleep 10; h2=$(hits "$1"); [ "$h2" = "$((h1 + 1))" ]
}
growing() { local h1 h2; h1=$(hits "$1"); sleep 6; h2=$(hits "$1"); [ "$h2" -gt "$h1" ]; }
reaches() { a nc -z -w 3 "$V" "$1" 2>/dev/null; }
http_ok() { [ "$(a curl -s -m 4 -o /dev/null -w '%{http_code}' "http://$V:$1/")" = "200" ]; }
incident() { v grep -q "$1" /var/lib/arx/incidents.jsonl 2>/dev/null; }
no_brake() { v python3 -c "import sys; sys.path.insert(0, '/usr/lib/arx/arx.pyz')
from arx import config
from arx.modules import response as r
config.write_json(r._actions_path(), [])"; }

# Un programa sin paquete (copia de python3) que llama al atacante cada 2 s y atiende en local
AGENT='import socket, sys, threading, time, http.server
target, port, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
if len(sys.argv) > 4:
    srv = http.server.HTTPServer(("127.0.0.1", int(sys.argv[4])), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
while True:
    try:
        socket.create_connection((target, port), timeout=3).close(); r = "SALE"
    except OSError:
        r = "CORTADO"
    open(log, "a").write(r + "\n"); time.sleep(2)'

step "víctima limpia e instalación del paquete construido aquí"
# `[a]`, `[k]`: sin corchetes, pkill mataba a esta misma limpieza, cuya línea contiene esas palabras
v bash -c 'systemctl disable --now arx arx-firewall agent sidedoor evild 2>/dev/null; rm -rf /etc/systemd/system/agent.service.d; pkill -9 -f "[a]rx.pyz"
  # -9: un proceso suspendido no muere con SIGTERM, y el de una corrida anterior entraría en la línea base
  pkill -9 -f "[a]gentpy"; pkill -9 -f "[k]worker"
  # uno a uno: con varios, apt aborta entero si uno no existe y no desinstala ninguno
  for p in arx nginx nginx-common nginx-core evild; do apt-get purge -y -qq "$p" >/dev/null 2>&1; done
  rm -rf /etc/arx /var/lib/arx /opt/agent /root/.cache/.x /etc/systemd/system/agent.service /etc/systemd/system/arx.service /etc/systemd/system/arx-firewall.service /etc/systemd/system.control \
    /etc/systemd/system/sidedoor.service /tmp/arxsrc /tmp/evil*
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null; apt-get install -y -qq socat nftables dpkg-dev >/dev/null'
# dpkg -i reinstala siempre: `apt-get install` de la misma versión no hace nada y probaría el paquete viejo
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
same_build() { v sh -c 'rm -rf /tmp/built && dpkg-deb -x /tmp/arxsrc/dist/arx_all.deb /tmp/built && cmp -s /tmp/built/usr/lib/arx/arx.pyz /usr/lib/arx/arx.pyz'; }
check "lo instalado es lo que se acaba de construir" same_build
check "estado limpio: sin incidentes de una corrida anterior" v test ! -e /var/lib/arx/incidents.jsonl
check "socat instalado (lo usan los escenarios D)" v test -x /usr/bin/socat
check "el paquete instala arx" v arx --version
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" \
  | limactl shell "$VM" sudo arx setup >/dev/null 2>&1
check "arx setup deja la configuración" v test -s /etc/arx/config.json
v bash -c 'install -d -m 755 /opt/agent && cp "$(readlink -f /usr/bin/python3)" /opt/agent/agentpy && chmod 755 /opt/agent/agentpy'
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v arx service install --enforce >/dev/null 2>&1
check "el servicio queda en guardia con --enforce" v systemctl is-active -q arx
check "y la contención se repone al arrancar, antes de la red" v systemctl is-enabled -q arx-firewall

step "D: nginx de apt (repositorio firmado, su propio unit) solo avisa"
v bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null 2>&1'
check "nginx instalado y activo" v systemctl is-active -q nginx
if wait_for 90 incident "verified package"; then pass "Arx lo reconoce como paquete verificado"; else fail "Arx lo reconoce como paquete verificado"; fi
sleep 35
check "el atacante sigue llegando a nginx tras varios barridos" http_ok 80

step "D: un servicio sin paquete, aunque use un binario firmado (socat), se bloquea"
no_brake
v bash -c 'printf "[Service]\nExecStart=/usr/bin/socat TCP-LISTEN:8088,fork,reuseaddr SYSTEM:\"echo hola\"\n" > /etc/systemd/system/sidedoor.service; systemctl daemon-reload; systemctl start sidedoor'
listening() { v sh -c "ss -ltn | grep -q ':$1 '"; }
in_block() { v nft get element inet arx block_tcp "{ $1 }" >/dev/null 2>&1; }
check "precondición: el servicio escucha en 8088" wait_for 15 listening 8088
blocked_8088() { in_block 8088 && ! reaches 8088; }
if wait_for 90 blocked_8088; then pass "el atacante ya no llega al 8088"; else fail "el atacante ya no llega al 8088"; fi
check "y el motivo queda escrito" incident "not from any package"

step "D: un .deb colado, con su binario y su unit, se bloquea"
no_brake
v bash -c 'set -e; mkdir -p /tmp/evil/DEBIAN /tmp/evil/usr/sbin /tmp/evil/lib/systemd/system
  cp /usr/bin/socat /tmp/evil/usr/sbin/evild
  printf "[Service]\nExecStart=/usr/sbin/evild TCP-LISTEN:8089,fork,reuseaddr SYSTEM:\"echo hola\"\n" > /tmp/evil/lib/systemd/system/evild.service
  printf "Package: evild\nVersion: 1.0\nArchitecture: all\nMaintainer: x <x@x>\nDescription: x\n" > /tmp/evil/DEBIAN/control
  dpkg-deb -b /tmp/evil /tmp/evild.deb >/dev/null; dpkg -i /tmp/evild.deb >/dev/null; systemctl daemon-reload; systemctl start evild'
check "precondición: el servicio escucha en 8089" wait_for 15 listening 8089
blocked_8089() { in_block 8089 && ! reaches 8089; }
if wait_for 90 blocked_8089; then pass "el atacante ya no llega al 8089"; else fail "el atacante ya no llega al 8089"; fi
check "y el motivo es que viene de un paquete suelto" incident "local package"

step "E: un programa sin paquete en un unit: sigue funcionando, pero ya no sale"
no_brake
listen $P1
printf '%s\n' "$AGENT" | limactl shell "$VM" sudo tee /opt/agent/agent.py >/dev/null
v bash -c "printf '[Service]\nEnvironment=PYTHONHOME=/usr\nExecStart=/opt/agent/agentpy /opt/agent/agent.py $A $P1 /var/log/agent.log 8090\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/agent.service"
v systemctl stop arx
v bash -c 'systemctl daemon-reload; systemctl enable --now agent >/dev/null 2>&1'
check "precondición (Arx parado): el programa llega al atacante" wait_for 30 growing $P1
v systemctl start arx
if wait_for 120 quiet $P1; then pass "confinado: al atacante ya no le llega nada"; else fail "confinado: al atacante ya no le llega nada"; fi
local_ok() { [ "$(v curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/)" = "200" ]; }
check "y sigue atendiendo en local: no se ha parado" local_ok
check "su proceso no está suspendido" bash -c "! limactl shell $VM ps -o stat= -C agentpy | grep -q T"
v systemctl restart agent
sleep 5
check "reiniciar el servicio no lo libera (NFTSet=, o un drop-in con systemd < 254)" quiet $P1

step "E: el mismo programa lanzado a mano desde una sesión también queda confinado"
listen $P2
limactl shell "$VM" bash -c "setsid nohup env PYTHONHOME=/usr /opt/agent/agentpy /opt/agent/agent.py $A $P2 /tmp/agent2.log >/dev/null 2>&1 < /dev/null &"
if wait_for 120 quiet $P2; then pass "el proceso de la sesión tampoco sale"; else fail "el proceso de la sesión tampoco sale"; fi
# `[a]` para que pgrep no se encuentre a sí mismo en la línea de órdenes
check "lo hizo adoptándolo en un scope propio" bash -c "limactl shell $VM sh -c 'cat /proc/\$(pgrep -f \"[a]gent2.log\" | head -1)/cgroup' | grep -q arxconfine"

step "señales de daño: un programa en una ruta oculta se suspende"
no_brake
KPID=$(v bash -c 'install -d /root/.cache/.x && cp /usr/bin/sleep /root/.cache/.x/kworker && (setsid nohup /root/.cache/.x/kworker 600 >/dev/null 2>&1 < /dev/null & echo $!)' | tr -d '\r')
check "precondición: el programa oculto corre (pid $KPID)" v sh -c "ps -o stat= -p $KPID | grep -qv T"
stopped() { v sh -c "ps -o stat= -p $KPID" | grep -q T; }
if wait_for 90 stopped; then pass "suspendido (estado T)"; else fail "suspendido (estado T)"; fi

step "reinicio real de la víctima: lo confinado sigue confinado"
before=$(hits $P1); CONTROL=0
limactl stop "$VM" >/dev/null 2>&1; limactl start "$VM" >/dev/null 2>&1
if wait_for 150 quiet $P1; then pass "tras el reinicio, al atacante vuelve a no llegarle nada"; else fail "tras el reinicio, al atacante vuelve a no llegarle nada"; fi
# desde antes de apagar: lo que llegó menos las conexiones de control de la propia medida
leaked=$(( $(hits $P1) - before - CONTROL ))
echo "  conexiones del programa que salieron durante el arranque: $leaked"
# arx-firewall.service repone la tabla antes de que haya red, y NFTSet= persistente mete al servicio
check "ninguna salió durante el arranque (antes, una: el hueco hasta el primer barrido)" [ "$leaked" = 0 ]

step "aceptar devuelve la red"
fp=$(v python3 -c "import sys; sys.path.insert(0, '/usr/lib/arx/arx.pyz')
from arx.modules import response as r
print(next(fp for fp, e in r.load_findings().items() if e.get('item') == '/opt/agent/agentpy'))")
v arx accept "$fp" | sed 's/^/  /'
if wait_for 30 growing $P1; then pass "el programa aceptado vuelve a salir"; else fail "el programa aceptado vuelve a salir"; fi

echo
[ "$FAILED" = 0 ] && echo "══ LAB LIMA COMPLETO ══" || echo "══ LAB LIMA CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
