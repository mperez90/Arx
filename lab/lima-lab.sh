#!/usr/bin/env bash
# D + E en un kernel real: procedencia y confinamiento, medidos desde una segunda máquina.
#   bash lab/lima-lab.sh                       # víctima Ubuntu 24.04 (systemd 255: NFTSet=)
#   ARX_LIMA_VICTIM=arx-u22 bash lab/lima-lab.sh   # víctima Ubuntu 22.04 (systemd 249: drop-in)
#   ARX_LIMA_LXC=c1 bash lab/lima-lab.sh           # víctima: contenedor LXC sin privilegios dentro de
#                                                  # arx-lxc (Incus), atacado a través de la VM
# Dos VM de Lima en la misma red (lima:user-v2): arx-victim (Ubuntu 24.04, systemd 255) y
# arx-attacker. Lo que un contenedor no da: kernel propio, cgroups de verdad, NFTSet= de systemd y
# un reinicio real. La víctima solo LEE este repositorio (Lima monta el home en solo lectura).
set -uo pipefail
cd "$(dirname "$0")/.."
LXC=${ARX_LIMA_LXC:-}
VM=${ARX_LIMA_VICTIM:-$([ -n "$LXC" ] && echo arx-lxc || echo arx-victim)}
# Puertos propios por víctima: un agente aceptado en otra VM seguiría llamando al mismo contador
case "$VM" in arx-victim) P1=9000; P2=9001; P3=9002; P4=9003; P5=9004 ;;
  arx-lxc) P1=9200; P2=9201; P3=9202; P4=9203; P5=9204 ;; *) P1=9100; P2=9101; P3=9102; P4=9103; P5=9104 ;; esac
ATT=arx-attacker
WORD=palabra-del-lab
FAILED=0

step() { echo; echo "══ $1 ══"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
# la víctima: la VM, o el contenedor LXC dentro de ella (-T: sin terminal, para poder pasarle stdin)
v() { if [ -n "$LXC" ]; then limactl shell "$VM" sudo incus exec -T "$LXC" -- "$@"; else limactl shell "$VM" sudo "$@"; fi; }
a() { limactl shell "$ATT" "$@"; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }
# con plazo de reloj, para lo que tarda en cada intento (quiet: 13 s): nunca un bucle sin fin, ni si el host se duerme
within() { local end=$((SECONDS + $1)); shift; while [ $SECONDS -lt $end ]; do "$@" && return 0; sleep 2; done; return 1; }

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
# Llegar = recibir la respuesta del servicio (sus «hola»), no solo completar el saludo TCP: un reenvío de
# Incus lo completa aunque el contenedor haya bloqueado el puerto
reaches() { a sh -c "nc -w 3 $V $1 < /dev/null 2>/dev/null" | grep -q hola; }
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
v bash -c 'systemctl disable --now arx arx-firewall agent sidedoor evild obs quiet 2>/dev/null; rm -rf /etc/systemd/system/agent.service.d /etc/systemd/system/obs.service* /etc/systemd/system/quiet.service*; rm -f /etc/systemd/system/*.service.d/90-arx-profile.conf; pkill -9 -f "[a]rx.pyz"
  # -9: un proceso suspendido no muere con SIGTERM, y el de una corrida anterior entraría en la línea base
  pkill -9 -f "[a]gentpy"; pkill -9 -f "[k]worker"
  # uno a uno: con varios, apt aborta entero si uno no existe y no desinstala ninguno
  for p in arx nginx nginx-common nginx-core evild; do apt-get -o DPkg::Lock::Timeout=300 purge -y -qq "$p" >/dev/null 2>&1; done
  rm -rf /etc/arx /var/lib/arx /opt/agent /root/.cache/.x /etc/systemd/system/agent.service /etc/systemd/system/arx.service /etc/systemd/system/arx-firewall.service /etc/systemd/system.control \
    /etc/systemd/system/sidedoor.service /tmp/arxsrc /tmp/evil*
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null; apt-get -o DPkg::Lock::Timeout=300 install -y -qq socat nftables dpkg-dev curl iproute2 python3 netcat-openbsd >/dev/null'
# dpkg -i reinstala siempre: `apt-get install` de la misma versión no hace nada y probaría el paquete viejo
if [ -n "$LXC" ]; then
  limactl shell "$VM" sudo bash -c "rm -rf /tmp/arxsrc && mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && incus file push /tmp/arxsrc/dist/arx_all.deb $LXC/tmp/arx_all.deb >/dev/null 2>&1"
  v bash -c "dpkg -i /tmp/arx_all.deb >/dev/null 2>&1"
  # el atacante llega al contenedor a través de la VM: reenvíos de Incus para los puertos que se miden
  for port in 80 8088 8089; do
    limactl shell "$VM" sudo incus config device add "$LXC" "p$port" proxy listen=tcp:0.0.0.0:$port connect=tcp:127.0.0.1:$port >/dev/null 2>&1
  done
  same_build() { [ "$(limactl shell "$VM" sudo sh -c 'rm -rf /tmp/built && dpkg-deb -x /tmp/arxsrc/dist/arx_all.deb /tmp/built && sha256sum < /tmp/built/usr/lib/arx/arx.pyz')" = "$(v sh -c 'sha256sum < /usr/lib/arx/arx.pyz')" ]; }
else
  v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
  same_build() { v sh -c 'rm -rf /tmp/built && dpkg-deb -x /tmp/arxsrc/dist/arx_all.deb /tmp/built && cmp -s /tmp/built/usr/lib/arx/arx.pyz /usr/lib/arx/arx.pyz'; }
fi
check "lo instalado es lo que se acaba de construir" same_build
check "estado limpio: sin incidentes de una corrida anterior" v test ! -e /var/lib/arx/incidents.jsonl
check "socat instalado (lo usan los escenarios D)" v test -x /usr/bin/socat
check "el paquete instala arx" v arx --version
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" \
  | v arx setup >/dev/null 2>&1
check "arx setup deja la configuración" v test -s /etc/arx/config.json
v bash -c 'install -d -m 755 /opt/agent && cp "$(readlink -f /usr/bin/python3)" /opt/agent/agentpy && chmod 755 /opt/agent/agentpy'
OBS='import socket, sys, time
target, ports_file = sys.argv[1], sys.argv[2]
while True:
    try:
        ports = open(ports_file).read().split()
    except OSError:
        ports = []
    for p in ports:
        try:
            socket.create_connection((target, int(p)), timeout=3).close()
        except OSError:
            pass
    time.sleep(2)'
printf '%s\n' "$OBS" | v tee /usr/local/lib/obs.py >/dev/null
v bash -c "echo $P3 > /etc/obs-ports; : > /etc/quiet-ports
  printf '[Service]\nExecStart=/usr/bin/python3 /usr/local/lib/obs.py $A /etc/obs-ports\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/obs.service
  printf '[Service]\nExecStart=/usr/bin/python3 /usr/local/lib/obs.py $A /etc/quiet-ports\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/quiet.service
  systemctl daemon-reload; systemctl enable --now obs quiet >/dev/null 2>&1; systemctl restart obs quiet"
listen "$P3"; listen "$P4"; listen "$P5"
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
# observación acortada solo para el lab (opción sin documentar): unos minutos en vez de semanas
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v arx service install --enforce >/dev/null 2>&1
check "el servicio queda en guardia con --enforce" v systemctl is-active -q arx
check "y la contención se repone al arrancar, antes de la red" v systemctl is-enabled -q arx-firewall

step "D: nginx de apt (repositorio firmado, su propio unit) solo avisa"
v bash -c 'DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq nginx >/dev/null 2>&1'
check "nginx instalado y activo" v systemctl is-active -q nginx
# el incidente del PUERTO 80: "verified package" a secas lo llevan muchos binarios del sistema
port80_verified() { v sh -c "grep 'tcp 80 all' /var/lib/arx/incidents.jsonl | grep -q 'verified package'"; }
if wait_for 90 port80_verified; then pass "Arx reconoce el puerto 80 de nginx como paquete verificado"; else fail "Arx reconoce el puerto 80 de nginx como paquete verificado"; fi
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
printf '%s\n' "$AGENT" | v tee /opt/agent/agent.py >/dev/null
v bash -c "printf '[Service]\nEnvironment=PYTHONHOME=/usr\nExecStart=/opt/agent/agentpy /opt/agent/agent.py $A $P1 /var/log/agent.log 8090\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/agent.service"
v systemctl stop arx
v bash -c 'systemctl daemon-reload; systemctl enable --now agent >/dev/null 2>&1'
check "precondición (Arx parado): el programa llega al atacante" wait_for 30 growing $P1
v systemctl start arx
if within 300 quiet $P1; then pass "confinado: al atacante ya no le llega nada"; else fail "confinado: al atacante ya no le llega nada"; fi
local_ok() { [ "$(v curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/)" = "200" ]; }
check "y sigue atendiendo en local: no se ha parado" local_ok
not_stopped() { ! v ps -o stat= -C agentpy | grep -q T; }
check "su proceso no está suspendido" not_stopped
v systemctl restart agent
sleep 5
check "reiniciar el servicio no lo libera (NFTSet=, o un drop-in con systemd < 254)" quiet $P1

step "E: el mismo programa lanzado a mano desde una sesión también queda confinado"
listen $P2
if [ -n "$LXC" ]; then
  v bash -c "setsid nohup env PYTHONHOME=/usr /opt/agent/agentpy /opt/agent/agent.py $A $P2 /tmp/agent2.log >/dev/null 2>&1 < /dev/null &"
else
  limactl shell "$VM" bash -c "setsid nohup env PYTHONHOME=/usr /opt/agent/agentpy /opt/agent/agent.py $A $P2 /tmp/agent2.log >/dev/null 2>&1 < /dev/null &"
fi
if within 300 quiet $P2; then pass "el proceso de la sesión tampoco sale"; else fail "el proceso de la sesión tampoco sale"; fi
# `[a]` para que pgrep no se encuentre a sí mismo en la línea de órdenes
adopted() { v sh -c 'cat /proc/$(pgrep -f "[a]gent2.log" | head -1)/cgroup' | grep -q arxconfine; }
check "lo hizo adoptándolo en un scope propio" adopted

step "señales de daño: un programa en una ruta oculta se suspende"
no_brake
KPID=$(v bash -c 'install -d /root/.cache/.x && cp /usr/bin/sleep /root/.cache/.x/kworker && (setsid nohup /root/.cache/.x/kworker 600 >/dev/null 2>&1 < /dev/null & echo $!)' | tr -d '\r')
check "precondición: el programa oculto corre (pid $KPID)" v sh -c "ps -o stat= -p $KPID | grep -qv T"
stopped() { v sh -c "ps -o stat= -p $KPID" | grep -q T; }
if wait_for 90 stopped; then pass "suspendido (estado T)"; else fail "suspendido (estado T)"; fi

step "reinicio real de la víctima: lo confinado sigue confinado"
# si el host se duerme (Mac con la tapa cerrada) o la víctima no vuelve, se dice por qué y el lab sigue
up() { ssh -F "$HOME/.lima/$VM/ssh.config" -o ConnectTimeout=5 -o BatchMode=yes "lima-$VM" true >/dev/null 2>&1; }
reboot_dump() {
  echo "  ── diagnóstico del reinicio ──"
  limactl list "$VM" 2>&1 | sed 's/^/  /'
  tail -n 15 "$HOME/.lima/$VM/ha.stderr.log" 2>/dev/null | cut -c1-200 | sed 's/^/  /'
  pmset -g log 2>/dev/null | grep -E " (Sleep|Wake|DarkWake) " | tail -n 4 | cut -c1-120 | sed 's/^/  host: /'
}
before=$(hits $P1); CONTROL=0
if [ -n "$LXC" ]; then limactl shell "$VM" sudo incus restart "$LXC" >/dev/null 2>&1
else limactl stop "$VM" >/dev/null 2>&1; limactl start "$VM" >/dev/null 2>&1; fi
if within 300 up; then pass "la víctima vuelve tras el reinicio"; else fail "la víctima vuelve tras el reinicio (300 s)"; reboot_dump; fi
if within 300 quiet $P1; then pass "tras el reinicio, al atacante vuelve a no llegarle nada"
else fail "tras el reinicio, al atacante vuelve a no llegarle nada"; reboot_dump; fi
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

step "observación: lo aprendido sigue; lo nuevo se corta desde el primer paquete y se avisa"
watching() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if all(s.get(k, {}).get('enforced') for k in ('system.slice/obs.service', 'system.slice/quiet.service')) else 1)"; }
# habilitados: el reinicio de antes no puede habérselos llevado, o lo de abajo no mediría nada
check "precondición: los dos servicios de prueba están activos" v systemctl is-active -q obs quiet
if wait_for 420 watching; then pass "los dos servicios pasan de observación a vigilancia"; else fail "los dos servicios pasan de observación a vigilancia"; fi
# cortado = el kernel registró el intento y al atacante no le llegó: las dos cosas, o no se midió nada
# la salida primero: con pipefail, `grep -q` puede cortar la tubería y dar fallo aunque la línea esté
attempted() { local out; out=$(v nft list set inet arx denied4); grep -F "$1" <<<"$out" | grep -qF ". tcp . $A . $2"; }
check "lo aprendido sigue funcionando" wait_for 20 growing "$P3"
v sh -c "echo '$P3 $P4' > /etc/obs-ports"
cut_p4() { attempted obs.service "$P4" && quiet "$P4"; }
if wait_for 40 cut_p4; then pass "un destino nuevo se corta: el kernel registró el intento y al atacante no le llega"; else fail "un destino nuevo se corta: el kernel registró el intento y al atacante no le llega"; fi
check "y lo aprendido sigue mientras tanto" growing "$P3"
if wait_for 70 incident "outside its usual behavior: cut"; then pass "y se avisa"; else fail "y se avisa"; fi
v sh -c "echo '$P5' > /etc/quiet-ports"
cut_p5() { attempted quiet.service "$P5" && quiet "$P5"; }
if wait_for 40 cut_p5; then pass "un servicio que nunca salió a la red no puede salir (intento registrado, nada llega)"; else fail "un servicio que nunca salió a la red no puede salir (intento registrado, nada llega)"; fi
v systemctl restart obs quiet
sleep 4
check "reiniciar el servicio no lo libera: recarga su lista antes de arrancar" quiet "$P4"
check "y tras reiniciar, lo aprendido sigue" growing "$P3"
fp=$(v python3 -c "import sys; sys.path.insert(0, '/usr/lib/arx/arx.pyz')
from arx.modules import response as r
print(next(fp for fp, e in r.load_findings().items() if e.get('kind') == 'egress_profile' and e.get('item', '').endswith('|$P4')))")
v arx accept "$fp" | sed 's/^/  /'
check "aceptar devuelve ese destino al momento" wait_for 20 growing "$P4"
v systemctl stop obs quiet

echo
[ "$FAILED" = 0 ] && echo "══ LAB LIMA COMPLETO ══" || echo "══ LAB LIMA CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
