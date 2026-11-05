#!/usr/bin/env bash
# Un día normal de un sysadmin, con Arx en --enforce: nada de esto es un ataque. Mide lo que el
# lab de ataques no puede: cuánto ruido hace Arx y si estorba o rompe algo.
#   bash lab/normal-day.sh
# Es una prueba sintética: da una primera cifra, y no sustituye a la semana piloto en hosts reales.
set -uo pipefail
cd "$(dirname "$0")/.."
source lab/systemd/lib.sh
lab_up

sweep_wait() { sleep 35; }  # el servicio barre cada 30 s

step "actividad normal"
echo "· instalar y arrancar nginx con apt (servicio web nuevo)"
# Debe quedar instalado de verdad: si no, lo de abajo no mediría nada
v bash -c 'set -e; apt-get update -qq 2>&1 | tail -2; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nginx curl 2>&1 | tail -3; systemctl enable --now nginx'
check "nginx quedó instalado y en marcha" v systemctl is-active -q nginx
sweep_wait
echo "· recargar y reiniciar servicios"
v bash -c 'systemctl reload nginx; systemctl restart cron; systemctl restart rsyslog'
sweep_wait
echo "· rotar logs de verdad"
v logrotate -f /etc/logrotate.d/rsyslog
sweep_wait
echo "· tmux con varias ventanas"
v bash -c 'tmux new-session -d -s trabajo; for i in 1 2 3; do tmux new-window -t trabajo; done'
sweep_wait
echo "· alta de un usuario y una tarea en su crontab"
v bash -c 'useradd -m -s /bin/bash carla; echo carla:clave-carla | chpasswd; echo "5 4 * * * /usr/bin/true" | crontab -u carla -'
sweep_wait
echo "· una app propia en /opt, escuchando en 8080"
v bash -c 'mkdir -p /opt/app; cp /usr/bin/nc.openbsd /opt/app/servidor; systemd-run --quiet --unit=miapp /opt/app/servidor -k -l 8080'
sweep_wait
echo "· un script del usuario desde su home y compilar algo temporal"
v bash -c 'install -o carla -m 755 /usr/bin/sleep /home/carla/tarea; systemd-run --quiet --uid=carla --unit=tarea /home/carla/tarea 120'
sweep_wait
echo "· actualizar paquetes"
v bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends --only-upgrade openssl libssl3 >/dev/null 2>&1; true'
sweep_wait
echo "· copias con scp desde otra máquina, sin terminal"
a sshpass -p clave-carla ssh -o StrictHostKeyChecking=no carla@victim "echo hola > /tmp/copia" 2>/dev/null
sweep_wait

step "¿Arx estorbó?"
http() { docker exec "$VIC" curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1/; }
CODE=$(http); [ "$CODE" = 200 ] && pass "nginx responde en local" || fail "nginx responde en local (HTTP $CODE)"
if reaches 80; then pass "nginx llega desde fuera"; else fail "nginx llega desde fuera (bloqueó el puerto de un servicio recién instalado)"; fi
if reaches 8080; then pass "la app de /opt llega desde fuera"; else fail "la app de /opt llega desde fuera"; fi
if reaches 22; then pass "el SSH llega desde fuera"; else fail "el SSH llega desde fuera"; fi
v bash -c 'ps -eo stat,comm | awk "\$1 ~ /^T/ {print \$2}" | sort | uniq -c' | sed 's/^/  suspendidos: /'
if v bash -c 'ps -eo stat,exe 2>/dev/null | awk "\$1 ~ /^T/" | grep -qE "/usr/|/bin/|/sbin/"'; then fail "ningún binario del sistema suspendido"; else pass "ningún binario del sistema suspendido"; fi
if v systemctl is-active -q arx; then pass "Arx sigue en pie"; else fail "Arx sigue en pie"; fi

step "la salida: lo que era tuyo se acepta y vuelve a funcionar al momento, sin reiniciar nada"
for fp in $(docker exec "$VIC" arx accept 2>/dev/null | awk '/^  [0-9a-f]{10}  /{print $1}'); do
  v arx accept "$fp" | sed 's/^/  /'
done
sleep 2
if reaches 80; then pass "nginx llega tras aceptar"; else fail "nginx llega tras aceptar"; fi
if reaches 8080; then pass "la app de /opt llega tras aceptar"; else fail "la app de /opt llega tras aceptar"; fi
if v bash -c 'ps -eo stat,comm | awk "\$1 ~ /^T/ {print \$2}" | grep -qE "servidor|tarea"'; then fail "lo aceptado ya no está suspendido"; else pass "lo aceptado ya no está suspendido"; fi
if wait_for 40 bash -c "! docker exec $VIC arx authorize 2>/dev/null | grep -q 'passwd changed'"; then pass "el alta del usuario ya no espera tu decisión"; else fail "el alta del usuario ya no espera tu decisión"; fi

step "el ruido, en cifras"
v arx metrics --days 1
v arx metrics --days 1 --json | sed 's/^/  /'
echo "--- hallazgos altos o críticos y qué hizo Arx con ellos"
vpy "
import json
for line in open('/var/lib/arx/incidents.jsonl'):
    e = json.loads(line)
    if e.get('kind') == 'incident' and e.get('new') and e.get('sev') in ('high', 'crit'):
        print(f\"  [{e['sev']}] {e.get('detail','')[:60]}  ->  T{e.get('tier')}: {e.get('status','')[:70]}\")
"
echo "--- pendientes de tu palabra"
v arx authorize | sed 's/^/  /'

echo
if [ "$FAILED" = 0 ]; then echo "══ DÍA NORMAL SIN ESTORBOS ══"; else echo "══ DÍA NORMAL: Arx ESTORBÓ (ver líneas [FAIL]) ══"; exit 1; fi
