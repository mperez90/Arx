# Víctima con systemd + atacante, con Arx instalado desde el .deb y como servicio: lo comparten
# lab/systemd-lab.sh y lab/normal-day.sh. Todo es efímero.
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
# El DNS de un contenedor son reglas NAT en su firewall. `systemctl start nftables` hace `flush
# ruleset` y se las lleva: sin esto, apt y los nombres dejan de funcionar y el lab mide otra cosa.
docker_dns_save() { docker exec "$VIC" sh -c 'nft list table ip nat > /var/tmp/docker-dns.nft'; }
docker_dns_restore() { docker exec "$VIC" sh -c 'nft list table ip nat >/dev/null 2>&1 || nft -f /var/tmp/docker-dns.nft'; }
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

lab_up() {
step "contenedores"
docker build -q -t arx-lab-systemd lab/systemd >/dev/null || exit 1
docker network create "$NET" >/dev/null
docker run -d --rm --name "$VIC" --privileged --cgroupns=host --pids-limit 4000 --memory 3g \
  --network "$NET" --network-alias victim \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$PWD":/src:ro arx-lab-systemd >/dev/null
docker run -d --rm --name "$ATT" --network "$NET" --network-alias attacker -v "$PWD":/src:ro ubuntu:22.04 bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq nmap netcat-openbsd sshpass curl procps python3 >/dev/null 2>&1
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
# nftables habilitado con su configuración por defecto, que trae su propia `chain input` (B22)
docker_dns_save
v systemctl start nftables
docker_dns_restore
v bash -c 'rm -rf /build && mkdir /build && cp -r /src/src /src/packaging /build/ && cd /build && packaging/build-deb.sh 2>&1 | tail -1 && dpkg -i dist/arx_all.deb >/dev/null'
check "el paquete instala arx" v arx --version
# Sin proveedores LLM: claves vacías. Respuestas en el orden del asistente.
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" \
  | docker exec -i "$VIC" arx setup >/dev/null 2>&1
check "arx setup deja la configuración" v test -s /etc/arx/config.json
# una llave legítima de root: lo que una autorización deberá poder restaurar si la alteran
v bash -c 'install -d -m 700 /root/.ssh; ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_lab -C legitima; cat /root/.ssh/id_lab.pub > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys'
v arx recon >/dev/null; v arx learn >/dev/null; v arx learn >/dev/null
v arx learn --seal | tail -3
check "con nftables habilitado, la tabla de Arx queda completa (B22)" bash -c "docker exec $VIC nft list chain inet arx input | grep -q @scan4"
v arx canaries plant >/dev/null
v arx service install --enforce | tail -1
check "el servicio queda activo" wait_for 10 v systemctl is-active -q arx
check "el unit lleva --enforce" v grep -q -- "guard --enforce" /etc/systemd/system/arx.service
}
