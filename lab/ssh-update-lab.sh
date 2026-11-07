#!/usr/bin/env bash
# Lab de A#1: una actualización de openssh-server que no es de fiar. sshd se queda sin red de salida, salvo
# lo que necesita para autenticar (DNS, Kerberos, LDAP, RADIUS); la entrada y las sesiones, intactas.
# La actualización se simula sin tocar paquetes: con Arx parado, la versión registrada pasa a ser otra y
# la instalada recibe un reparo (como si lo hubiera encontrado el modelo).
#   bash lab/ssh-update-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-victim}
WORD=palabra-del-lab
FAILED=0
SSHCFG="$HOME/.lima/$VM/ssh.config"

step() { echo; echo "══ $1 ══"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
v() { limactl shell "$VM" sudo "$@"; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }
# un login de verdad: conexión nueva, sin el maestro de Lima que multiplexa
fresh_login() { ssh -F "$SSHCFG" -o ControlMaster=no -o ControlPath=none -o ConnectTimeout=10 "lima-$VM" true; }
in_sshd() { v sh -c "echo \$\$ > /sys/fs/cgroup/system.slice/ssh.service/cgroup.procs && exec $*"; }
ssh_confined() { local out; out=$(v nft list set inet arx confined2 2>/dev/null); grep -q '"system.slice/ssh.service"' <<<"$out"; }
not_confined() { ! ssh_confined; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia y Arx"
v bash -c 'systemctl disable --now arx arx-firewall 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq nftables netcat-openbsd >/dev/null'
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx
known() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if s.get('system.slice/ssh.service', {}).get('package') else 1)"; }
check "precondición: Arx conoce ssh.service y su paquete" wait_for 60 known
check "precondición: desde el cgroup de sshd se sale a Internet" in_sshd nc -z -w 5 1.1.1.1 443
check "precondición: un login nuevo funciona" fresh_login

step "una sesión abierta antes, y la actualización no fiable de openssh-server"
limactl shell "$VM" sleep 900 > /dev/null 2>&1 &
SESSION=$!
sleep 3
VER=$(v dpkg-query -W -f='${Version}' openssh-server)
v systemctl stop arx
v python3 - "$VER" <<'PY'
import json, sys, time
ver = sys.argv[1]
p = "/var/lib/arx/profiles.json"; st = json.load(open(p))
st["subjects"]["system.slice/ssh.service"]["version"] = "0:lab-old"
json.dump(st, open(p, "w"))
t = "/var/lib/arx/trust.json"
try:
    c = json.load(open(t))
except OSError:
    c = {}
c[f"openssh-server={ver}|model"] = {"t": time.time(), "concerns": [{"what": "lab", "why": "simulated poisoned update"}]}
json.dump(c, open(t, "w"))
PY
v touch /var/lib/dpkg/status
v systemctl start arx
check "Arx deja a sshd sin red de salida" wait_for 240 ssh_confined
check "y lo explica" wait_for 30 sh -c "limactl shell $VM sudo cat /var/lib/arx/incidents.jsonl | grep -q 'ssh.service was updated to'"
check "la sesión abierta antes sigue viva" kill -0 "$SESSION"
check "un login nuevo sigue funcionando" fresh_login
cut() { ! in_sshd nc -z -w 5 1.1.1.1 443; }
check "desde el cgroup de sshd ya no se sale a Internet" cut
check "pero el DNS sí resuelve (excepción para autenticar)" in_sshd getent hosts ubuntu.com
v systemctl restart ssh
sleep 3
check "tras reiniciar sshd (cgroup nuevo): sigue sin salida" cut
check "y las excepciones se recargan: el DNS sigue resolviendo" in_sshd getent hosts ubuntu.com
check "y un login nuevo funciona" fresh_login

step "aceptar esa versión lo devuelve todo"
fp=$(v python3 -c "import sys; sys.path.insert(0, '/usr/lib/arx/arx.pyz')
from arx.modules import response as r
print(next(fp for fp, e in r.load_findings().items() if 'ssh.service was updated to' in str(e.get('detail'))))")
v arx accept "$fp" >/dev/null 2>&1
check "sshd vuelve a tener salida" wait_for 30 not_confined
check "y sale a Internet" in_sshd nc -z -w 5 1.1.1.1 443
gone() { ! v test -e /etc/systemd/system/ssh.service.d/91-arx-confallow.conf; }
check "sin restos de las excepciones" gone
kill "$SESSION" 2>/dev/null

echo
[ "$FAILED" = 0 ] && echo "══ LAB DE SSH COMPLETO ══" || echo "══ LAB DE SSH CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
