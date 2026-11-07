#!/usr/bin/env bash
# Lab de A#9: con sshd confinado tras una actualización no fiable (también sus conexiones por instancia,
# sshd@), desinstalar Arx no puede dejar a nadie fuera: login nuevo, sin drop-ins en ssh@/sshd@, sin tabla
# inet arx, y las conexiones vuelven a tener salida.
#   ARX_LIMA_VICTIM=arx-deb13 bash lab/ssh-uninstall-lab.sh
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
fresh_login() { ssh -F "$SSHCFG" -o ControlMaster=no -o ControlPath=none -o ConnectTimeout=10 "lima-$VM" true; }
in_sshd() { v sh -c "echo \$\$ > /sys/fs/cgroup/system.slice/ssh.service/cgroup.procs && exec $*"; }
ssh_confined() { local out; out=$(v nft list set inet arx confined2 2>/dev/null); grep -q '"system.slice/ssh.service"' <<<"$out"; }
inst() { v sh -c 'ls -d /sys/fs/cgroup/system.slice/system-sshd.slice/sshd@*.service 2>/dev/null | head -1'; }
in_inst() { local i; i=$(inst); [ -n "$i" ] && v sh -c "echo \$\$ > '$i/cgroup.procs' && exec $*"; }
leftovers() { v sh -c 'ls /etc/systemd/system/ssh@.service.d/91-arx-* /etc/systemd/system/sshd@.service.d/91-arx-* \
  /etc/systemd/system/ssh.service.d/9[01]-arx-* 2>/dev/null; nft list table inet arx >/dev/null 2>&1 && echo "tabla inet arx"; true'; }

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

step "actualización no fiable de openssh-server: sshd y sus conexiones por instancia, sin salida"
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
check "precondición: sshd queda sin salida" wait_for 240 ssh_confined
if [ -n "$(inst)" ]; then
  check "precondición: la plantilla sshd@ lleva su drop-in" v test -e /etc/systemd/system/sshd@.service.d/91-arx-confallow.conf
  check "precondición: y una conexión por instancia no sale" sh -c "! limactl shell $VM sudo sh -c 'echo \$\$ > \"$(inst)/cgroup.procs\" && exec nc -z -w 5 1.1.1.1 443'"
fi
check "precondición: un login nuevo funciona con Arx confinando" fresh_login

step "desinstalar (purge) con todo eso confinado"
v bash -c 'DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1'
LEFT=$(leftovers)
[ -n "$LEFT" ] && echo "  restos: $LEFT"
check "sin drop-ins de Arx en ssh, ssh@ ni sshd@, y sin tabla inet arx" test -z "$LEFT"
OK=0; for i in $(seq 10); do fresh_login && OK=$((OK + 1)); done
check "10 logins nuevos tras desinstalar (hechos: $OK)" test "$OK" = 10
check "sshd vuelve a salir" in_sshd nc -z -w 5 1.1.1.1 443
[ -n "$(inst)" ] && check "y sus conexiones por instancia también" in_inst nc -z -w 5 1.1.1.1 443
v systemctl restart ssh
check "y tras reiniciar sshd, un login nuevo" fresh_login

echo
[ "$FAILED" = 0 ] && echo "══ LAB DE DESINSTALACIÓN CON SSH CONFINADO COMPLETO ══" || echo "══ LAB DE DESINSTALACIÓN CON SSH CONFINADO CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
