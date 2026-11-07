#!/usr/bin/env bash
# Lab de DoD-4: instalar, que Arx confine y vigile, y desinstalar sin dejar nada suyo. Lo que estaba
# confinado recupera la red y los servicios arrancan sin los drop-ins de Arx.
#   bash lab/uninstall-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-victim}
WORD=palabra-del-lab
FAILED=0

step() { echo; echo "══ $1 ══"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
v() { limactl shell "$VM" sudo "$@"; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }
in_unit() { local u="$1"; shift; v sh -c "echo \$\$ > /sys/fs/cgroup/system.slice/$u/cgroup.procs && exec $*"; }
leftovers() { v sh -c 'ls /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service 2>/dev/null
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf
  nft list table inet arx >/dev/null 2>&1 && echo "tabla inet arx"
  ls -d /etc/arx /var/lib/arx 2>/dev/null; true'; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia, Arx instalado desde su paquete"
v bash -c 'systemctl disable --now arx arx-firewall loose 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /opt/loose /etc/systemd/system/loose.service \
    /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq socat nftables netcat-openbsd >/dev/null'
check "precondición: sin restos de antes" test -z "$(leftovers)"
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx

step "Arx deja huella: un programa sin paquete confinado, y servicios vigilados"
v bash -c 'mkdir -p /opt/loose && cp /usr/bin/socat /opt/loose/server
  printf "[Service]\nExecStart=/opt/loose/server TCP-LISTEN:8099,fork,reuseaddr SYSTEM:\"echo loose\"\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/loose.service
  systemctl daemon-reload; systemctl enable --now loose >/dev/null 2>&1'
# leer primero y buscar después: grep devuelve 2 si uno de los globs no existe, aunque el otro case
pinned() { local out; out=$(v sh -c 'cat /etc/systemd/system.control/loose.service.d/*.conf /etc/systemd/system/loose.service.d/*.conf 2>/dev/null')
  grep -qE "inet:arx:confined|inet arx confined" <<<"$out"; }
if wait_for 90 pinned; then pass "precondición: loose.service confinado y atado a su set"; else
  fail "precondición: loose.service confinado y atado a su set"
  v sh -c 'systemctl show loose -p NFTSet; ls -R /etc/systemd/system.control 2>/dev/null | head; for p in $(pgrep -f /opt/loose/server); do cat /proc/$p/cgroup; done
    nft list set inet arx confined2; nft list set inet arx confined3; grep -h loose /var/lib/arx/incidents.jsonl | cut -c1-300'
fi
check "precondición: desde loose no se sale" sh -c "! limactl shell $VM sudo sh -c 'echo \$\$ > /sys/fs/cgroup/system.slice/loose.service/cgroup.procs && exec nc -z -w 5 1.1.1.1 443'"
profiled() { v sh -c 'ls /etc/systemd/system/*.service.d/90-arx-profile.conf' >/dev/null 2>&1; }
check "precondición: servicios vigilados con su drop-in" wait_for 420 profiled

step "autoprotección: pararlo o tocarlo queda dicho (DoD-6)"
incident() { local out; out=$(v cat /var/lib/arx/incidents.jsonl 2>/dev/null); grep -q "$1" <<<"$out"; }
v systemctl stop arx
check "parar Arx queda anotado (y se avisaría por los canales)" wait_for 20 incident "self_stopped"
v bash -c 'mkdir -p /etc/systemd/system/arx.service.d && printf "[Service]\nEnvironment=X=1\n" > /etc/systemd/system/arx.service.d/override.conf
  systemctl daemon-reload; systemctl start arx'
check "un drop-in ajeno en su unit da alerta crítica" wait_for 60 incident "someone added drop-ins to Arx"
v bash -c 'rm -rf /etc/systemd/system/arx.service.d; systemctl daemon-reload; systemctl restart arx'

step "desinstalar (purge)"
v bash -c 'DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1'
check "Arx ya no corre" sh -c "! limactl shell $VM systemctl is-active -q arx"
LEFT=$(leftovers)
[ -n "$LEFT" ] && echo "  restos: $LEFT"
check "sin restos: drop-ins, pines, units, tabla nft, configuración ni estado" test -z "$LEFT"
check "loose.service sigue en pie" v systemctl is-active -q loose
check "y recupera la red" in_unit loose.service nc -z -w 5 1.1.1.1 443
v systemctl restart loose cron
check "los servicios arrancan sin los drop-ins de Arx" v systemctl is-active -q loose cron

v bash -c 'systemctl disable --now loose >/dev/null 2>&1; rm -rf /opt/loose /etc/systemd/system/loose.service; systemctl daemon-reload'
echo
[ "$FAILED" = 0 ] && echo "══ LAB DE DESINSTALACIÓN COMPLETO ══" || echo "══ LAB DE DESINSTALACIÓN CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
