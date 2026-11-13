#!/usr/bin/env bash
# Lab de F18.4: librerías inyectadas y ficheros sensibles, en un kernel real.
#  · acme-lib (python) carga una librería nueva: de un paquete, se aprende sin ruido; en /dev/shm, alerta
#    crítica y el servicio se queda sin salida (sigue en pie).
#  · acme-read abre su clave TLS mientras se le observa; después abre /etc/shadow: el servicio se queda sin
#    salida y se avisa. Un usuario que lee shadow desde su sesión no cuenta.
#   bash lab/files-lab.sh            ARX_LIMA_VICTIM=arx-deb13 bash lab/files-lab.sh
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
incident() { local out; out=$(v cat /var/lib/arx/incidents.jsonl 2>/dev/null); grep -q "$1" <<<"$out"; }
no_incident() { ! incident "$1"; }
confined() { local out; out=$(v nft list set inet arx confined2 2>/dev/null); grep -q "\"system.slice/$1\"" <<<"$out"; }
flag() { v sh -c "echo '$2' > /tmp/acme-$1-flag"; }
mapped() { local out; out=$(v sh -c "grep -c '$2' /proc/\$(systemctl show -p MainPID --value acme-$1)/maps"); test "${out:-0}" -gt 0; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia, Arx y dos servicios python"
v bash -c 'systemctl disable --now arx arx-firewall acme-lib acme-read 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /opt/acme-py /tmp/acme-*-flag /dev/shm/evil.so /etc/ssl/private/acme-lab.key \
    /etc/systemd/system/acme-lib.service /etc/systemd/system/acme-read.service \
    /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service /etc/systemd/system/arx*.timer
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq nftables python3 auditd >/dev/null
  systemctl enable --now auditd >/dev/null 2>&1'
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
v bash -s <<'PREP'
mkdir -p /opt/acme-py /etc/ssl/private
umask 077; echo "clave de laboratorio" > /etc/ssl/private/acme-lab.key
cat > /opt/acme-py/lib.py <<'PY'
import ctypes, os, time
while True:
    flag = open("/tmp/acme-lib-flag").read().strip() if os.path.exists("/tmp/acme-lib-flag") else ""
    if flag == "pkg":
        ctypes.CDLL("libbz2.so.1.0")
    elif flag == "evil":
        ctypes.CDLL("/dev/shm/evil.so")
    time.sleep(2)
PY
cat > /opt/acme-py/read.py <<'PY'
import os, time
while True:
    flag = open("/tmp/acme-read-flag").read().strip() if os.path.exists("/tmp/acme-read-flag") else ""
    open("/etc/shadow" if flag == "shadow" else "/etc/ssl/private/acme-lab.key").read()
    time.sleep(3)
PY
for s in lib read; do
  printf "[Service]\nExecStart=/usr/bin/python3 /opt/acme-py/$s.py\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/acme-$s.service
done
systemctl daemon-reload; systemctl enable --now acme-lib acme-read >/dev/null 2>&1
PREP
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx
files_on() { local out; out=$(v journalctl -u arx --no-pager -n 200); grep -q "sensitive files: full" <<<"$out"; }
check "cobertura fanotify completa de los ficheros sensibles" wait_for 20 files_on
learned() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if '/etc/ssl/private/acme-lab.key' in s.get('system.slice/acme-read.service', {}).get('reads', []) else 1)"; }
check "aprende que acme-read abre su clave TLS" wait_for 120 learned
watching() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if all(s.get(f'system.slice/acme-{n}.service', {}).get('status') == 'watching' for n in ('lib', 'read')) else 1)"; }
check "y los dos pasan a vigilados" wait_for 420 watching

step "librerías"
flag lib pkg
check "precondición: la librería de paquete está cargada" wait_for 30 mapped lib libbz2
sleep 70
check "una librería nueva de un paquete no avisa" no_incident "acme-lib.service loaded"
check "ni lo confina" sh -c "! limactl shell $VM sudo nft list set inet arx confined2 | grep -q acme-lib"
v sh -c 'cp "$(readlink -f $(ls /usr/lib/*/libz.so.1 /lib/*/libz.so.1 2>/dev/null | head -1))" /dev/shm/evil.so'
flag lib evil
check "precondición: /dev/shm/evil.so está cargada" wait_for 30 mapped lib /dev/shm/evil.so
check "una librería en /dev/shm: alerta crítica" wait_for 90 incident "acme-lib.service loaded /dev/shm/evil.so"
check "y el servicio se queda sin salida" wait_for 30 confined acme-lib.service
check "pero sigue en pie" v systemctl is-active -q acme-lib

step "ficheros sensibles"
v cat /etc/shadow > /dev/null   # un usuario desde su sesión: no es un servicio
flag read shadow
check "acme-read abre /etc/shadow: se avisa" wait_for 60 incident "acme-read.service opened /etc/shadow"
check "y el servicio se queda sin salida" wait_for 30 confined acme-read.service
check "pero sigue en pie" v systemctl is-active -q acme-read
check "la sesión del usuario que leyó shadow no cuenta" sh -c "! limactl shell $VM sudo grep -q 'session.*opened /etc/shadow' /var/lib/arx/incidents.jsonl"

step "intentos denegados (B50): fanotify no los ve; la regla de auditd sí"
denied_rules() { local out; out=$(v auditctl -l); grep -q "path=/etc/shadow .*key=arx_denied" <<<"$out"; }
check "precondición: las reglas de aperturas fallidas están en auditd" wait_for 30 denied_rules
limactl shell "$VM" cat /etc/shadow >/dev/null 2>&1   # el usuario de la sesión olvidó sudo: denegado, no cuenta
v systemd-run --quiet --wait --uid=nobody --unit=acme-deny sh -c 'cat /etc/shadow >/dev/null 2>&1; true'
check "un servicio como nobody que intenta leer /etc/shadow: se avisa" \
  wait_for 75 incident "nobody tried to open /etc/shadow and the kernel denied it (/usr/bin/cat"
SESSION_USER=$(limactl shell "$VM" id -un | tr -d '[:space:]')
check "el intento desde una sesión de login no cuenta" \
  sh -c "! limactl shell $VM sudo grep -q '$SESSION_USER tried to open /etc/shadow' /var/lib/arx/incidents.jsonl"
check "una lectura permitida no se cuenta como denegada" \
  sh -c "! limactl shell $VM sudo grep -q 'root tried to open' /var/lib/arx/incidents.jsonl"

v bash -c 'systemctl disable --now acme-lib acme-read >/dev/null 2>&1; rm -f /dev/shm/evil.so /tmp/acme-lib-flag /tmp/acme-read-flag'
echo
[ "$FAILED" = 0 ] && echo "══ LAB DE LIBRERÍAS Y FICHEROS COMPLETO ══" || echo "══ LAB DE LIBRERÍAS Y FICHEROS CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
