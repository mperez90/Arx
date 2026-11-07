#!/usr/bin/env bash
# Lab de lo que lanzan los servicios (F18.2), en un kernel real (Lima):
#  · control negativo: muchos logins SSH reales (cada orden de Lima lo es) y ninguna alarma de
#    «sshd antes de autenticar» (el patrón de xz no puede saltar con lo normal);
#  · webshell: un «nginx» que, como www-data, lanza una shell. Se congela; el servicio sigue;
#  · lo aprendido: un servicio que, tras su observación, lanza un programa nuevo. Ese proceso se queda
#    sin red en su propio scope y sigue corriendo; el servicio también.
#   bash lab/exec-lab.sh
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

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia y Arx"
v bash -c 'systemctl disable --now arx arx-firewall acme-web acme-gen 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /etc/systemd/system/acme-web.service /etc/systemd/system/acme-gen.service \
    /usr/local/bin/nginx /usr/local/bin/acme-handler /tmp/acme-flag /opt/acme /etc/systemd/system/*.service.d/90-arx-*.conf \
    /etc/systemd/system/arx*.service
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq socat nftables netcat-openbsd python3 >/dev/null'
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version

# dos servicios de prueba: un «nginx» (socat con ese nombre) como www-data, y uno que lanza lo que diga su manejador
v bash -c 'cp /usr/bin/socat /usr/local/bin/nginx
  printf "[Service]\nUser=www-data\nExecStart=/usr/local/bin/nginx TCP-LISTEN:8097,fork,reuseaddr SYSTEM:\"sleep 60; echo web\"\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/acme-web.service
  mkdir -p /opt/acme/tools && cp /usr/bin/sleep /opt/acme/tools/a && cp /usr/bin/sleep /opt/acme/tools/b
  printf "import time\ntime.sleep(120)\n" > /opt/acme/sleep.py
  printf "#!/bin/sh\nif [ -f /tmp/acme-flag ]; then exec \$(cat /tmp/acme-flag); fi\nexec /usr/bin/sleep 2\n" > /usr/local/bin/acme-handler; chmod 755 /usr/local/bin/acme-handler
  printf "[Service]\nExecStart=/usr/bin/socat TCP-LISTEN:8098,fork,reuseaddr SYSTEM:/usr/local/bin/acme-handler\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/acme-gen.service
  systemctl daemon-reload; systemctl enable --now acme-web acme-gen >/dev/null 2>&1'
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx
kernel_watch() { local out; out=$(v journalctl -u arx --no-pager -n 200); grep -q "process watch: in the kernel" <<<"$out"; }
check "vigila cada exec desde el kernel (conector de procesos)" wait_for 20 kernel_watch

step "aprender: acme-gen lanza su manejador y sleep mientras se le observa"
poke() { limactl shell "$VM" sh -c "nc -w 1 127.0.0.1 $1 < /dev/null > /dev/null 2>&1"; }
for i in 1 2 3; do poke 8098; sleep 2; done
watching() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if s.get('system.slice/acme-gen.service', {}).get('status') == 'watching' else 1)"; }
if wait_for 420 watching; then pass "acme-gen pasó a vigilado"; else fail "acme-gen pasó a vigilado"; fi
learned() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if '/usr/bin/sleep' in s.get('system.slice/acme-gen.service', {}).get('execs', []) else 1)"; }
check "y aprendió que lanza sleep" learned

step "webshell: el «nginx» lanza una shell como www-data"
poke 8097 &
shell_pid() { v sh -c 'pgrep -u www-data -x sleep | head -1'; }
frozen() { local p; p=$(v sh -c 'for p in $(pgrep -u www-data -f "sleep 60"); do ps -o stat= -p $p; done' | tr -d ' '); grep -q T <<<"$p"; }
check "se avisa: un servicio web lanzó una shell" wait_for 60 incident "started /usr/bin/dash as www-data"
check "y esa shell queda congelada" wait_for 30 frozen
web_alive() { v systemctl is-active -q acme-web; }
check "el servicio web sigue en pie" web_alive

step "lo nuevo: acme-gen lanza un intérprete que nunca lanzó"
v sh -c 'echo "/usr/bin/python3 /opt/acme/sleep.py" > /tmp/acme-flag'
poke 8098
check "se avisa del programa nuevo" wait_for 60 incident "acme-gen.service started /usr/bin/python3"
cg_of() { v sh -c "for p in \$(pgrep -f '$1'); do cat /proc/\$p/cgroup; ps -o stat= -p \$p; done"; }
isolated() { local out; out=$(cg_of "acme/sleep.py"); grep -q "arxconfine" <<<"$out" && ! grep -q "T" <<<"$(tail -1 <<<"$out")"; }
check "ese proceso queda en su propio scope sin red, y sigue corriendo" wait_for 30 isolated

step "ruido: una herramienta nueva de un paquete verificado solo avisa"
v sh -c 'echo "/usr/bin/tail -f /dev/null" > /tmp/acme-flag'
poke 8098
check "se avisa" wait_for 60 incident "acme-gen.service started /usr/bin/tail"
sleep 35
not_isolated() { local out; out=$(cg_of "tail -f /dev/null"); grep -q "acme-gen.service" <<<"$out" && ! grep -q arxconfine <<<"$out"; }
check "pero no se aísla: sigue en su servicio" not_isolated

step "aceptar un directorio entero (--dir)"
v sh -c 'echo "/opt/acme/tools/a 120" > /tmp/acme-flag'
poke 8098
check "un programa sin paquete se aísla" wait_for 60 incident "acme-gen.service started /opt/acme/tools/a"
fp=$(v python3 -c "import sys; sys.path.insert(0, '/usr/lib/arx/arx.pyz')
from arx.modules import response as r
print(next(fp for fp, e in r.load_findings().items() if '/opt/acme/tools/a' in str(e.get('detail'))))")
v arx accept "$fp" --dir >/dev/null 2>&1
v sh -c 'echo "/opt/acme/tools/b 120" > /tmp/acme-flag'
poke 8098
sleep 35
check "su vecino del mismo directorio ya no da aviso" sh -c "! limactl shell $VM sudo grep -q 'started /opt/acme/tools/b' /var/lib/arx/incidents.jsonl"
b_free() { local out; out=$(cg_of "tools/b 120"); grep -q "acme-gen.service" <<<"$out"; }
check "ni se aísla" b_free
gen_alive() { v systemctl is-active -q acme-gen; }
check "acme-gen sigue en pie" gen_alive

step "control negativo: decenas de logins SSH reales sin alarma de sshd"
for i in $(seq 20); do v true; done
sleep 35
check "ninguna alarma de «sshd antes de autenticar»" no_incident "before authenticating anyone"

v bash -c 'systemctl disable --now acme-web acme-gen >/dev/null 2>&1; rm -f /tmp/acme-flag; pkill -CONT -u www-data; pkill -f "acme/sleep.py"; pkill -f "tail -f /dev/null"; pkill -f "tools/[ab] 120"'
echo
[ "$FAILED" = 0 ] && echo "══ LAB DE PROCESOS COMPLETO ══" || echo "══ LAB DE PROCESOS CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
