#!/usr/bin/env bash
# Lab de A#6: un AuthorizedKeysCommand (un script) dentro de un bloque Match, como con LDAP o sssd. sshd
# lo ejecuta antes de autenticar en cada login: Arx no puede congelar ninguno. Y con `sshd -T` roto, la
# regla de sshd solo avisaría: nunca un login congelado por una lectura dudosa.
#   bash lab/sshd-config-lab.sh
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
incident() { local out; out=$(v cat /var/lib/arx/incidents.jsonl 2>/dev/null); grep -q "$1" <<<"$out"; }
logins() { local ok=0 i; for i in $(seq "$1"); do fresh_login && ok=$((ok + 1)); done; echo "$ok"; }
no_frozen() { local out; out=$(v sh -c 'for p in $(cat /sys/fs/cgroup/system.slice/ssh.service/cgroup.procs); do ps -o stat= -p $p; done')
  ! grep -q T <<<"$out"; }
cleanup() { v bash -c 'rm -f /etc/ssh/sshd_config.d/50-arxlab.conf /usr/local/bin/arx-lab-akc /usr/local/bin/arx-lab-akc-real /usr/local/bin/arx-lab-tool /usr/local/sbin/sshd /tmp/arx-akc-calls /etc/arx-lab-keys
  gpasswd -d "$1" arxlab >/dev/null 2>&1; groupdel arxlab 2>/dev/null; systemctl reload ssh' _ "$U"; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1
U=$(limactl shell "$VM" whoami)

step "víctima limpia y Arx"
cleanup
v bash -c 'systemctl disable --now arx arx-firewall 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload'
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx
# solo este arranque de Arx: la línea de uno anterior seguiría en el journal y el lab empezaría sin vigilancia
kernel_watch() { local out; out=$(v sh -c 'journalctl -u arx --no-pager _SYSTEMD_INVOCATION_ID=$(systemctl show -p InvocationID --value arx)'); grep -q "process watch: in the kernel" <<<"$out"; }
check "vigila cada exec desde el kernel" wait_for 20 kernel_watch

step "un AuthorizedKeysCommand (envoltorio con exec) dentro de Match Group, recién añadido"
v bash -c 'groupadd -f arxlab && usermod -aG arxlab "$1"
  install -m 644 "$(getent passwd "$1" | cut -d: -f6)/.ssh/authorized_keys" /etc/arx-lab-keys
  # un envoltorio declarado que hace exec del programa real (no declarado), como con sssd; con un argumento en el
  # shebang, el kernel ejecuta `sh -e /usr/local/bin/arx-lab-akc …`
  printf "#!/bin/sh -e\necho \"\$1\" >> /tmp/arx-akc-calls\nexec /usr/local/bin/arx-lab-akc-real \"\$@\"\n" > /usr/local/bin/arx-lab-akc
  printf "#!/bin/sh\nexec cat /etc/arx-lab-keys\n" > /usr/local/bin/arx-lab-akc-real
  chmod 755 /usr/local/bin/arx-lab-akc /usr/local/bin/arx-lab-akc-real
  : > /tmp/arx-akc-calls && chmod 666 /tmp/arx-akc-calls
  # sin AuthorizedKeysFile: sshd solo llama al comando si la clave no está ya en el fichero
  printf "Match Group arxlab\n    AuthorizedKeysFile none\n    AuthorizedKeysCommand /usr/local/bin/arx-lab-akc %%u\n    AuthorizedKeysCommandUser nobody\n" > /etc/ssh/sshd_config.d/50-arxlab.conf
  sshd -t && systemctl reload ssh' _ "$U"
OK=$(logins 20)   # en seguida: sin esperar a que Arx relea nada
check "20 logins nuevos, los 20 entran (hechos: $OK)" test "$OK" = 20
CALLS=$(v sh -c 'wc -l < /tmp/arx-akc-calls' | tr -d ' ')
check "sshd ejecutó el comando antes de autenticar en cada uno (llamadas: $CALLS)" test "${CALLS:-0}" -ge 20
sleep 35
check "ninguna alarma de «sshd antes de autenticar»" sh -c "! limactl shell $VM sudo grep -q 'before authenticating anyone' /var/lib/arx/incidents.jsonl"
v sh -c 'grep "before authenticating anyone" /var/lib/arx/incidents.jsonl | cut -c1-300' || true
check "nada congelado en ssh.service" no_frozen

step "el comando de claves pasa a lanzar algo que su script no nombra (A#10)"
akc_watching() { v python3 -c "import json, sys, datetime as d
s = json.load(open('/var/lib/arx/profiles.json')).get('sshd_akc', {})
u = s.get('akc_until'); sys.exit(0 if u and d.datetime.fromisoformat(u) < d.datetime.now(d.timezone.utc) else 1)"; }
check "precondición: pasó la ventana de aprendizaje del comando de claves" wait_for 420 akc_watching
OK=$(logins 20)
check "ya vigilado: envoltorio → real → cat, 20 logins, los 20 entran (hechos: $OK)" test "$OK" = 20
sleep 35
check "y en silencio: ninguna alarma de «sshd antes de autenticar»" sh -c "! limactl shell $VM sudo grep -q 'before authenticating anyone' /var/lib/arx/incidents.jsonl"
v sh -c 'grep "before authenticating anyone" /var/lib/arx/incidents.jsonl | cut -c1-400' || true
v bash -c 'cp /usr/bin/cat /usr/local/bin/arx-lab-tool
  printf "#!/bin/sh\nT=/usr/local/bin/arx-lab-tool\nexec \"\$T\" /etc/arx-lab-keys\n" > /usr/local/bin/arx-lab-akc-real'
OK=$(logins 3)
check "los logins siguen entrando (hechos: $OK)" test "$OK" = 3
check "alerta crítica con evidencia: fuera de lo que ejecuta su comando de claves" wait_for 60 incident "outside what its keys command runs"
check "sin congelar nada" no_frozen

step "con sshd -T roto: nunca un login congelado"
v bash -c 'printf "#!/bin/sh\nexit 255\n" > /usr/local/sbin/sshd && chmod 755 /usr/local/sbin/sshd'
sleep 65   # pasa el minuto de relectura: Arx lee -T roto
OK=$(logins 10)
check "10 logins nuevos, los 10 entran (hechos: $OK)" test "$OK" = 10
check "nada congelado en ssh.service" no_frozen

cleanup
echo
[ "$FAILED" = 0 ] && echo "══ LAB DE CONFIGURACIÓN DE SSHD COMPLETO ══" || echo "══ LAB DE CONFIGURACIÓN DE SSHD CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
