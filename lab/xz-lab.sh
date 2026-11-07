#!/usr/bin/env bash
# Lab de DEC#13: el patrón de la puerta trasera de xz, de verdad. Una librería cargada en sshd (por
# /etc/ld.so.preload) ejecuta una orden antes de autenticar, en el proceso de cada conexión. Arx tiene
# que congelarla en milisegundos (la orden espera 200 ms antes de dejar su marca: si la marca aparece,
# Arx llegó tarde), dar la alerta crítica y aislarla. Retirado el drop-in, los logins vuelven.
# Solo en la VM del lab: es una puerta trasera simulada.
#   bash lab/xz-lab.sh
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
unplant() { v bash -c 'rm -f /etc/ld.so.preload /etc/ssh/sshd_config.d/50-arxlab-akcuser.conf /usr/local/lib/xz-lab-as-nobody /usr/local/bin/arx-lab-akc-nadie /etc/systemd/system/ssh.service.d/xz-lab.conf; rmdir /etc/systemd/system/ssh.service.d 2>/dev/null
  systemctl daemon-reload; systemctl restart ssh
  for c in /sys/fs/cgroup/arxconfine.slice/arxconfine-*.scope; do echo 1 > $c/cgroup.kill; done 2>/dev/null
  pkill -KILL -f "xz-lab-payloa[d]"; true'; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia, Arx y la librería «envenenada»"
unplant
v bash -c 'systemctl disable --now arx arx-firewall arx-revive.timer 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /tmp/xz-lab-ran /tmp/xz-fork-ran /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service /etc/systemd/system/arx*.timer
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq gcc libc6-dev >/dev/null'
v bash -s <<'C'
cat > /tmp/xz-lab.c <<'EOF'
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
/* Solo en el proceso de cada conexión, antes de autenticar: como la puerta trasera de xz. OpenSSH 9 se
   reejecuta con -R; OpenSSH 10 ejecuta sshd-session. */
__attribute__((constructor)) static void hook(void) {
    char buf[4096] = {0}, exe[512] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    int conn = 0;
    for (ssize_t i = 0; i < n; i += strlen(buf + i) + 1)
        if (strcmp(buf + i, "-R") == 0) conn = 1;
    ssize_t m = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (m > 13 && strcmp(exe + m - 13, "/sshd-session") == 0) conn = 1;
    if (!conn) return;
    unsetenv("LD_PRELOAD");
    if (access("/usr/local/lib/xz-lab-as-nobody", F_OK) == 0) {  /* A#10: se hace pasar por el comando de claves */
        pid_t p = fork();
        if (p == 0) {
            if (setgid(65534) == 0 && setuid(65534) == 0)
                execl("/bin/sh", "sh", "/usr/local/lib/xz-lab-payload.sh", (char *)0);
            _exit(1);
        }
        if (p > 0) waitpid(p, 0, 0);
        return;
    }
    system("/bin/sh /usr/local/lib/xz-lab-payload.sh");  /* la orden la decide el lab en cada escenario */
}
EOF
gcc -shared -fPIC -o /usr/local/lib/xz-lab.so /tmp/xz-lab.c
C
check "librería compilada" v test -f /usr/local/lib/xz-lab.so
payload() { v sh -c "printf '%s\n' '$1' > /usr/local/lib/xz-lab-payload.sh"; }
payload 'sleep 0.2; touch /tmp/xz-lab-ran'
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx
kernel_watch() { local out; out=$(v journalctl -u arx --no-pager -n 200); grep -q "process watch: in the kernel" <<<"$out"; }
check "vigila cada exec desde el kernel" wait_for 20 kernel_watch
check "precondición: un login nuevo funciona" fresh_login

step "sshd con la librería: la conexión siguiente ejecuta algo antes de autenticar"
# /etc/ld.so.preload, como hace el malware real: OpenSSH 10 no pasa su entorno a sshd-session, así que un
# LD_PRELOAD en el unit no llegaría. La librería solo actúa en el proceso de cada conexión
v sh -c 'echo /usr/local/lib/xz-lab.so > /etc/ld.so.preload'
( fresh_login >/dev/null 2>&1 & )   # el atacante llama a la puerta; esta conexión se quedará colgada
frozen() { local out; out=$(v sh -c 'for p in $(pgrep -f "xz-lab-payloa[d]"); do ps -o stat= -p $p; done'); grep -q T <<<"$out"; }
check "la orden queda congelada" wait_for 30 frozen
sleep 3
check "en milisegundos: no llegó a dejar su marca (200 ms)" sh -c "! limactl shell $VM test -e /tmp/xz-lab-ran"
check "alerta crítica: sshd ejecutó algo antes de autenticar" wait_for 40 incident "sshd, before authenticating anyone, ran"
crit() { local out; out=$(v cat /var/lib/arx/incidents.jsonl); grep "before authenticating anyone" <<<"$out" | grep -q '"sev": "crit"'; }
check "y es crítica" crit
lat=$(v sh -c 'grep -o "frozen [0-9]* ms" /var/lib/arx/incidents.jsonl | head -1')
echo "  latencia medida por el kernel: ${lat:-(sin dato)}"
isolated() { local out; out=$(v sh -c 'for p in $(pgrep -f "xz-lab-payloa[d]"); do cat /proc/$p/cgroup; done'); grep -q arxconfine <<<"$out"; }
check "y la orden queda aislada sin red" wait_for 30 isolated

step "la orden hace forks en bucle: queda contenida y Arx no se cuelga (A#7)"
v sh -c 'for c in /sys/fs/cgroup/arxconfine.slice/arxconfine-*.scope; do echo 1 > $c/cgroup.kill; done 2>/dev/null; pkill -KILL -f "xz-lab-payloa[d]"; true'   # lo del escenario anterior, fuera: no puede dar un PASS prestado
sleep 2
payload 'for i in 1 2 3 4; do (while :; do sleep 0.01 & done) & done; sleep 0.3; touch /tmp/xz-fork-ran'
( fresh_login >/dev/null 2>&1 & )
check "la orden queda congelada" wait_for 30 frozen
spawned() { v sh -c 'pgrep -f "sleep 0.0[1]" | sort | tr "\n" " "'; }
sleep 3
A=$(spawned); sleep 3; B=$(spawned)
check "nadie de su familia sigue creando procesos" test "$A" = "$B"
check "no llegó a dejar su marca" sh -c "! limactl shell $VM test -e /tmp/xz-fork-ran"
check "Arx sigue respondiendo" v sh -c 'timeout 30 arx status >/dev/null'
check "y sigue en guardia" v systemctl is-active -q arx
# el scope de ESTE escenario (el de su primer proceso), no uno cualquiera
cg_frozen() { local out; out=$(v sh -c 'p=$(pgrep -of "xz-lab-payloa[d]"); c=$(cut -d: -f3 /proc/$p/cgroup); cat /sys/fs/cgroup$c/cgroup.freeze') ; test "$out" = 1; }
check "su scope está congelado ya (lo hace el vigilante, no el barrido)" cg_frozen
v sh -c 'pkill -CONT -f "xz-lab-payloa[d]"; pkill -CONT -f "sleep 0.0[1]"; true'   # el «vigilante» de la puerta trasera
sleep 3
C=$(spawned)
check "un SIGCONT ajeno no la despierta: ni procesos nuevos" test "$B" = "$C"
check "ni su marca" sh -c "! limactl shell $VM test -e /tmp/xz-fork-ran"

step "la puerta trasera se hace pasar por el usuario del comando de claves (A#10)"
v sh -c 'for c in /sys/fs/cgroup/arxconfine.slice/arxconfine-*.scope; do echo 1 > $c/cgroup.kill; done 2>/dev/null; pkill -KILL -f "xz-lab-payloa[d]"; rm -f /tmp/xz-lab-ran; true'
# un comando de claves en shell: su intérprete no le vale a nadie más que a su script
v bash -c 'printf "#!/bin/sh\nexec cat /dev/null\n" > /usr/local/bin/arx-lab-akc-nadie && chmod 755 /usr/local/bin/arx-lab-akc-nadie
  printf "Match User arx-lab-nadie\n    AuthorizedKeysCommand /usr/local/bin/arx-lab-akc-nadie\n    AuthorizedKeysCommandUser nobody\n" > /etc/ssh/sshd_config.d/50-arxlab-akcuser.conf
  touch /usr/local/lib/xz-lab-as-nobody; chmod 755 /usr/local/lib/xz-lab-payload.sh'
payload 'sleep 0.2; touch /tmp/xz-lab-ran'
akc_watching() { v python3 -c "import json, sys, datetime as d
s = json.load(open('/var/lib/arx/profiles.json')).get('sshd_akc', {})
u = s.get('akc_until'); sys.exit(0 if u and d.datetime.fromisoformat(u) < d.datetime.now(d.timezone.utc) else 1)"; }
check "precondición: pasó la ventana de aprendizaje del comando de claves" wait_for 420 akc_watching
( fresh_login >/dev/null 2>&1 & )
check "alerta crítica: corre como nobody, fuera de lo que ejecuta su comando de claves" wait_for 60 incident "as nobody, outside what its keys command runs"
check "sin congelar: un login entra" fresh_login
v sh -c 'rm -f /etc/ssh/sshd_config.d/50-arxlab-akcuser.conf /usr/local/lib/xz-lab-as-nobody /usr/local/bin/arx-lab-akc-nadie'

step "retirada la librería, los logins vuelven"
unplant
check "un login nuevo funciona" fresh_login
check "y ninguna alarma nueva de sshd con sshd limpio" sh -c "test \$(limactl shell $VM sudo grep -c 'before authenticating anyone' /var/lib/arx/incidents.jsonl) -le 1"

echo
[ "$FAILED" = 0 ] && echo "══ LAB DEL PATRÓN XZ COMPLETO ══" || echo "══ LAB DEL PATRÓN XZ CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
