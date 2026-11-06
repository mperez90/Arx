#!/usr/bin/env bash
# Lab de DEC#13: el patrón de la puerta trasera de xz, de verdad. Una librería cargada en sshd (LD_PRELOAD
# por un drop-in) ejecuta una orden antes de autenticar, en la copia de sshd de cada conexión. Arx tiene
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
unplant() { v bash -c 'rm -f /etc/systemd/system/ssh.service.d/xz-lab.conf; rmdir /etc/systemd/system/ssh.service.d 2>/dev/null
  systemctl daemon-reload; systemctl restart ssh; pkill -KILL -f "xz-lab-ra[n]"; true'; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia, Arx y la librería «envenenada»"
unplant
v bash -c 'systemctl disable --now arx arx-firewall arx-revive.timer 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /tmp/xz-lab-ran /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service /etc/systemd/system/arx*.timer
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq gcc libc6-dev >/dev/null'
v bash -s <<'C'
cat > /tmp/xz-lab.c <<'EOF'
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Solo en la copia de sshd de cada conexión (-R), antes de autenticar: como la puerta trasera de xz. */
__attribute__((constructor)) static void hook(void) {
    char buf[4096] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    int rexec = 0;
    for (ssize_t i = 0; i < n; i += strlen(buf + i) + 1)
        if (strcmp(buf + i, "-R") == 0) rexec = 1;
    if (!rexec) return;
    unsetenv("LD_PRELOAD");
    system("/bin/sh -c 'sleep 0.2; touch /tmp/xz-lab-ran'");
}
EOF
gcc -shared -fPIC -o /usr/local/lib/xz-lab.so /tmp/xz-lab.c
C
check "librería compilada" v test -f /usr/local/lib/xz-lab.so
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx
kernel_watch() { local out; out=$(v journalctl -u arx --no-pager -n 200); grep -q "process watch: in the kernel" <<<"$out"; }
check "vigila cada exec desde el kernel" wait_for 20 kernel_watch
check "precondición: un login nuevo funciona" fresh_login

step "sshd con la librería: la conexión siguiente ejecuta algo antes de autenticar"
v bash -c 'mkdir -p /etc/systemd/system/ssh.service.d
  printf "[Service]\nEnvironment=LD_PRELOAD=/usr/local/lib/xz-lab.so\n" > /etc/systemd/system/ssh.service.d/xz-lab.conf
  systemctl daemon-reload; systemctl restart ssh'
( fresh_login >/dev/null 2>&1 & )   # el atacante llama a la puerta; esta conexión se quedará colgada
frozen() { local out; out=$(v sh -c 'for p in $(pgrep -f "xz-lab-ra[n]"); do ps -o stat= -p $p; done'); grep -q T <<<"$out"; }
check "la orden queda congelada" wait_for 30 frozen
sleep 3
check "en milisegundos: no llegó a dejar su marca (200 ms)" sh -c "! limactl shell $VM test -e /tmp/xz-lab-ran"
check "alerta crítica: sshd ejecutó algo antes de autenticar" wait_for 40 incident "sshd, before authenticating anyone, ran"
crit() { local out; out=$(v cat /var/lib/arx/incidents.jsonl); grep "before authenticating anyone" <<<"$out" | grep -q '"sev": "crit"'; }
check "y es crítica" crit
lat=$(v sh -c 'grep -o "frozen [0-9]* ms" /var/lib/arx/incidents.jsonl | head -1')
echo "  latencia medida por el kernel: ${lat:-(sin dato)}"
isolated() { local out; out=$(v sh -c 'for p in $(pgrep -f "xz-lab-ra[n]"); do cat /proc/$p/cgroup; done'); grep -q arxconfine <<<"$out"; }
check "y la orden queda aislada sin red" wait_for 30 isolated

step "retirada la librería, los logins vuelven"
unplant
check "un login nuevo funciona" fresh_login
check "y ninguna alarma nueva de sshd con sshd limpio" sh -c "test \$(limactl shell $VM sudo grep -c 'before authenticating anyone' /var/lib/arx/incidents.jsonl) -le 1"

echo
[ "$FAILED" = 0 ] && echo "══ LAB DEL PATRÓN XZ COMPLETO ══" || echo "══ LAB DEL PATRÓN XZ CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
