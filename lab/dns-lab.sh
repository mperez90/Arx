#!/usr/bin/env bash
# Lab de F18.3: qué dominios consulta cada servicio, leído del kernel (NFLOG). acme-dns consulta ubuntu.com
# mientras se le observa; después, un subdominio de lo aprendido no avisa, github.com sí, y un nombre con
# pinta de generado por un malware da alerta alta.
#   bash lab/dns-lab.sh            ARX_LIMA_VICTIM=arx-deb13 bash lab/dns-lab.sh
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
name() { v sh -c "echo '$1' > /tmp/acme-dns-name"; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia, Arx y un servicio que resuelve nombres"
v bash -c 'systemctl disable --now arx arx-firewall acme-dns 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /etc/systemd/system/acme-dns.service /tmp/acme-dns-name \
    /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service /etc/systemd/system/arx*.timer
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq nftables bind9-dnsutils auditd >/dev/null'
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
v bash -c 'echo ubuntu.com > /tmp/acme-dns-name
  printf "[Service]\nExecStart=/bin/sh -c '"'"'while :; do dig +short +tries=1 +time=2 \$(cat /tmp/acme-dns-name) >/dev/null; sleep 3; done'"'"'\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/acme-dns.service
  systemctl daemon-reload; systemctl enable --now acme-dns >/dev/null 2>&1'
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx
dns_on() { local out; out=$(v journalctl -u arx --no-pager -n 200); grep -q "DNS watch: on" <<<"$out"; }
check "lee el DNS de cada servicio desde el kernel (NFLOG)" wait_for 20 dns_on

step "aprender"
learned() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if 'ubuntu.com' in s.get('system.slice/acme-dns.service', {}).get('domains', []) else 1)"; }
check "aprende que acme-dns consulta ubuntu.com" wait_for 120 learned
watching() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if s.get('system.slice/acme-dns.service', {}).get('status') == 'watching' else 1)"; }
check "y pasa a vigilado" wait_for 420 watching

step "vigilar"
name archive.ubuntu.com
sleep 40
check "un subdominio de lo aprendido no avisa" sh -c "! limactl shell $VM sudo grep -q 'looked up archive.ubuntu.com' /var/lib/arx/incidents.jsonl"
name github.com
check "un dominio nuevo se avisa" wait_for 60 incident "acme-dns.service looked up github.com"
name xk3j9qz7vw2mrt8p.com
check "uno con pinta de generado, alerta alta" wait_for 60 incident "looked up xk3j9qz7vw2mrt8p.com, a domain it never used while Arx observed it (it looks machine-generated)"
high() { local out; out=$(v cat /var/lib/arx/incidents.jsonl); grep "xk3j9qz7vw2mrt8p" <<<"$out" | grep -q '"sev": "high"'; }
check "y es alta" high

v bash -c 'systemctl disable --now acme-dns >/dev/null 2>&1; rm -f /etc/systemd/system/acme-dns.service; systemctl daemon-reload'
echo
[ "$FAILED" = 0 ] && echo "══ LAB DE DNS COMPLETO ══" || echo "══ LAB DE DNS CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
