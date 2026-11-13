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
leftovers() { v sh -c 'ls /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service /etc/systemd/system/arx*.timer /etc/systemd/system/arx*.slice 2>/dev/null
  systemctl list-units --type=scope --all --plain --no-legend 2>/dev/null | awk '\''$1 ~ /^arx-maint-.*\.scope$/ {print $1}'\''
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf
  nft list table inet arx >/dev/null 2>&1 && echo "tabla inet arx"
  ls -d /etc/arx /var/lib/arx 2>/dev/null; true'; }
incidents_count() { v sh -c 'test ! -f /var/lib/arx/incidents.jsonl || wc -l < /var/lib/arx/incidents.jsonl' | tr -d '[:space:]'; }
# B60: canales falsos en la propia VM. Token y chat_id inventados; el servidor solo anota si el token casaba.
FAKE=/tmp/fakechan
channels() {  # $1 = telegram_api ("" quita los canales)
  v python3 - "$1" <<'PY'
import sys
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx import config
cfg, sec = config.load_config() or {}, config.load_secrets() or {}
keys = ("telegram_chat_id", "telegram_api", "webhook_url")
cfg["notify"] = {k: v for k, v in (cfg.get("notify") or {}).items() if k not in keys}
sec.pop("telegram_bot_token", None)
if sys.argv[1]:
    cfg["notify"].update(telegram_chat_id="-1000000000999", telegram_api=sys.argv[1],
                         webhook_url="http://127.0.0.1:18181/hook/lab")
    sec["telegram_bot_token"] = open("/tmp/fakechan/token").read().strip()
config.save_config(cfg)
config.save_secrets(sec)
PY
}
chan_mode() { v sh -c "echo $2 > $FAKE/$1.mode"; }
fake_count() { v sh -c "test -f $FAKE/requests.jsonl && wc -l < $FAKE/requests.jsonl || echo 0" | tr -d '[:space:]'; }
notify_check() {  # $1 = líneas previas de incidents.jsonl · $2 = evento · $3 = condición Python sobre r (results)
  v python3 - "$1" "$2" "$3" <<'PY'
import json, sys
rows = [json.loads(line) for line in open("/var/lib/arx/incidents.jsonl") if line.strip()][int(sys.argv[1]):]
assert any(row.get("kind") == sys.argv[2] for row in rows), f"no {sys.argv[2]} incident"
results = [row["results"] for row in rows if row.get("kind") == "notify_result" and row.get("event") == sys.argv[2]]
assert results, f"no notify_result for {sys.argv[2]}"
r = results[-1]
print(f"  {sys.argv[2]} → notify_result {json.dumps(r, ensure_ascii=False)[:300]}")
assert eval(sys.argv[3], {}, {"r": r}), r
PY
}
telegram_received() {  # $1 = peticiones previas del servidor falso · $2 = texto
  v python3 - "$1" "$2" <<'PY'
import json, sys
rows = [json.loads(line) for line in open("/tmp/fakechan/requests.jsonl") if line.strip()][int(sys.argv[1]):]
assert any(r["channel"] == "telegram" and r["token_ok"] and sys.argv[2] in r["text"] for r in rows), rows
PY
}

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia, Arx instalado desde su paquete"
v bash -c 'systemctl disable --now arx arx-firewall loose 2>/dev/null; pkill -9 -f "[a]rx.pyz"; pkill -f "[f]akechan/server.py"; rm -rf /tmp/fakechan
  systemctl list-units --type=scope --all --plain --no-legend | awk '\''$1 ~ /^arx-maint-.*\.scope$/ {print $1}'\'' | xargs -r systemctl stop
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /opt/loose /etc/systemd/system/loose.service \
    /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service /etc/systemd/system/arx*.timer \
    /etc/systemd/system/arx*.slice
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq socat nftables netcat-openbsd >/dev/null'
check "precondición: sin restos de antes" test -z "$(leftovers)"
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
# El servidor falso existe antes de aprender: su proceso y su puerto local son parte de lo normal.
v bash -c "mkdir -p $FAKE && echo LAB-FAKE-TOKEN-not-for-telegram-7c1d > $FAKE/token && cat > $FAKE/server.py" <<'PY'
import json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
D = "/tmp/fakechan"
TOKEN = open(D + "/token").read().strip()

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        channel = "telegram" if self.path.startswith("/bot") else "webhook" if self.path.startswith("/hook/") else "other"
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            mode = open(f"{D}/{channel}.mode").read().strip()
        except OSError:
            mode = "ok"
        try:
            text = str(json.loads(body).get("text", ""))
        except ValueError:
            text = ""
        row = {"t": time.time(), "channel": channel, "mode": mode, "text": text[:200],
               "token_ok": self.path == f"/bot{TOKEN}/sendMessage" if channel == "telegram" else None}
        with open(f"{D}/requests.jsonl", "a") as f:
            f.write(json.dumps(row) + "\n")
        if mode == "hang":
            time.sleep(120)
        code = 500 if mode == "fail" else 200
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}' if code == 200 else b'{"ok": false}')
        except OSError:
            pass

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", 18181), Handler).serve_forever()
PY
# setsid -f: ni el servidor ni ningún intermediario conservan el canal SSH (si no, limactl shell no vuelve)
v bash -c "cd $FAKE && setsid -f python3 server.py >/dev/null 2>&1 < /dev/null"
fake_up() { v python3 -c 'import socket; socket.create_connection(("127.0.0.1", 18181), 1).close()' 2>/dev/null; }
check "precondición: canales falsos escuchando en 127.0.0.1:18181" wait_for 10 fake_up
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
channels "http://127.0.0.1:18181"
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

step "autoprotección: pararlo o tocarlo queda dicho, con el resultado de cada canal (DoD-6/B60)"
incident() { local out; out=$(v cat /var/lib/arx/incidents.jsonl 2>/dev/null); grep -q "$1" <<<"$out"; }
INC=$(incidents_count); REQ=$(fake_count)
chan_mode telegram ok; chan_mode webhook fail
v systemctl stop arx
check "parar Arx queda anotado" wait_for 20 incident "self_stopped"
check "su notify_result separa el canal que aceptó del que falló" \
  notify_check "$INC" self_stopped 'r.get("telegram") == "ok" and r.get("webhook", "").startswith("error")'
check "el canal falso recibió el aviso con su token" telegram_received "$REQ" "Arx stopped"

chan_mode telegram hang; chan_mode webhook hang
v systemctl start arx
check "Arx activo antes de la parada con canales colgados" wait_for 30 v systemctl is-active -q arx
INC=$(incidents_count); T0=$(date +%s)
v systemctl stop arx
ELAPSED=$(( $(date +%s) - T0 ))
echo "  parada con los dos canales colgados: ${ELAPSED} s (presupuesto de avisos 45 s, TimeoutStopSec 90 s)"
check "con canales colgados la parada termina dentro del presupuesto" test "$ELAPSED" -le 60
check "y aun así deja el resultado de cada canal" \
  notify_check "$INC" self_stopped '"error" in r.get("telegram", "") and "error" in r.get("webhook", "")'
check "systemd no tuvo que matar el aviso" sh -c "! limactl shell $VM systemctl show arx -p Result --value | grep -q timeout"
chan_mode telegram ok; chan_mode webhook ok

channels ""
v systemctl start arx
check "Arx activo sin canales" wait_for 30 v systemctl is-active -q arx
INC=$(incidents_count)
v systemctl stop arx
check "sin canales, el resultado queda vacío y no se inventa ningún envío" notify_check "$INC" self_stopped 'r == {}'
channels "http://127.0.0.1:18181"

v bash -c 'mkdir -p /etc/systemd/system/arx.service.d && printf "[Service]\nEnvironment=X=1\n" > /etc/systemd/system/arx.service.d/override.conf
  systemctl daemon-reload; systemctl start arx'
check "un drop-in ajeno en su unit da alerta crítica" wait_for 60 incident "someone added drop-ins to Arx"
v bash -c 'rm -rf /etc/systemd/system/arx.service.d; systemctl daemon-reload; systemctl restart arx'

step "fallo con reinicio programado, agotamiento real y relanzamiento (B61/DEC#11)"
check "el relanzador está programado" v systemctl is-active -q arx-revive.timer
# Un telegram_api sin esquema hace que urllib cite la URL entera, token incluido: el resultado debe redactarlo.
channels "/sin-esquema"
INC_DOWN=$(incidents_count)
v bash -c 'mv /var/lib/arx/baseline.json /root/baseline.lab && systemctl restart arx'   # sin base sellada: sale con error
check "el primer fallo dice reinicio programado, no agotamiento" wait_for 30 incident '"restart_state": "scheduled"'
failed() { v systemctl is-failed -q arx; }
check "tras los reintentos, systemd lo da por caído" wait_for 240 failed
check "el estado terminal sí declara StartLimit agotado" wait_for 30 incident '"restart_state": "exhausted"'
check "self_down deja su resultado: canal mal configurado redactado, el otro aceptado" \
  notify_check "$INC_DOWN" self_down '"error" in r.get("telegram", "") and "/bot" in r.get("telegram", "") and r.get("webhook") == "ok"'
no_fake_token() {
  v sh -c "t=\$(cat $FAKE/token); ! grep -qF \"\$t\" /var/lib/arx/incidents.jsonl && ! journalctl --no-pager -u arx -u arx-down -u arx-revive | grep -qF \"\$t\""
}
check "el token falso no aparece ni en incidents.jsonl ni en el journal" no_fake_token
channels "http://127.0.0.1:18181"
v bash -c 'mv /root/baseline.lab /var/lib/arx/baseline.json && systemctl start arx-revive.service'
check "el relanzador lo vuelve a arrancar" wait_for 30 v systemctl is-active -q arx
v systemctl stop arx
v systemctl start arx-revive.service
check "pero no deshace una parada hecha a mano" sh -c "! limactl shell $VM systemctl is-active -q arx"
v systemctl start arx

step "desinstalar (purge)"
check "Arx activo antes de desinstalar" wait_for 30 v systemctl is-active -q arx
REQ=$(fake_count)
v bash -c 'DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1'
check "Arx ya no corre" sh -c "! limactl shell $VM systemctl is-active -q arx"
no_stop_alert_since() {
  v python3 - "$1" <<'PY2'
import json, sys
rows = [json.loads(line) for line in open("/tmp/fakechan/requests.jsonl") if line.strip()][int(sys.argv[1]):]
print("  avisos durante la desinstalación:", [r["text"][:60] for r in rows])
assert not any("Arx stopped" in r["text"] or "Arx failure" in r["text"] for r in rows), rows
PY2
}
check "su propia desinstalación es una parada planeada: ningún aviso de parada" no_stop_alert_since "$REQ"
LEFT=$(leftovers)
[ -n "$LEFT" ] && echo "  restos: $LEFT"
check "sin restos: drop-ins, pines, units, tabla nft, configuración ni estado" test -z "$LEFT"
check "loose.service sigue en pie" v systemctl is-active -q loose
check "y recupera la red" in_unit loose.service nc -z -w 5 1.1.1.1 443
v systemctl restart loose cron
check "los servicios arrancan sin los drop-ins de Arx" v systemctl is-active -q loose cron

v bash -c 'systemctl disable --now loose >/dev/null 2>&1; rm -rf /opt/loose /etc/systemd/system/loose.service; systemctl daemon-reload
  pkill -f "[f]akechan/server.py"; rm -rf /tmp/fakechan'
echo
[ "$FAILED" = 0 ] && echo "══ LAB DE DESINSTALACIÓN COMPLETO ══" || echo "══ LAB DE DESINSTALACIÓN CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
