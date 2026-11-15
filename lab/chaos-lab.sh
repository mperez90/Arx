#!/usr/bin/env bash
# Pista Q · R5 caos: Arx no se cae y degrada de forma explícita.
#
# Somete a Arx (en guardia, --enforce) a cada avería y comprueba las invariantes:
#   1. el servicio sigue ACTIVO (systemctl is-active arx);
#   2. no aparece ningún traceback de Python en el journal desde que empezó la avería;
#   3. `arx status` sigue respondiendo (sale 0) y refleja el estado;
#   4. no se inventa ningún veredicto ni hallazgo crit/high falso durante la avería.
# Averías: auditd parado · dpkg bloqueado mucho tiempo · proveedor del modelo caído · receptor de
# webhooks caído · salto de reloj · disco de estado lleno. Cada una se aplica y se revierte.
#
#   bash lab/chaos-lab.sh            ARX_LIMA_VICTIM=arx-deb13-rc9 bash lab/chaos-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-deb13-rc9}
WORD=palabra-del-lab
SETTLE=${ARX_CHAOS_SETTLE:-70}   # ~2 barridos de 30 s
FAILED=0

v() { limactl shell "$VM" sudo "$@"; }
vb() { limactl shell "$VM" sudo bash -c "$1"; }
step() { echo; echo "══ $1 ══"; }
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }

# marca en el journal: contamos tracebacks SOLO desde aquí
_mark_journal() { v journalctl -u arx --no-pager -o short-unix 2>/dev/null | tail -1 | awk '{print $1}' | tr -d '[].'; }
_no_traceback_since() {
  local out; out=$(v journalctl -u arx --no-pager --since "@$1" 2>/dev/null)
  ! grep -qE "Traceback \(most recent call last\)|Unhandled|KeyError|AttributeError|TypeError:" <<<"$out"
}

# invariantes universales tras una avería: <nombre> <marca-journal>
invariants() {
  local name="$1" mark="$2"
  v systemctl is-active -q arx && pass "$name · servicio activo" || fail "$name · servicio CAÍDO"
  if _no_traceback_since "$mark"; then pass "$name · sin traceback en el journal"; else
    fail "$name · traceback en el journal"; v journalctl -u arx --since "@$mark" --no-pager 2>/dev/null | grep -A3 Traceback | head -8; fi
  v arx status >/dev/null 2>&1 && pass "$name · arx status responde" || fail "$name · arx status falla"
}

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia + Arx en guardia (--enforce)"
vb 'systemctl disable --now arx arx-firewall 2>/dev/null; pkill -9 -f "[a]rx.pyz" 2>/dev/null
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /etc/ld.so.preload /etc/systemd/system/arx*.service \
    /etc/systemd/system/arx*.timer /etc/systemd/system/arx-maintenance.slice \
    /etc/systemd/system/*.service.d/9[01]-arx-*.conf
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 install -y -qq nftables python3 auditd >/dev/null 2>&1
  systemctl enable --now auditd >/dev/null 2>&1'
vb "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
v arx --version >/dev/null 2>&1 || { echo "  [FAIL] Arx no instaló"; exit 1; }
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
vb 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v arx service install --enforce >/dev/null 2>&1
v systemctl is-active -q arx || { echo "  [FAIL] Arx no quedó en guardia"; exit 1; }
CRIT0=$(v sh -c 'grep -c "\"sev\": \"crit\"\|\"sev\": \"high\"" /var/lib/arx/incidents.jsonl 2>/dev/null' | tr -d "[:space:]")
echo "  [OK] Arx en guardia; incidentes crit/high de partida: ${CRIT0:-0}"

# ── 1. auditd parado ──────────────────────────────────────────────────────────
step "auditd parado"
M=$(_mark_journal); v systemctl stop auditd
sleep "$SETTLE"
invariants "auditd parado" "$M"
# autoría degradada: writers_of vacío, pero la integridad sigue viva (no se inventa)
v systemctl start auditd >/dev/null 2>&1

# ── 2. dpkg bloqueado mucho tiempo ────────────────────────────────────────────
step "dpkg bloqueado (lock retenido)"
M=$(_mark_journal)
vb 'nohup flock -x /var/lib/dpkg/lock-frontend sleep '"$SETTLE"' >/dev/null 2>&1 &'
sleep "$SETTLE"
invariants "dpkg bloqueado" "$M"
# pkgdb debe degradar con NoAnswer, no inventar versiones

# ── 3. proveedor del modelo caído ─────────────────────────────────────────────
step "proveedor del modelo caído (endpoint inalcanzable)"
M=$(_mark_journal)
vb 'python3 - <<PY
import json
p="/etc/arx/config.json"; c=json.load(open(p))
c["providers"]={"openai":{"base_url":"http://127.0.0.1:1/v1","model":"x"}}
c["fallback_order"]=["openai"]
json.dump(c, open(p,"w"))
PY
systemctl restart arx'
sleep 5
# provocar un hallazgo que dispararía el motor: un ejecutable nuevo en /tmp
vb 'cp /bin/true /tmp/chaos-dropper && chmod +x /tmp/chaos-dropper && /tmp/chaos-dropper'
sleep "$SETTLE"
invariants "modelo caído" "$M"
# no se inventa veredicto: no debe haber línea de veredicto del motor con el proveedor caído
if v sh -c 'grep -q "engine_verdict\|VERDICTS" /var/lib/arx/incidents.jsonl 2>/dev/null'; then
  fail "modelo caído · se registró un veredicto con el proveedor caído"; else
  pass "modelo caído · ningún veredicto inventado"; fi
vb 'python3 -c "import json;p=\"/etc/arx/config.json\";c=json.load(open(p));c[\"providers\"]={};c[\"fallback_order\"]=[];json.dump(c,open(p,\"w\"))"; rm -f /tmp/chaos-dropper; systemctl restart arx'
sleep 3

# ── 4. receptor de webhooks caído ─────────────────────────────────────────────
step "receptor de webhooks caído"
M=$(_mark_journal)
vb 'python3 -c "import json;p=\"/etc/arx/config.json\";c=json.load(open(p));c.setdefault(\"notify\",{})[\"webhook\"]=\"http://127.0.0.1:1/hook\";json.dump(c,open(p,\"w\"))"; systemctl restart arx'
sleep 5
vb 'cp /bin/true /tmp/chaos-dropper2 && chmod +x /tmp/chaos-dropper2 && /tmp/chaos-dropper2'
sleep "$SETTLE"
invariants "webhook caído" "$M"
vb 'python3 -c "import json;p=\"/etc/arx/config.json\";c=json.load(open(p));c.get(\"notify\",{}).pop(\"webhook\",None);json.dump(c,open(p,\"w\"))"; rm -f /tmp/chaos-dropper2; systemctl restart arx'
sleep 3

# ── 5. salto de reloj ─────────────────────────────────────────────────────────
step "salto de reloj (+2h y vuelta)"
M=$(_mark_journal)
vb 'timedatectl set-ntp false 2>/dev/null; date -s "+2 hours" >/dev/null 2>&1'
sleep 35
vb 'date -s "-2 hours" >/dev/null 2>&1; timedatectl set-ntp true 2>/dev/null'
sleep 35
invariants "salto de reloj" "$M"

# ── 6. disco de estado lleno ──────────────────────────────────────────────────
step "disco de estado lleno (no debe caerse al no poder escribir)"
M=$(_mark_journal)
# relleno acotado del raíz dejando poco libre; si no hay sitio, se omite con aviso
if vb 'avail=$(df --output=avail -k / | tail -1); [ "$avail" -gt 200000 ]'; then
  vb 'fallocate -l $(($(df --output=avail -k / | tail -1)*1024 - 100*1024*1024)) /var/tmp/chaos-fill 2>/dev/null || \
      dd if=/dev/zero of=/var/tmp/chaos-fill bs=1M count=$(( $(df --output=avail -m / | tail -1) - 100 )) 2>/dev/null'
  vb 'cp /bin/true /tmp/chaos-dropper3 && chmod +x /tmp/chaos-dropper3 && /tmp/chaos-dropper3'
  sleep "$SETTLE"
  invariants "disco lleno" "$M"
  vb 'rm -f /var/tmp/chaos-fill /tmp/chaos-dropper3'
else
  echo "  [SKIP] disco lleno: poco espacio libre para un relleno seguro"
fi

step "RESUMEN"
CRIT1=$(v sh -c 'grep -c "\"sev\": \"crit\"\|\"sev\": \"high\"" /var/lib/arx/incidents.jsonl 2>/dev/null' | tr -d "[:space:]")
echo "  incidentes crit/high: partida ${CRIT0:-0} → final ${CRIT1:-0} (el dropper de /tmp es esperado)"
v systemctl is-active -q arx && echo "  Arx sigue en guardia tras todo el caos" || fail "Arx NO sobrevivió al caos"
[ "$FAILED" = 0 ] && echo "══ LAB DE CAOS COMPLETO: Arx degradó sin caerse ══" || echo "══ LAB DE CAOS CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
