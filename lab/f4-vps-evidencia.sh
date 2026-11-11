#!/usr/bin/env bash
# F4 assume-breach: measure Arx's response on arx-u24. READ-ONLY with respect to Arx state:
# this script neither plants nor launches scenarios; the operator runs those separately.
# Usage, as root on the VPS:
#   bash f4-vps-evidencia.sh init            # baseline
#   bash f4-vps-evidencia.sh antes  <esc>    # open a scenario evidence window
#   bash f4-vps-evidencia.sh despues <esc>   # close it and collect observations
#   bash f4-vps-evidencia.sh informe         # generate /root/f4/f4-informe-<date>.md
set -uo pipefail
DIR=/root/f4/evidencia
INC=/var/lib/arx/incidents.jsonl

ESCENARIOS="f4-a1-shell f4-a2-recon f4-a3-leer f4-a4-pwnkit f4-a5-persist f4-a6-exfil f4-a7-minero f4-suid f4-b-paralelo f4-c1-logs f4-c2-tamper f4-c3-stop"

esperado() {  # defensive signal per link (F4 cards); each link has its own clock
  case "$1" in
    f4-a1-shell)   echo "unexpected_exec high (+hot webshell with the triple filter); tier 1 isolate/confine" ;;
    f4-a2-recon)   echo "coverage note: only unlearned commands or sensitive accesses are visible" ;;
    f4-a3-leer)    echo "sensitive_read high with unit+file+exe (ephemeral reader named, B57)" ;;
    f4-a4-pwnkit)  echo "unexpected_exec for pkexec if the unit never launched it; the CVE itself is not recognized" ;;
    f4-a5-persist) echo "integrity high cron/systemd_units: TIER 2 pending (pending_id), no automatic restore" ;;
    f4-a6-exfil)   echo "egress_profile: kernel cut on the first packet to an unlearned destination; zero bytes received" ;;
    f4-a7-minero)  echo "same F3 fixture: detection + suspension on the first sweep" ;;
    f4-suid)       echo "suid_new crit ONLY for a new post-baseline SUID; tier 2 pending; hourly cadence" ;;
    f4-b-paralelo) echo "findings per unit without cross-unit dedup; 0 benign FPs; brake=documented policy" ;;
    f4-c1-logs)    echo "log_tamper high tier 0 on the next sweep (auth.log deleted/truncated)" ;;
    f4-c2-tamper)  echo "self_tamper crit tier 0 <=5 min (dpkg --verify in self-check)" ;;
    f4-c3-stop)    echo "self_stopped crit + external notice; clean stop does NOT auto-restart (LAST scenario)" ;;
  esac
}

estado() {  # instantaneous snapshot of relevant Arx state
  echo "fecha: $(date -Is)"
  echo "arx: $(systemctl is-active arx) · reinicios: $(systemctl show -p NRestarts --value arx) · memoria: $(systemctl show -p MemoryCurrent --value arx)"
  echo "incidentes: $([ -f "$INC" ] && wc -l < "$INC" || echo 0) · sha256: $([ -f "$INC" ] && sha256sum "$INC" | cut -c1-16 || echo -)"
  echo "bloqueos-ipv4: $(nft list set inet arx block_ipv4 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | wc -l | tr -d ' ') · ipv6: $(nft list set inet arx block_ipv6 2>/dev/null | grep -cE '::|:[0-9a-f]' || echo 0)"
  echo "congelados: $(grep -l '^1$' /sys/fs/cgroup/arxconfine.slice/arxconfine-*.scope/cgroup.freeze 2>/dev/null | wc -l)"
  echo "journal-cursor: $(journalctl -u arx -n 0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p')"
}

_ventana_ini() { # $1=scenario: opening marker
  case " $ESCENARIOS " in *" $1 "*) ;; *) echo "escenario desconocido: $1 (válidos: $ESCENARIOS)" >&2; exit 2;; esac
  mkdir -p "$DIR"
  { echo "fecha: $(date -Is)"; echo "incidentes: $(wc -l < "$INC" 2>/dev/null || echo 0)"
    journalctl -u arx -n 0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p'; } > "$DIR/$1.ini"
  echo "ventana abierta: $1 — lanza ahora el escenario; al terminar: despues $1"
}

_ventana_fin() { # $1=scenario: observations inside the window
  [ -f "$DIR/$1.ini" ] || { echo "falta 'antes $1'" >&2; exit 2; }
  local ini_n ini_cursor fin_n
  ini_n=$(sed -n 's/^incidentes: //p' "$DIR/$1.ini")
  ini_cursor=$(sed -n '3p' "$DIR/$1.ini")
  fin_n=$(wc -l < "$INC" 2>/dev/null || echo 0)
  {
    echo "== $1 · $(date -Is)"
    echo "esperado: $(esperado "$1")"
    echo "incidentes nuevos: $((fin_n - ini_n))"
    [ -f "$INC" ] && [ "$fin_n" -gt "$ini_n" ] && { echo "-- incidentes de la ventana:"; tail -n +"$((ini_n + 1))" "$INC"; }
    echo "-- journal de la ventana (crit/high):"
    journalctl -u arx --after-cursor "$ini_cursor" 2>/dev/null | grep -iE "crit|high|alta|crít" | tail -20
    echo "-- estado final:"
    estado
  } > "$DIR/$1.fin"
  echo "ventana cerrada: $1 → $DIR/$1.fin"
}

_informe() {
  local f="$DIR/f4-informe-$(date +%Y%m%d-%H%M).md" e nuevos det
  {
    echo "# F4 · arx-u24 · $(date -Is)"
    echo
    echo "F4 assume-breach: el exploit funciona por diseño; se mide la respuesta post-explotación, eslabón por eslabón. Medición: f4-vps-evidencia.sh (solo lectura)."
    echo
    echo "| escenario | esperado | incidentes nuevos | detección |"
    echo "|---|---|---|---|"
    for e in $ESCENARIOS; do
      [ -f "$DIR/$e.fin" ] || continue
      nuevos=$(sed -n 's/^incidentes nuevos: //p' "$DIR/$e.fin")
      det=$([ "${nuevos:-0}" -gt 0 ] && echo "sí" || echo "NO")
      echo "| $e | $(esperado "$e") | $nuevos | $det |"
    done
    echo
    for e in $ESCENARIOS; do [ -f "$DIR/$e.fin" ] && { echo; echo "## $e"; echo '```'; cat "$DIR/$e.fin"; echo '```'; }; done
    echo
    echo "baseline:"; echo '```'; cat "$DIR/antes.txt" 2>/dev/null; echo '```'
    echo "EV: sha256 incidents.jsonl = $(sha256sum "$INC" 2>/dev/null | cut -d' ' -f1)"
  } > "$f"
  echo "$f"
}

case "${1:-}" in
  init)    mkdir -p "$DIR"; estado | tee "$DIR/antes.txt" ;;
  antes)   _ventana_ini "${2:?escenario}" ;;
  despues) _ventana_fin "${2:?escenario}" ;;
  informe) _informe ;;
  *) echo "uso: $0 init | antes <esc> | despues <esc> | informe  (escenarios: $ESCENARIOS)" >&2; exit 2 ;;
esac
