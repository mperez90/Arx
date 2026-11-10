#!/usr/bin/env bash
# F3 (prueba de fuego): medición de la respuesta de Arx en arx-u24. SOLO LECTURA del estado de Arx:
# este script no planta ni lanza ningún escenario; los escenarios los ejecuta Mauricio a mano en otra
# terminal (referencia: lab/*.sh). Uso, como root en el VPS:
#   bash f2-vps-evidencia.sh init            # baseline
#   bash f2-vps-evidencia.sh antes  <esc>    # abre la ventana de un escenario
#   bash f2-vps-evidencia.sh despues <esc>   # la cierra y recoge lo observado
#   bash f2-vps-evidencia.sh informe         # genera /root/f2/f3-informe-<fecha>.md
set -uo pipefail
DIR=/root/f3
INC=/var/lib/arx/incidents.jsonl

ESCENARIOS="ext-scan ext-bruteforce ext-web ext-synburst evasion-rapido evasion-lenta evasion-freno evasion-mimica minero limites-userland limites-kernel"

esperado() {  # qué debe hacer Arx (defensivo) en cada escenario
  case "$1" in
    ext-scan)        echo "alta: escaneo de puertos detectado (set scan4/tarpit), IP marcada o en tarpit" ;;
    ext-bruteforce)  echo "alta/crit: fuerza bruta SSH; IP en block_ipv4 o tarpit; 0 éxitos" ;;
    ext-web)         echo "alta: sondeo web / slowloris absorbido; nginx sigue sirviendo" ;;
    ext-synburst)    echo "rafaga SYN absorbida; ssh sigue respondiendo; sin falsos positivos" ;;
    evasion-rapido)  echo "procesos < intervalo de barrido: vistos por conector de procesos (no por barrido)" ;;
    evasion-lenta)   echo "exfil lenta bajo umbral: registrada por perfil de egreso acumulado o límite documentado" ;;
    evasion-freno)   echo "abuso del freno 5/h: el ataque tras el freno sigue alertado aunque no actúe" ;;
    evasion-mimica)  echo "proceso que imita perfil aprendido: no alerta (límite) o alerta por contexto" ;;
    minero)          echo "crit: ejecutable nuevo + egreso a pool cortado + CPU anómala; congelado o confinado" ;;
    limites-userland) echo "Arx ve el proceso oculto vía LD_PRELOAD (netlink no usa ps); documentar" ;;
    limites-kernel)  echo "carga de módulo: alerta o límite honesto documentado (fuera de alcance)" ;;
  esac
}

estado() {  # volcado instantáneo del estado relevante de Arx
  echo "fecha: $(date -Is)"
  echo "arx: $(systemctl is-active arx) · reinicios: $(systemctl show -p NRestarts --value arx) · memoria: $(systemctl show -p MemoryCurrent --value arx)"
  echo "incidentes: $([ -f "$INC" ] && wc -l < "$INC" || echo 0) · sha256: $([ -f "$INC" ] && sha256sum "$INC" | cut -c1-16 || echo -)"
  echo "bloqueos-ipv4: $(nft list set inet arx block_ipv4 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | wc -l | tr -d ' ') · ipv6: $(nft list set inet arx block_ipv6 2>/dev/null | grep -cE '::|:[0-9a-f]' || echo 0)"
  echo "congelados: $(grep -l '^1$' /sys/fs/cgroup/arxconfine.slice/arxconfine-*.scope/cgroup.freeze 2>/dev/null | wc -l)"
  echo "journal-cursor: $(journalctl -u arx -n 0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p')"
}

_ventana_ini() { # $1=escenario: marca de apertura
  case " $ESCENARIOS " in *" $1 "*) ;; *) echo "escenario desconocido: $1 (válidos: $ESCENARIOS)" >&2; exit 2;; esac
  mkdir -p "$DIR"
  { echo "fecha: $(date -Is)"; echo "incidentes: $(wc -l < "$INC" 2>/dev/null || echo 0)"
    journalctl -u arx -n 0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p'; } > "$DIR/$1.ini"
  echo "ventana abierta: $1 — lanza ahora el escenario; al terminar: despues $1"
}

_ventana_fin() { # $1=escenario: lo observado en la ventana
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
  local f="$DIR/f3-informe-$(date +%Y%m%d-%H%M).md" e nuevos det
  {
    echo "# F3 · arx-u24 · $(date -Is)"
    echo
    echo "Prueba de fuego F3 (externo + evasión + malware real + límites) contra arx-u24 (propio). Medición: f3-vps-evidencia.sh (solo lectura)."
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
