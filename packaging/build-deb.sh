#!/usr/bin/env bash
# Construye el paquete .deb de Arx Core.
#
# Requiere dpkg-deb (viene en Ubuntu/Debian y en cualquier runner de CI Ubuntu).
# En macOS/otros: genera el árbol del paquete para inspección y avisa que el
# empaquetado final necesita dpkg-deb — no lo finge.
#
#   packaging/build-deb.sh [version]
#
# Instala:
#   /usr/lib/arx/arx.pyz      el agente (zipapp de un fichero)
#   /usr/bin/arx              wrapper de consola
# El unit de systemd NO va en el paquete: lo gestiona `arx service install`
# (única fuente de verdad), tras setup + baseline sellada.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-$(python3 -c "import sys; sys.path.insert(0, '$ROOT/src'); import arx; print(arx.__version__)" 2>/dev/null || echo 0.0.1)}"
# 0.0.9rc1 (Python) → 0.0.9~rc1 (Debian): una candidata se ordena antes que su versión final
VERSION="$(printf '%s' "$VERSION" | sed -E 's/(a|b|rc)([0-9]+)$/~\1\2/')"
MAINTAINER="${ARX_MAINTAINER:-Advanced Systems Laboratories <mperez90@users.noreply.github.com>}"
STAGE="$(mktemp -d)"
PKG="$STAGE/pkg"
trap 'rm -rf "$STAGE"' EXIT

# 1) zipapp
python3 -m zipapp "$ROOT/src" -m "arx.cli:entry" -o "$STAGE/arx.pyz" -p "/usr/bin/env python3"

# 2) árbol del paquete
mkdir -p "$PKG/DEBIAN" "$PKG/usr/lib/arx" "$PKG/usr/bin" "$PKG/usr/share/man/man1"
cp "$STAGE/arx.pyz" "$PKG/usr/lib/arx/arx.pyz"
gzip -9n -c "$ROOT/packaging/arx.1" > "$PKG/usr/share/man/man1/arx.1.gz"  # `man arx`

cat > "$PKG/usr/bin/arx" <<'EOF'
#!/bin/sh
exec /usr/bin/env python3 /usr/lib/arx/arx.pyz "$@"
EOF
chmod 0755 "$PKG/usr/bin/arx"

INSTALLED_KB="$(du -sk "$PKG" | cut -f1)"
cat > "$PKG/DEBIAN/control" <<EOF
Package: arx
Version: $VERSION
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.10), auditd
Recommends: nftables
Maintainer: $MAINTAINER
Installed-Size: $INSTALLED_KB
Description: Arx - autonomous defensive security agent
 Learns your server's normal and contains threats automatically with actions that
 undo themselves. Human-gated for irreversible actions. Python stdlib only.
EOF

cat > "$PKG/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -e
# Un zipapp no es un ELF: zipimport vuelve a abrir /usr/lib/arx/arx.pyz en cada import perezoso, así que el
# archive no puede cambiar bajo un guardián vivo. Va en el preinst del paquete NUEVO: dpkg lo ejecuta antes de
# unpack en toda actualización, también desde versiones cuyo prerm no paraba nada (≤ 0.0.8), y si falla la
# actualización se aborta (un prerm fallido lo rescata «new-prerm failed-upgrade» y dpkg seguiría).
MARK=/run/arx/package-upgrade-active
if [ "$1" = "upgrade" ] && [ -d /run/systemd/system ]; then
  state=$(systemctl show -p ActiveState --value arx.service 2>/dev/null) || state=""
  case "$state" in
    inactive|failed)
      # Parado. Una marca superviviente solo puede venir de una operación de paquete que lo paró y no llegó a
      # arrancarlo (el guardián la borra al arrancar): se conserva para que el postinst lo arranque.
      ;;
    deactivating)
      # Alguien ya lo está parando: se espera a que termine sin cambiar su intención.
      systemctl stop arx.service
      ;;
    "")
      echo "arx: cannot read the state of arx.service; not replacing Arx under a possibly running daemon" >&2
      exit 1
      ;;
    *)
      # active, activating (también auto-restart), reloading…: parada planeada y marca para volver a arrancar.
      mkdir -p /run/arx
      : > "$MARK"
      : > /run/arx/planned-stop
      if ! systemctl stop arx.service; then
        rm -f "$MARK" /run/arx/planned-stop
        echo "arx: arx.service could not be stopped; not replacing Arx under a running daemon" >&2
        exit 1
      fi
      # stop es síncrono: si ExecStopPost no la consumió (auto-restart), no puede tragarse una parada posterior.
      rm -f /run/arx/planned-stop
      ;;
  esac
fi
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/preinst"

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
MARK=/run/arx/package-upgrade-active
# Actualiza el slice. Si el guardián corría, preinst ya lo detuvo antes de reemplazar
# el zipapp; aquí vuelve a arrancar con un único archive coherente.
if [ -d /run/systemd/system ] && [ -f /etc/systemd/system/arx.service ]; then
  arx service refresh-maintenance >/dev/null 2>&1 || true
  if [ -f "$MARK" ]; then
    # Si no arranca, la marca se queda: `dpkg --configure -a` (o la siguiente actualización) lo reintenta.
    if ! systemctl start arx.service; then
      echo "arx: arx.service did not start after the upgrade; fix it and run: dpkg --configure -a" >&2
      exit 1
    fi
    rm -f "$MARK"
  fi
fi
cat <<'MSG'

Arx installed. To put it on guard:
  sudo arx setup            # language, LLM model, authorization word, license
  sudo arx recon            # map the server
  sudo arx learn            # learn what is normal (repeat over a few days)
  sudo arx learn --seal     # seal the baseline
  sudo arx service install  # 24/7 defense in observe mode (systemd)
  sudo arx notify test      # check that alerts reach you

MSG
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/postinst"

cat > "$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# Una actualización no se gestiona aquí sino en el preinst del paquete nuevo (lo ejecuta siempre).
# Sin Arx no queda nada suyo: lo que confinó recupera la red, y sus units, drop-ins y tabla nft se van.
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  if [ -d /run/systemd/system ]; then
    if ! arx service uninstall >/dev/null 2>&1; then
      systemctl disable --now arx arx-firewall 2>/dev/null || true
      systemctl list-units --type=scope --all --plain --no-legend 2>/dev/null \
        | awk '$1 ~ /^arx-maint-.*\.scope$/ {print $1}' | xargs -r systemctl stop 2>/dev/null || true
      rm -f /etc/systemd/system/arx.service /etc/systemd/system/arx-firewall.service \
        /etc/systemd/system/arx-down.service /etc/systemd/system/arx-revive.service \
        /etc/systemd/system/arx-revive.timer /etc/systemd/system/arx-maintenance.slice
      systemctl daemon-reload 2>/dev/null || true
    fi
  fi
fi
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/prerm"

cat > "$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
# B71: si el unpack falla después de que preinst parara a Arx, dpkg llama a este postrm con abort-upgrade. Lo
# desempaquetado nunca reemplazó los ficheros viejos (medido: en este punto el zipapp en disco es el anterior),
# así que se vuelve a arrancar el Arx que corría. Al venir de ≤0.0.8, su postinst abort-upgrade no lo haría.
if [ "$1" = "abort-upgrade" ] && [ -f /run/arx/package-upgrade-active ] && [ -d /run/systemd/system ]; then
  if systemctl start arx.service; then
    rm -f /run/arx/package-upgrade-active
  fi
fi
# purge: también la configuración (claves de API, la palabra) y el estado
if [ "$1" = "purge" ]; then
  rm -rf /etc/arx /var/lib/arx
fi
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/postrm"

# 3) empaquetar
mkdir -p "$ROOT/dist"
DEB="$ROOT/dist/arx_${VERSION}_all.deb"
if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "Package tree ready at: $PKG"
  find "$PKG" -type f | sed "s|$PKG|  |"
  echo ""
  echo "dpkg-deb is not on this system. To build the .deb, run this on Ubuntu/Debian or CI:"
  echo "  packaging/build-deb.sh $VERSION"
  exit 1
fi
dpkg-deb --root-owner-group --build "$PKG" "$DEB"
# Copia con nombre estable: es la que descarga install.sh desde .../releases/latest/download/
cp "$DEB" "$ROOT/dist/arx_all.deb"
echo "OK: $DEB (+ dist/arx_all.deb)"
