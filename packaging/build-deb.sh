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
MAINTAINER="${ARX_MAINTAINER:-Advanced Systems Laboratories <mperez90@users.noreply.github.com>}"
STAGE="$(mktemp -d)"
PKG="$STAGE/pkg"
trap 'rm -rf "$STAGE"' EXIT

# 1) zipapp
python3 -m zipapp "$ROOT/src" -m "arx.cli:entry" -o "$STAGE/arx.pyz" -p "/usr/bin/env python3"

# 2) árbol del paquete
mkdir -p "$PKG/DEBIAN" "$PKG/usr/lib/arx" "$PKG/usr/bin"
cp "$STAGE/arx.pyz" "$PKG/usr/lib/arx/arx.pyz"

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
Depends: python3 (>= 3.10)
Recommends: nftables
Maintainer: $MAINTAINER
Installed-Size: $INSTALLED_KB
Description: Arx - autonomous defensive security agent
 Learns your server's normal and contains threats automatically with actions that
 undo themselves. Human-gated for irreversible actions. Python stdlib only.
EOF

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
cat <<'MSG'

Arx instalado. Para ponerlo en guardia:
  sudo arx setup            # modelo LLM, palabra de autorización, licencia
  sudo arx recon            # mapear el servidor
  sudo arx learn            # aprender lo normal (repetir unos días)
  sudo arx learn --seal     # cerrar la línea base
  sudo arx service install  # defensa 24/7 en modo observar (systemd)
  sudo arx notify test      # comprobar que te llegan las alertas

MSG
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/postinst"

cat > "$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  if [ -d /run/systemd/system ]; then
    systemctl disable --now arx 2>/dev/null || true
  fi
fi
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/prerm"

# 3) empaquetar
mkdir -p "$ROOT/dist"
DEB="$ROOT/dist/arx_${VERSION}_all.deb"
if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "Árbol del paquete listo en: $PKG"
  find "$PKG" -type f | sed "s|$PKG|  |"
  echo ""
  echo "dpkg-deb no está en este sistema. Para producir el .deb, corre esto en Ubuntu/Debian o CI:"
  echo "  packaging/build-deb.sh $VERSION"
  exit 1
fi
dpkg-deb --root-owner-group --build "$PKG" "$DEB"
# Copia con nombre estable: es la que descarga install.sh desde .../releases/latest/download/
cp "$DEB" "$ROOT/dist/arx_all.deb"
echo "OK: $DEB (+ dist/arx_all.deb)"
