#!/bin/sh
# Arx Core — instalador.
#
#   curl -fsSL https://<host>/install.sh | sudo sh
#
# Variables:
#   ARX_DEB_URL   URL del .deb (por defecto: última release de GitHub)
#   ARX_DEB_PATH  ruta a un .deb local (pruebas/offline; salta la descarga y la verificación)
#
# Verifica el SHA-256 del .deb contra el SHA256SUMS publicado en la misma release antes de
# instalar nada: si no coincide, aborta.
set -eu

if [ "$(id -u)" != "0" ]; then
  echo "Arx se instala como root:  curl -fsSL <url>/install.sh | sudo sh"
  exit 1
fi

if ! command -v dpkg >/dev/null 2>&1; then
  echo "Este instalador es para sistemas Debian/Ubuntu (dpkg)."
  echo "En otros sistemas: descarga arx.pyz y córrelo con python3 (>= 3.11)."
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -n "${ARX_DEB_PATH:-}" ]; then
  DEB="$ARX_DEB_PATH"
else
  DEB="$TMP/arx.deb"
  URL="${ARX_DEB_URL:-https://github.com/mperez90/Arx/releases/latest/download/arx_all.deb}"
  SUMS_URL="${URL%/*}/SHA256SUMS"
  fetch() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
    else echo "Necesito curl o wget para descargar."; exit 1; fi
  }
  echo "Descargando Arx desde $URL …"
  fetch "$URL" "$DEB"
  fetch "$SUMS_URL" "$TMP/SHA256SUMS"
  WANT="$(awk '$2 ~ /arx_all\.deb$/ {print $1}' "$TMP/SHA256SUMS")"
  GOT="$(sha256sum "$DEB" | cut -d' ' -f1)"
  if [ -z "$WANT" ] || [ "$WANT" != "$GOT" ]; then
    echo "✗ El SHA-256 del paquete no coincide con el publicado. NO se instala."
    exit 1
  fi
  echo "✓ Integridad verificada (sha256 $GOT)"
fi

echo "Instalando…"
# dpkg -i puede fallar por la dependencia python3; apt la resuelve.
# Silenciamos su salida (el postinst) para no duplicar el mensaje de pasos de abajo.
if ! dpkg -i "$DEB" >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -f -y
fi

cat <<'MSG'

✓ Arx instalado. Para ponerlo en guardia:
  sudo arx setup            # modelo LLM, palabra de autorización, licencia
  sudo arx recon            # mapear el servidor
  sudo arx learn            # aprender lo normal (repetir unos días)
  sudo arx learn --seal     # cerrar la línea base
  sudo arx service install  # defensa 24/7 en modo observar (systemd)
  sudo arx notify test      # comprobar que te llegan las alertas
MSG
