#!/bin/sh
# Arx Core — instalador.
#
#   curl -fsSL https://<host>/install.sh | sudo sh
#
# Variables:
#   ARX_DEB_URL   URL del .deb (por defecto: última release de GitHub — fijar en el release)
#   ARX_DEB_PATH  ruta a un .deb local (pruebas/offline; salta la descarga)
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
  echo "Descargando Arx desde $URL …"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$DEB"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$DEB" "$URL"
  else
    echo "Necesito curl o wget para descargar."
    exit 1
  fi
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
  sudo arx service install  # defensa 24/7 (systemd)
MSG
