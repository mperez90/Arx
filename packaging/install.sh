#!/bin/sh
# Arx Core — instalador.
#
#   curl -fsSLO https://raw.githubusercontent.com/mperez90/Arx/f1-core-mvp/packaging/install.sh
#   sudo sh install.sh
#
# Variables:
#   ARX_DEB_URL   URL del .deb (por defecto: última release de GitHub)
#   ARX_DEB_PATH  ruta a un .deb local (pruebas/offline; salta la descarga y la verificación)
#
# Verifica el SHA-256 del .deb contra el SHA256SUMS publicado en la misma release antes de
# instalar nada: si no coincide, aborta.
set -eu

if [ "$(id -u)" != "0" ]; then
  echo "Arx installs as root:  sudo sh install.sh"
  exit 1
fi

if ! command -v dpkg >/dev/null 2>&1; then
  echo "This installer is for Debian/Ubuntu systems (dpkg)."
  echo "On other systems: download arx.pyz and run it with python3 (>= 3.10)."
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
    else echo "curl or wget is needed to download."; exit 1; fi
  }
  echo "Downloading Arx from $URL …"
  fetch "$URL" "$DEB"
  fetch "$SUMS_URL" "$TMP/SHA256SUMS"
  WANT="$(awk '$2 ~ /arx_all\.deb$/ {print $1}' "$TMP/SHA256SUMS")"
  GOT="$(sha256sum "$DEB" | cut -d' ' -f1)"
  if [ -z "$WANT" ] || [ "$WANT" != "$GOT" ]; then
    echo "✗ The package SHA-256 does not match the published one. NOT installing."
    exit 1
  fi
  echo "✓ Integrity verified (sha256 $GOT)"
fi

echo "Installing…"
# dpkg -i falla si faltan sus dependencias (python3, auditd); apt las resuelve e instala.
# Silenciamos su salida (el postinst) para no duplicar el mensaje de pasos de abajo.
if ! dpkg -i "$DEB" >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -f -y
fi

# auditd viene siempre con Arx: sin él no hay avisos de ficheros de identidad, señuelos ni lecturas
# denegadas. En un contenedor el núcleo no deja arrancarlo; se avisa, no se aborta.
if [ -d /run/systemd/system ] && ! systemctl is-active --quiet auditd 2>/dev/null; then
  systemctl enable --now auditd >/dev/null 2>&1 || \
    echo "⚠ auditd is installed but not running (systemctl status auditd): Arx's identity-file, honeytoken and denied-open alerts stay off until it runs."
fi

# Programa de mejora: se pregunta una sola vez y solo con una terminal delante. Sin respuesta, no se envía nada.
arx telemetry ask || true

cat <<'MSG'

✓ Arx installed. To put it on guard:
  sudo arx setup            # language, LLM model, authorization word, license
  sudo arx recon            # map the server
  sudo arx learn            # learn what is normal (repeat over a few days)
  sudo arx learn --seal     # seal the baseline
  sudo arx service install  # 24/7 defense in observe mode (systemd)
  sudo arx notify test      # check that alerts reach you

  sudo arx shell            # interactive console (colored prompt, history, Tab)
  man arx                   # the full manual
MSG
