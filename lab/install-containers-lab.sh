#!/usr/bin/env bash
# B75: `packaging/install.sh` en contenedores limpios (Ubuntu 24.04, Ubuntu 22.04, Debian 13), sin python3 ni auditd:
# apt tiene que resolver las dependencias y el paquete en un solo paso, con salida limpia y un único mensaje final.
# Un contenedor no tiene systemd (el aviso de auditd no aplica: eso se ve en una VM) ni terminal (no se pregunta nada).
# El .deb se construye en un contenedor Debian 13 desde NEW_REF (el Mac no tiene dpkg-deb); necesita red para apt.
#   NEW_REF=HEAD bash lab/install-containers-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."
NEW_REF=${NEW_REF:-HEAD}
IMAGES=${IMAGES:-"ubuntu:24.04 ubuntu:22.04 debian:13"}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }

echo "# instalador en contenedores · ${IMAGES} · $(git rev-parse --short "$NEW_REF")"
mkdir -p "$WORK/src" "$WORK/dist"
git archive --format=tar "$NEW_REF" src packaging | tar -x -C "$WORK/src"
cp "$WORK/src/packaging/install.sh" "$WORK/install.sh"

echo; echo "══ construir el .deb (debian:13) ══"
docker run --rm -v "$WORK/src:/src" -v "$WORK/dist:/dist" debian:13 sh -c '
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 >/dev/null 2>&1 &&
  cd /src && bash packaging/build-deb.sh "0.0.9~rc2+ctr" >/dev/null 2>&1 && cp dist/arx_all.deb /dist/arx_all.deb' \
  && [ -s "$WORK/dist/arx_all.deb" ] || { echo "[FAIL] no se pudo construir el .deb"; exit 1; }
ls -l "$WORK/dist/arx_all.deb" | awk '{print "  " $NF " " $5 " bytes"}'

for IMG in $IMAGES; do
  echo; echo "══ $IMG ══"
  NAME="arx-install-lab-$$-$(echo "$IMG" | tr -c 'a-z0-9' '-')"
  docker run -d --name "$NAME" -v "$WORK/dist:/dist:ro" -v "$WORK/install.sh:/install.sh:ro" "$IMG" sleep 3600 >/dev/null
  run() { docker exec "$NAME" sh -c "$1" 2>&1; }

  OUT=$(run 'cd /dist && ARX_DEB_PATH=arx_all.deb sh /install.sh; echo "EXIT=$?"')
  echo "$OUT" | sed 's/^/  | /' | head -14
  check "$IMG: instala (exit 0)" grep -q '^EXIT=0$' <<<"$OUT"
  check "$IMG: un único mensaje final" test "$(grep -c 'Arx installed' <<<"$OUT")" = 1
  check "$IMG: sin ruido de apt ni del postinst" bash -c '! grep -qE "Reading package lists|Setting up|NEW packages|Unpacking|Selecting previously|^N: |^W: " <<<"$1"' _ "$OUT"
  check "$IMG: apt resolvió python3 y auditd" run 'dpkg -s python3 auditd | grep -c "^Status: install ok installed" | grep -qx 2'
  check "$IMG: el paquete quedó instalado y arx arranca" run 'dpkg -s arx | grep -q "Status: install ok installed" && arx --version'
  check "$IMG: sin avisos de apt por el .deb (_apt, ruta relativa)" bash -c '! grep -qiE "unsandboxed|not a package|Unable to locate" <<<"$1"' _ "$OUT"

  OUT2=$(run 'cd /dist && ARX_DEB_PATH=arx_all.deb sh /install.sh; echo "EXIT=$?"')
  check "$IMG: volver a ejecutarlo es inocuo (exit 0, un mensaje)" bash -c 'grep -q "^EXIT=0$" <<<"$1" && test "$(grep -c "Arx installed" <<<"$1")" = 1' _ "$OUT2"
  docker rm -f "$NAME" >/dev/null 2>&1

  # sin red: apt no puede traer las dependencias; el instalador lo dice con la salida de apt y sale con 1, sin victoria falsa
  OUT3=$(docker run --rm --network none -v "$WORK/dist:/dist:ro" -v "$WORK/install.sh:/install.sh:ro" "$IMG" \
         sh -c 'cd /dist && ARX_DEB_PATH=arx_all.deb sh /install.sh; echo "EXIT=$?"' 2>&1)
  check "$IMG: sin red falla con exit 1, enseña la salida de apt y no canta victoria" bash -c \
    'grep -q "^EXIT=1$" <<<"$1" && grep -q "could not be installed" <<<"$1" && ! grep -q "Arx installed" <<<"$1"' _ "$OUT3"
done

echo
[ "$FAILED" = 0 ] && echo "RESULT: ok" || echo "RESULT: FAIL"
exit "$FAILED"
