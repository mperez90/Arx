#!/usr/bin/env bash
# Mini-lab Docker de Arx — DOS contenedores en red aislada:
#   · víctima  (ubuntu:22.04 privilegiada, sin ufw → ejercita nftables; sshd+rsyslog)
#   · atacante (ubuntu:22.04 con nmap/sshpass/curl)
# Niveles: L1 escaneo nmap real · L2 fuerza bruta SSH real · L4/L5/L7/L8/L9 en víctima.
# Niveles 3 y 10 son destructivos/VM (ver lab/README.md y lab/vm/). Todo es efímero:
# la red y los contenedores se destruyen al salir.
set -euo pipefail
cd "$(dirname "$0")/.."

SUF=$$
NET=arxlab-$SUF
VIC=arxv-$SUF
ATT=arxa-$SUF
FAILED=0

cleanup() {
  docker rm -f "$VIC" "$ATT" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "══ red y contenedores ══"
docker network create "$NET" >/dev/null

docker run -d --name "$VIC" --privileged --network "$NET" --network-alias victim \
  -v "$PWD":/src:ro ubuntu:22.04 bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq python3 nftables netcat-openbsd procps \
      openssh-server rsyslog >/dev/null 2>&1
    ssh-keygen -A >/dev/null 2>&1
    mkdir -p /run/sshd /work/labcfg /work/labstate
    echo root:arxlab | chpasswd
    sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config
    rsyslogd 2>/dev/null || true
    /usr/sbin/sshd
    # listeners señuelo 9001-9012: HAN de nacer en el entrypoint (docker exec mata
    # el árbol de procesos al terminar la sesión — B7). Dan al escaneo algo que tocar:
    # un SYN-scan contra puertos cerrados no deja socket en /proc/net (límite honesto).
    for p in $(seq 9001 9012); do nc -k -l $p </dev/null >/dev/null 2>&1 & done
    sleep infinity' >/dev/null

docker run -d --name "$ATT" --network "$NET" --network-alias attacker \
  ubuntu:22.04 bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq nmap sshpass curl >/dev/null 2>&1
    sleep infinity' >/dev/null

echo "esperando a que víctima (sshd) y atacante (nmap) estén listos…"
docker exec "$VIC" bash -c 'for i in $(seq 90); do pgrep -x sshd >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1'
docker exec "$ATT" bash -c 'for i in $(seq 90); do command -v nmap >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1'

ATTACKER_IP=$(docker exec "$VIC" python3 -c "import socket; print(socket.gethostbyname('attacker'))")
echo "atacante: $ATTACKER_IP"

step() { echo; echo "══ $1 ══"; }

step "preparación de la víctima (learn + seal + canario + señuelos de puerto)"
docker exec "$VIC" python3 /src/lab/driver.py prep

step "nivel 1: escaneo real — nmap -sS (SYN, el escaneo por defecto) desde el atacante"
docker exec "$ATT" nmap -sS -p 9000-9020 --max-retries 1 victim | grep -E "open|closed" | head -4 || true
docker exec "$VIC" bash -c 'nft list set inet arx scan4 2>/dev/null | head -8' || true
docker exec "$VIC" python3 /src/lab/driver.py net-scan "$ATTACKER_IP" || FAILED=1

# El bloqueo del L1 cortaría la fuerza bruta del L2: liberar entre fases (ciclo real
# de expiración, no un flush a mano).
docker exec "$VIC" python3 /src/lab/driver.py release

step "nivel 2: fuerza bruta real — 8 intentos SSH fallidos desde el atacante"
docker exec "$ATT" bash -c 'for i in $(seq 8); do
  sshpass -p "clave-mala-$i" ssh -o StrictHostKeyChecking=no \
    -o PreferredAuthentications=password -o ConnectTimeout=3 root@victim true \
    2>/dev/null || true
done'
docker exec "$VIC" python3 /src/lab/driver.py net-brute "$ATTACKER_IP" || FAILED=1

step "prueba de contención: el atacante ya NO alcanza a la víctima"
if docker exec "$ATT" curl -s --max-time 4 http://victim:9001/ >/dev/null 2>&1; then
  echo "[FAIL] contención: el atacante SIGUE alcanzando la víctima tras el bloqueo"
  FAILED=1
else
  echo "[PASS] contención: la IP del atacante quedó bloqueada (curl agota el tiempo)"
fi

step "niveles 4, 5, 7, 8 y 9 en la víctima"
docker exec "$VIC" python3 /src/lab/driver.py levels || FAILED=1

echo
if [ "$FAILED" = 0 ]; then
  echo "══ MINI-LAB COMPLETO: todos los niveles ejecutables superados ══"
else
  echo "══ MINI-LAB CON FALLOS (ver líneas [FAIL]) ══"
  exit 1
fi
