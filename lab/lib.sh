# Contenedores del mini-lab de Arx — los usan docker-lab.sh y demo.sh.
#   · víctima  (ubuntu:22.04 privilegiada, sin ufw → ejercita nftables; sshd+rsyslog)
#   · atacante (ubuntu:22.04 con nmap/sshpass/curl/nc y un C2 de laboratorio en 4444)
# Todo es efímero: la red y los contenedores se destruyen al salir.

SUF=$$
NET=arxlab-$SUF
VIC=arxv-$SUF
ATT=arxa-$SUF

cleanup() {
  docker rm -f "$VIC" "$ATT" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

lab_up() {
  docker network create "$NET" >/dev/null

  docker run -d --name "$VIC" --privileged --network "$NET" --network-alias victim \
    -v "$PWD":/src:ro ubuntu:22.04 bash -c '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq python3 nftables netcat-openbsd procps iproute2 \
        openssh-server rsyslog >/dev/null 2>&1
      ssh-keygen -A >/dev/null 2>&1
      mkdir -p /run/sshd /work/labcfg /work/labstate
      echo root:arxlab | chpasswd
      sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config
      rsyslogd 2>/dev/null || true
      /usr/sbin/sshd
      # listeners señuelo 9001-9012: HAN de nacer en el entrypoint (docker exec mata el
      # árbol de procesos al terminar la sesión — B7). Dan al escaneo algo que tocar.
      for p in $(seq 9001 9012); do nc -k -l $p </dev/null >/dev/null 2>&1 & done
      touch /ready
      sleep infinity' >/dev/null

  # El C2 usa `nc` y no `ncat`: con stdin cerrado, ncat cierra cada conexión al instante.
  # La FIFO permite enviar órdenes al reverse shell y comprobar si llegan o no.
  docker run -d --name "$ATT" --network "$NET" --network-alias attacker \
    ubuntu:22.04 bash -c '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq nmap netcat-openbsd sshpass curl >/dev/null 2>&1
      mkfifo /tmp/c2in
      (tail -f /tmp/c2in | nc -lk 4444 >/tmp/c2out 2>&1) &
      touch /ready
      sleep infinity' >/dev/null

  local c
  for c in "$VIC" "$ATT"; do
    docker exec "$c" bash -c 'for i in $(seq 180); do [ -f /ready ] && exit 0; sleep 1; done; exit 1'
  done

  ATTACKER_IP=$(docker exec "$VIC" python3 -c "import socket; print(socket.gethostbyname('attacker'))")
}

# Envía una orden al reverse shell a través del C2 del atacante.
c2_send() { docker exec "$ATT" bash -c "echo '$1' > /tmp/c2in"; }
