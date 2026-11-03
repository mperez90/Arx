#!/usr/bin/env bash
# Mini-lab Docker de Arx: víctima Ubuntu 22.04 privilegiada (sin ufw → prueba el
# ejecutor nftables), atacando niveles 3-9 en contenedor único. Ver lab/README.md.
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm --privileged \
  -v "$PWD":/src:ro \
  ubuntu:22.04 bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq python3 nftables netcat-openbsd procps >/dev/null 2>&1
    mkdir -p /work/labcfg /work/labstate
    python3 /src/lab/driver.py
  '
