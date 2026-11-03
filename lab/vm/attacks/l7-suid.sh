#!/usr/bin/env bash
# L7 — escalada: plantar un binario SUID nuevo (dentro de la víctima, tras entrar por SSH).
# Esperado: crit de integridad SUID (barrido horario; inmediato con `sudo arx guard --once`).
set -e
cp /usr/bin/id /tmp/.su
chmod u+s /tmp/.su
echo "[L7] SUID plantado en /tmp/.su — espera el barrido o fuerza: sudo arx guard --once --enforce"
