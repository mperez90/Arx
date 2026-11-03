#!/usr/bin/env bash
# Prepara la VM víctima con Arx defendiendo (snapshot "oro" DESPUÉS de esto).
set -euo pipefail

curl -fsSL https://raw.githubusercontent.com/mperez90/Arx/main/packaging/install.sh | sudo bash
# (si el release cambia de rama, ajusta la URL; install.sh verifica SHA256SUMS siempre)

sudo arx setup        # wizard: alertas Telegram opcionales en el lab
sudo arx recon
sudo arx learn
sleep 2
sudo arx learn
sudo arx learn --seal # también respalda los ficheros críticos en el vault
sudo arx canaries plant
sudo arx service install --enforce
sudo arx status
echo "── Apaga limpio (sudo poweroff) y toma el snapshot ORO ahora ──"
