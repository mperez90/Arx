#!/usr/bin/env bash
# L8 — persistencia: cron + systemd + authorized_keys (dentro de la víctima).
# Esperado: crit de integridad → Tier 2 pendiente → `sudo arx authorize` restaura
# desde el vault y cuarentena la versión hostil como evidencia.
set -e
echo '* * * * * root /bin/echo persistencia' > /etc/cron.d/arx-l8
printf '[Service]\nExecStart=/bin/true\n' > /etc/systemd/system/arx-l8.service
echo 'ssh-ed25519 AAAAC3NzaCllDI1NTE5AAAAILabKeyDePruebaNoValida lab@l8' >> /root/.ssh/authorized_keys 2>/dev/null || true
echo "[L8] persistencia plantada (cron + unit + authorized_keys)"
echo "     verifica: sudo arx guard --once --enforce  →  sudo arx authorize"
