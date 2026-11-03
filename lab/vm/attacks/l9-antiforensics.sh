#!/usr/bin/env bash
# L9 — anti-forense: leer los señuelos y truncar logs (dentro de la víctima).
# Esperado: lectura de canarios = ALTA inmediata (atime). El truncado de logs puede
# quedar como GAP honesto (el cursor detecta rotación; el silencio prolongado aún no).
set -e
echo "[L9] leyendo señuelos…"
arx canaries list 2>/dev/null | awk '{print $1}' | while read -r f; do
  [ -f "$f" ] && head -c 64 "$f" >/dev/null && echo "  leído: $f"
done
echo "[L9] truncando auth.log…"
: > /var/log/auth.log 2>/dev/null || echo "  (sin auth.log — apt install openssh-server)"
echo "[L9] fuerza barrido: sudo arx guard --once --enforce"
