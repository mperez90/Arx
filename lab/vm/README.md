# VM de niveles 7–10 — "modo real"

El mini-lab Docker cubre L3–L9 de forma rápida, pero los niveles altos necesitan un
sistema completo: systemd de verdad, auditd, persistencia real y **permiso para destruir**.
Esta VM es desechable por diseño.

## Topología

```
┌─────────────────┐   red host-only   ┌──────────────────┐
│  VÍCTIMA         │ ◄──────────────► │  ATACANTE         │
│  Ubuntu 22.04    │  192.168.64.10   │  Kali Linux       │
│  + Arx --enforce │                  │  (kali-rolling)   │
└─────────────────┘                   └──────────────────┘
   snapshot "oro" ──► restaurar entre niveles
```

Lo que se puede sin VM ya está en `lab/systemd-lab.sh` y `lab/level10.sh`. Esta VM añade kernel
propio, auditd, Falco y un reinicio de verdad.

## Montaje (Apple Silicon — UTM)

1. **UTM** (gratis, App Store o brew). Nueva VM → Linux → ISO `ubuntu-22.04-live-server-arm64`.
   2 CPU / 4 GB RAM / 25 GB disco alcanzan.
2. Red: **Host-Only** (sin NAT saliente durante L10; para instalar paquetes, cambiar a
   NAT temporalmente y volver).
3. Instala Ubuntu, luego dentro de la VM:
   ```bash
   bash lab/vm/setup-victim.sh      # instala Arx del release, learn+seal, canarios, servicio
   ```
4. Apaga limpio y toma el **snapshot "oro"** (UTM → botón derecho → Clone o
   `qemu-img snapshot`). Todo nivel destructivo empieza desde oro.
5. Atacante: otra VM con Kali ARM64 en la misma red host-only.

## Niveles

| Nivel | Script (se ejecuta DESDE el atacante o dentro según indique) | Qué debe pasar |
|---|---|---|
| 7 | `attacks/l7-suid.sh` (dentro, vía SSH ganada) | crit por integridad SUID en ≤ 1 h (o inmediato con `--once`) |
| 8 | `attacks/l8-persist.sh` (dentro) | crit → Tier 2 → autorización → restauración desde vault + evidencia en cuarentena |
| 9 | `attacks/l9-antiforensics.sh` (dentro) | lectura de canarios detectada; truncado de logs registrado como gap si no hay hallazgo |
| 10 | `attacks/l10-destroy.sh` (dentro — DESTRUYE la VM) | el freno de seguridad salta (≤5 acciones/h), alertas críticas masivas, Arx no hace nada irreversible; la VM puede morir |

## Disciplina de evidencia

Cada nivel deja: salida del atacante, `incidents.jsonl`, `arx status`, y notas en
`lab/vm/scoreboard.md`. Lo que falle se convierte en bug nuevo en
`DevelopDocs/registro-bugs.md` con su test de regresión.
