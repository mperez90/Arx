# Manual de Arx Core

Versión 0.0.9rc2 · [English version](manual.md) · `man arx` una vez instalado

Arx se usa desde la terminal. No tiene interfaz web, a propósito: un agente que defiende un servidor
no debería añadirle otra página de acceso. Este manual recorre cada comando en el orden en que te
los vas a encontrar y termina con una referencia a la que puedes volver.

## Contenido

1. [Antes de empezar](#1-antes-de-empezar)
2. [Instalación](#2-instalación)
3. [La terminal](#3-la-terminal)
4. [Primera puesta en marcha: setup, recon, learn, guard](#4-primera-puesta-en-marcha-setup-recon-learn-guard)
5. [Funcionamiento 24/7 con systemd](#5-funcionamiento-247-con-systemd)
6. [El día a día](#6-el-día-a-día)
7. [Cuando llega una alerta](#7-cuando-llega-una-alerta)
8. [Alertas y control desde el móvil](#8-alertas-y-control-desde-el-móvil)
9. [Cómo responde Arx](#9-cómo-responde-arx)
10. [Herramientas: señuelos, scan, forense, vacunas, propuestas, métricas](#10-herramientas)
11. [El programa de mejora](#11-el-programa-de-mejora)
12. [Licencias y ediciones](#12-licencias-y-ediciones)
13. [Actualizar y desinstalar](#13-actualizar-y-desinstalar)
14. [Ficheros y variables de entorno](#14-ficheros-y-variables-de-entorno)
15. [Problemas frecuentes](#15-problemas-frecuentes)
16. [Referencia de comandos](#16-referencia-de-comandos)

---

## 1. Antes de empezar

**Qué necesitas**

| | |
|---|---|
| Sistema | Debian o Ubuntu (probado en Ubuntu 22.04 y 24.04 y Debian 13). Otras distribuciones Linux pueden ejecutar `arx.pyz`, sin prueba de origen del software |
| Python | 3.10 o superior (solo la biblioteca estándar, nada de pip) |
| Privilegios | root. Arx bloquea IPs, congela procesos y restaura ficheros, y eso exige root. Sin root, los comandos trabajan sobre una copia privada en `~/.arx` y no protegen nada |
| systemd | para funcionar 24/7, confinar programas y avisar de los fallos del propio Arx |
| nftables | recomendado (se instala con el paquete salvo que omitas los recomendados). Los bloqueos y el corte de reverse shells lo usan |
| auditd | se instala automáticamente con el paquete. De él salen las alertas de ficheros de identidad, de señuelos y de lecturas denegadas |
| cgroup v2 | para confinar un programa sin red. Sin él, Arx lo suspende |

**Convenciones de este manual**

- Los comandos se muestran con `sudo`. Si ya eres root, quítalo.
- `<id>` es un valor que sustituyes: el id de un hallazgo, una cuenta, una ruta.
- Las salidas de ejemplo están en español; Arx también habla inglés (ver [3.2](#32-idioma)).

**Primero observa.** Arx arranca en modo observar: dice lo que habría hecho y no cambia nada fuera de
sus propios ficheros. Pasa a modo proteger (`--enforce`) cuando te fíes de lo que informa.

---

## 2. Instalación

### 2.1 Con el instalador (recomendado)

```bash
curl -fsSLO https://raw.githubusercontent.com/mperez90/Arx/f1-core-mvp/packaging/install.sh
less install.sh          # un instalador como root de una herramienta de seguridad: léelo antes
sudo sh install.sh
```

El instalador:

1. comprueba que corre como root en un sistema con `dpkg`;
2. descarga el `arx_all.deb` de la última release y su `SHA256SUMS`, y no instala nada si la suma
   no coincide;
3. instala el paquete y deja que `apt` traiga sus dependencias (`python3`, `auditd`, y `nftables`
   como recomendado);
4. se asegura de que `auditd` está en marcha, o te dice por qué no (dentro de un contenedor el núcleo
   no deja arrancarlo);
5. pregunta una sola vez si quieres unirte al [programa de mejora](#11-el-programa-de-mejora). La
   respuesta por defecto es no, y sin terminal no pregunta;
6. muestra los pasos siguientes.

Variables del instalador:

| Variable | Uso |
|---|---|
| `ARX_DEB_URL` | descargar el paquete de otra URL (su `SHA256SUMS` debe estar al lado) |
| `ARX_DEB_PATH` | instalar un `.deb` local (sin conexión o para pruebas). Se salta la descarga y la suma |

### 2.2 Con el paquete

```bash
sudo apt install ./arx_all.deb
```

`apt` resuelve las dependencias. Con `dpkg -i`, ejecuta después `sudo apt-get install -f`.

### 2.3 Sin paquete (otras distribuciones)

Descarga `arx.pyz` de [Releases](https://github.com/mperez90/Arx/releases) y ejecútalo:

```bash
sudo python3 arx.pyz --version
sudo python3 arx.pyz setup
```

Todos los comandos de este manual funcionan igual con `python3 arx.pyz` en lugar de `arx`. Sin dpkg
nada cuenta como probado, así que con `--enforce` todo programa nuevo queda contenido.

### 2.4 Verificar la release

Cada release lleva procedencia de compilación firmada:

```bash
gh attestation verify arx.pyz -R mperez90/Arx
gh attestation verify arx_all.deb -R mperez90/Arx
```

### 2.5 Qué se instala

| Ruta | Qué |
|---|---|
| `/usr/bin/arx` | el comando |
| `/usr/lib/arx/arx.pyz` | el programa (una aplicación zip de Python) |
| `/usr/share/man/man1/arx.1.gz` | `man arx` |
| `/etc/arx/` | configuración y secretos, los crea `arx setup` (solo root) |
| `/var/lib/arx/` | estado: línea base, incidentes, bóveda, cuarentena, informes (solo root) |

Instalar no cambia nada más hasta que ejecutas `arx setup` y sellas una línea base.

---

## 3. La terminal

### 3.1 Colores

Cuando Arx escribe en una terminal colorea tres cosas, para que leas su salida de un vistazo:

| Color | Qué | Ejemplo |
|---|---|---|
| **azul** | nombres de usuario y de cuenta | `cuenta 'deploy' bloqueada` |
| **amarillo** | comandos que puedes ejecutar | `Acepta uno con:  arx accept <id>` |
| **verde** | rutas | `abrió /etc/shadow` |

Los colores existen solo en la salida de Arx y solo en una terminal. Arx no toca la configuración de
tu shell ni tu prompt. Cuando la salida va a una tubería, a un fichero o al journal, y en los mensajes
de Telegram y el webhook, el texto va limpio.

| Ajuste | Efecto |
|---|---|
| `NO_COLOR=1` | sin colores ([no-color.org](https://no-color.org)) |
| `ARX_COLOR=never` | sin colores |
| `ARX_COLOR=always` | colores incluso por una tubería (por ejemplo `ARX_COLOR=always arx status \| less -R`) |
| `TERM=dumb` | sin colores |

Un comando se colorea solo hasta donde llega de verdad: en «ejecuta `arx learn` varias veces», solo
`arx learn` va en amarillo. Un usuario se colorea cuando el contexto no deja dudas («cuenta 'x'»,
«usuario: x», «uid=0(root)»), o detrás de «como» o «por» solo si la cuenta existe en este host.

### 3.2 Idioma

Arx habla español e inglés. El idioma se elige en este orden:

1. `ARX_LANG` (`es` o `en`);
2. el idioma elegido en `arx setup` (queda en la configuración, así el servicio también lo usa);
3. el locale del sistema (`LC_ALL`, `LC_MESSAGES`, `LANG`);
4. inglés.

```bash
ARX_LANG=es arx status
```

Los comandos de Telegram valen en los dos idiomas sea cual sea el de la salida (`/estado` o
`/status`).

### 3.3 La consola de Arx: `arx shell`

`arx shell` abre una consola interactiva de Arx:

```
$ sudo arx shell
Consola de Arx 0.0.9rc2 · «help» lista los comandos · «exit» o Ctrl+D para salir
root@web01:/etc arx› status
…
root@web01:/etc arx› accept
…
root@web01:/etc arx› exit
```

- En el prompt, `usuario@host` va en azul, el directorio actual en verde y lo que escribes en
  amarillo. La salida de los comandos usa los mismos colores que en todas partes. Al salir, tu
  terminal queda exactamente como estaba. (Con la libedit de macOS el prompt queda sin color; los
  servidores Linux usan GNU readline.)
- Escribe los comandos de Arx sin el `arx` delante (`status`, `accept <id>`). Con él también vale.
- **Tab** completa comandos, acciones (`license a` → `activate`), opciones (`metrics --` →
  `--days`, `--json`) y rutas (después de `cd`, de `scan`, o de cualquier cosa que empiece por `/`,
  `~` o `.`).
- El historial se guarda en `~/.arx_history` (modo 0600, 1000 líneas). Las flechas arriba y abajo
  lo recorren.
- Un error, un `--help` o un fallo en un comando nunca cierran la consola. Ctrl+C detiene el comando
  en curso (por ejemplo `guard`) y vuelve al prompt.

Órdenes propias de la consola:

| Orden | Qué |
|---|---|
| `help` o `?` | lista los comandos de Arx con una línea de descripción |
| `cd <dir>` | cambia de directorio (útil antes de `scan` con rutas relativas) |
| `pwd` | muestra el directorio actual |
| `history` | muestra el historial |
| `clear` | limpia la pantalla |
| `exit`, `quit`, Ctrl+D | salir |

Sin terminal, la consola lee los comandos de su entrada, uno por línea, sin prompt y sin colores.
Las líneas que empiezan por `#` se ignoran:

```bash
printf 'status\nmetrics --json\n' | sudo arx shell
```

### 3.4 Ayuda

```bash
arx --help              # todos los comandos
arx <comando> --help    # las opciones de un comando
man arx                 # la página de referencia
arx --version
```

---

## 4. Primera puesta en marcha: setup, recon, learn, guard

El ciclo de vida de Arx son cuatro pasos:

```
setup  →  recon  →  learn  →  guard
```

### 4.1 `arx setup`: configuración

```bash
sudo arx setup
```

El asistente pregunta primero el idioma (`en`/`es`) y después recorre ocho pasos. Enter conserva el
valor que aparece entre corchetes:

1. **Proveedores del modelo** (opcional). Claves de API de OpenAI, Anthropic y Kimi, y el modelo de
   cada uno. Las claves se escriben sin eco y se guardan en `/etc/arx/secrets.json` (0600). El orden
   es el orden de respaldo. Sin ningún proveedor Arx defiende exactamente igual; las decisiones que
   usarían el modelo te esperan a ti.
2. **Palabra de autorización** (obligatoria). Protege toda acción irreversible (Tier 2). Se pide dos
   veces y solo se guarda su hash scrypt. Arx nunca la muestra y nunca viaja por un chat. Si la
   pierdes, vuelve a ejecutar `arx setup`.
3. **Alcance.** Qué defiende Arx, y qué no debe tocar nunca: puertos, rutas, procesos o cuentas,
   separados por comas. Tu puerto SSH siempre está protegido.
4. **Aprendizaje y motor.** La ventana de la línea base en días (7 por defecto) y el máximo de
   consultas diarias al modelo (48). El modelo solo se consulta cuando aparece algo nuevo.
5. **Licencia** (`core`, `pro`, `business`). Core es gratuita y no necesita clave. Ver
   [12](#12-licencias-y-ediciones).
6. **Alertas** (opcional). El token de un bot de Telegram, tu chat id, si quieres gobernar Arx desde
   ese chat (con una app de autenticación), una URL de webhook, y desde qué severidad avisar
   (`crit`, `high`, `med`). Ver [8](#8-alertas-y-control-desde-el-móvil).
7. **Respuesta automática.** Ante un escaneo de puertos: `block` corta la IP y `tarpit` la frena
   (mejor si la IP puede ser compartida). Con un modelo configurado: si puede bloquear una cuenta
   que confirme como amenaza (ver [9.2](#92-la-única-excepción)).
8. **Programa de mejora** (opcional, por defecto no). Ver [11](#11-el-programa-de-mejora).

Cuando la entrada no es una terminal y se acaba, las preguntas que quedan toman su valor por defecto.
Así puedes automatizarlo.

Ver la configuración actual, con los secretos redactados:

```bash
sudo arx setup --show
```

Las claves del modelo también pueden venir del entorno en vez del fichero: `ARX_OPENAI_API_KEY`,
`ARX_ANTHROPIC_API_KEY`, `ARX_KIMI_API_KEY`.

### 4.2 `arx recon`: el mapa del servidor

```bash
sudo arx recon
```

Una mirada profunda, de solo lectura, al host: hardware, sistema operativo, paquetes, servicios y
puertos en escucha, usuarios, sudo, binarios SUID, cron, contenedores, red y alcance. Muestra la
superficie de ataque y un plan de defensa a medida, y guarda el inventario en JSON en
`/var/lib/arx/`.

| Opción | Efecto |
|---|---|
| `--json <ruta>` | guardar el inventario en otro sitio |
| `--no-save` | solo mostrar, sin escribir nada |

### 4.3 `arx learn`: aprender lo normal

```bash
sudo arx learn            # una instantánea
sudo arx learn --status   # lo aprendido hasta ahora
sudo arx learn --seal     # cerrar la línea base
```

Cada ejecución toma una instantánea del comportamiento del host y la funde en la línea base:

- **conjuntos**: ejecutables por su ruta real, puertos en escucha, servicios, usuarios conectados;
- **medidores**: carga, memoria, disco, conexiones (mínimo, máximo, media).

Repítelo a distintas horas durante unos días (la ventana de setup, 7 días por defecto) para que la
línea base vea las copias de seguridad, los cron y las horas punta. Para varias instantáneas en una
sola ejecución:

```bash
sudo arx learn --samples 12 --interval 300    # 12 instantáneas, cada 5 minutos
```

**Integridad de arranque.** La primera instantánea toma la huella de los ficheros críticos
(`authorized_keys`, `sudoers`, `passwd`, cron, units de systemd, `ld.so.preload`, el conjunto de
binarios SUID). Si cambian mientras Arx aprende, te lo dice, para no aprender a un intruso como
normal.

**Sellar** (`--seal`) termina el aprendizaje. Además:

- copia los ficheros críticos a la bóveda de Arx, para poder restaurarlos después;
- carga la tabla `inet arx` de nftables con un rastreador pasivo de escaneos y conjuntos de bloqueo
  vacíos;
- registra los binarios SUID presentes.

Una línea base sellada es contra lo que compara `arx guard`. Puedes volver a aprender y sellar
cuando quieras; `arx accept` añade cambios sueltos sin reaprender.

### 4.4 `arx guard`: en guardia

```bash
sudo arx guard               # modo observar, cada 30 segundos, hasta Ctrl+C
sudo arx guard --enforce     # modo proteger: acciones Tier 1 automáticas
```

| Opción | Efecto |
|---|---|
| `--enforce` | aplica acciones Tier 1 automáticas y reversibles. Sin ella, Arx solo informa |
| `--interval <s>` | segundos entre barridos (30 por defecto) |
| `--once` | un barrido y termina (para cron o pruebas) |
| `--verbose` | muestra todos los hallazgos en cada barrido, no solo los nuevos |
| `--chat` | habla con el modelo configurado desde la consola (`salir` para terminar). No puede actuar |

Al arrancar muestra su tier, los sensores activos, el modo y los canales de alerta. Después:

- cada barrido compara el host con la línea base sellada y ejecuta los sensores;
- como root, los procesos se vigilan en tiempo real desde el núcleo (cada `exec`), y los ficheros
  sensibles con fanotify;
- los hallazgos nuevos se muestran con lo que hizo Arx. Las acciones Tier 2 esperan tu palabra;
- con un modelo configurado, los hallazgos nuevos se explican en lenguaje llano.

`arx guard` en una terminal sirve para probar Arx. Para dejarlo funcionando, usa systemd.

---

## 5. Funcionamiento 24/7 con systemd

```bash
sudo arx service install              # modo observar
sudo arx service install --enforce    # modo proteger
sudo arx service status
sudo arx service uninstall
```

`install` escribe y arranca:

| Unit | Qué |
|---|---|
| `arx.service` | el guardián (`arx guard`), endurecido, se reinicia si falla |
| `arx-firewall.service` | repone la contención de Arx en el núcleo al principio del arranque (`arx service restore`) |
| `arx-down.service` | informa del estado real de reinicio de Arx cuando falla |
| `arx-revive.timer` | cada 15 minutos, vuelve a arrancar Arx si quedó caído tras un fallo |
| `arx-maintenance.slice` | aquí corren las comprobaciones de apt y dpkg, fuera de la memoria del guardián |

Sin systemd o sin root, `install` no finge: escribe el unit en el directorio de estado y muestra los
comandos exactos para instalarlo.

Para cambiar entre observar y proteger, vuelve a instalar con o sin `--enforce`, o usa `/modo` desde
Telegram.

Comandos útiles:

```bash
systemctl status arx
journalctl -u arx -f                  # la salida del guardián en directo
journalctl -u arx --since today
```

Si alguien detiene Arx, o edita su unit o sus ficheros, te avisa por tus canales de alerta.

Las demás acciones de `service` (`restore`, `stopped`, `down`, `refresh-maintenance`) las ejecutan
systemd y el paquete. No hace falta lanzarlas a mano.

---

## 6. El día a día

### 6.1 `arx status`

```bash
sudo arx status
sudo arx status --json     # lo mismo, para scripts
```

```
▸ Arx — estado
  configurado    sí
  proveedores    anthropic
  palabra auth   configurada
  baseline       sellada (14 muestras)
  licencia       core  (sin licencia (Core))
  servicio       active
  canarios       5 activos, 0 disparados
  bloqueos T1    1 activos
  modo           proteger (--enforce)
  procesos       netlink · identidad de exec: completa
  capturas       1520 guardadas · 0 descartadas · 0 desbordamiento(s)
  ficheros sensibles completa
  alertas        telegram
  vacunas        0 aplicadas
  mejora         no participa (arx telemetry)
  observación    2 servicios aprendiendo · 9 vigilados
  hallazgos      12 conocidos  ·  aceptar cambios legítimos: arx accept
  Tier 2 pend.   0
  incidentes recientes:
    …
```

| Línea | Significado |
|---|---|
| `configurado`, `proveedores`, `palabra auth` | si se ejecutó setup, qué proveedores del modelo, si existe la palabra |
| `baseline` | aprendiendo o sellada, y el número de instantáneas |
| `licencia` | tier efectivo y por qué |
| `servicio` | estado de `arx.service` en systemd |
| `canarios` | señuelos plantados y disparados |
| `bloqueos T1` | bloqueos automáticos en vigor. `⚠ FRENO DE SEGURIDAD activo` significa que Arx ha dejado de actuar solo por ahora (ver [9.3](#93-salvaguardas)) |
| `modo` | observar, proteger (`--enforce`), o «aún no ha corrido» |
| `procesos`, `capturas` | el vigilante de procesos del núcleo y la captura de procesos efímeros. `descartadas` o `desbordamiento` por encima de 0 indican eventos perdidos |
| `ficheros sensibles` | la vigilancia con fanotify de shadow, claves y credenciales: completa, parcial, degradada o no disponible |
| `alertas` | canales configurados |
| `mejora` | si este servidor participa en el programa de mejora |
| `observación` | servicios cuyo comportamiento se está aprendiendo, y servicios ya vigilados |
| `hallazgos` | hallazgos conocidos; `arx accept` lista los que puedes aceptar |
| `Tier 2 pend.` | acciones que esperan tu palabra (`arx authorize`) |
| `cuentas bloq.` | cuentas que Arx bloqueó (`arx unlock`) |
| `incidentes recientes` | los cinco últimos |

### 6.2 `arx accept`: «esto es normal»

```bash
sudo arx accept                # hallazgos que puedes aceptar
sudo arx accept <id>           # aceptar uno
```

Aceptar añade el cambio a la línea base, deja de señalarlo y levanta en el acto lo que lo contenía
(un programa confinado recupera la red, un puerto bloqueado se reabre). Es lo que ejecutas después de
instalar algo a propósito.

Para un programa que arrancó un servicio:

| Opción | Acepta |
|---|---|
| (ninguna) | ese programa exacto para ese servicio |
| `--dir` | todo su directorio para ese servicio |
| `--children` | ese programa y lo que arranque |

Un paquete actualizado que «no es de fiar» se acepta solo para esa versión exacta.

### 6.3 `arx authorize`: acciones Tier 2

```bash
sudo arx authorize             # acciones pendientes, con lo que hará cada una
sudo arx authorize <id>        # pide tu palabra de autorización y actúa
```

Las acciones Tier 2 son las que no se deshacen solas: restaurar un fichero crítico desde la bóveda,
poner en cuarentena un fichero plantado, bloquear una cuenta y cerrar sus sesiones, terminar un
proceso que volvió, quitar un bit SUID. Arx las propone; solo tú, con tu palabra, las ejecutas. Una
palabra equivocada no cambia nada.

### 6.4 `arx unblock`: levantar un bloqueo antes de tiempo

```bash
sudo arx unblock               # bloqueos temporales en vigor y cuándo vencen
sudo arx unblock <ip|id>       # levantar uno ahora (pide tu palabra)
```

Los bloqueos Tier 1 se levantan solos a los 60 minutos. Usa esto para un falso positivo que no
quieres esperar. Para que no vuelva, `arx accept <id>`.

### 6.5 `arx unlock`: cuentas bloqueadas

```bash
sudo arx unlock                # cuentas que Arx bloqueó, desde cuándo y por qué
sudo arx unlock <cuenta>       # desbloquear (pide tu palabra)
```

Una cuenta bloqueada tiene cerrado el acceso por contraseña y por clave SSH. Nunca se desbloquea
sola. Desbloquear restaura su estado anterior. Las sesiones cerradas no se pueden reabrir. Si el
acceso era legítimo, ejecuta después `arx accept` para que no vuelva a señalarse.

### 6.6 `arx restore`: la cuarentena

```bash
sudo arx restore               # ficheros en cuarentena, origen, fecha y hash
sudo arx restore <id>          # devolver uno a su sitio (pide tu palabra)
```

Los ficheros en cuarentena se guardan como evidencia (0600, solo root) en `/var/lib/arx/vault/`.

---

## 7. Cuando llega una alerta

Cada alerta nombra el id de un hallazgo. La guía completa es [docs/runbook.md](runbook.md). En
resumen:

1. **Primero guarda la evidencia:** `sudo arx forensics`.
2. **Mira qué hizo Arx:** `sudo arx status`.
3. **Decide:**

| La alerta dice | Arx ya | Decides tú |
|---|---|---|
| Un programa, puerto o servicio nuevo que no puede demostrar su origen | Lo confinó o bloqueó el puerto; sigue funcionando | Es tuyo: `sudo arx accept <id>`. No lo es: detenlo y quítalo |
| Una actualización «no es de fiar» | Confinó el servicio; sigue sirviendo | Legítima: `sudo arx accept <id>`. Si no, vuelve a la versión anterior del paquete |
| Un servicio «intentó llegar a … fuera de su comportamiento habitual» | Cortó esa conexión | Un destino nuevo legítimo: `sudo arx accept <id>` |
| Un servicio «arrancó …, que nunca había ejecutado» | Aisló ese proceso sin red | Era esperado: `sudo arx accept <id>` |
| sshd «antes de autenticar a nadie, ejecutó …» | Congeló y aisló ese proceso | Trátalo como un compromiso. Solo si configuraste tú ese comando: `sudo arx accept <id>` |
| Un servidor web o una base de datos «arrancó una shell» | Congeló ese proceso | Busca una webshell y después `sudo arx accept <id>` |
| Acceso desde un origen desconocido | Cerró esa cuenta (con tu palabra o la del modelo) | `sudo arx unlock <cuenta>` solo cuando sepas que era legítimo |
| Cron plantado, bit SUID, segunda cuenta root, fichero crítico cambiado | Avisó y pidió tu palabra | `sudo arx authorize <id>`, o `sudo arx accept <id>` si fuiste tú |
| Un intento denegado de abrir un fichero sensible | Avisó (desde auditd), con usuario, programa y proceso | Averigua por qué lo intentó ese servicio |
| Se leyó o cambió un señuelo | Alerta alta, con el programa si auditd lo vio | Trátalo como un intruso |
| Arx se detuvo, o cambiaron su unit o sus ficheros | Te avisó por tus canales | Si no fuiste tú, asume que alguien es root: trabaja desde otra máquina |

---

## 8. Alertas y control desde el móvil

### 8.1 Canales

Se configuran en el paso 6 de `arx setup`:

- **Telegram**: crea un bot solo para Arx con @BotFather (`/newbot`), pega su token y envíale
  cualquier mensaje: Arx detecta tu chat id. Solo ese chat puede hablar con Arx.
- **Webhook**: Arx envía por POST el JSON `{"source": "arx", "host": "<host>", "text": "<alerta>"}`
  a la URL (Slack, Discord, n8n…).

Las alertas salen desde la severidad que elegiste (`high` por defecto). Todo mensaje sale con los
secretos redactados. Arx solo hace conexiones salientes y no abre ningún puerto.

```bash
sudo arx notify test           # envía un mensaje de prueba por cada canal
```

`ok` significa que el canal aceptó el mensaje, no que alguien lo leyera. Una vez al día Arx también
envía un resumen de lo que espera tu decisión y de cuánto ruido hizo. Para quitar ese resumen, pon
`"daily_report": false` dentro de `"notify"` en `/etc/arx/config.json`.

### 8.2 Comandos de Telegram

| Comando | Qué |
|---|---|
| `/estado` (`/status`) | estado |
| `/hallazgos` (`/findings`) | hallazgos recientes |
| `/pendientes` (`/pending`) | acciones Tier 2 en espera |
| `/informe` (`/report`) | los últimos 7 días: alertas, falsos positivos, acciones automáticas, contención, cuarentena |
| `/callar <horas>` (`/mute`) | silenciar las alertas no críticas |
| `/autorizar <id> <código>` (`/authorize`) | autorizar una acción Tier 2 |
| `/desbloquear <cuenta> <código>` (`/unlock`) | desbloquear una cuenta |
| `/aceptar <id> <código>` (`/accept`) | aceptar un hallazgo |
| `/modo observar\|proteger <código>` (`/mode observe\|protect`) | cambiar de modo |
| `/ayuda` (`/help`) | la lista |

`<código>` es el código de un solo uso de 6 cifras de tu app de autenticación (Google Authenticator,
Aegis, 1Password…). La clave se muestra una vez en `arx setup` cuando activas el control desde el
chat. Tu palabra de autorización nunca viaja por el chat. Cualquier otro texto va al modelo, si lo
hay; el modelo no puede actuar.

---

## 9. Cómo responde Arx

### 9.1 Niveles

| Nivel | Qué pasa | Autoridad |
|---|---|---|
| **0** | Registrar la evidencia y avisar | Automático, siempre |
| **1** | Bloquear una IP, un puerto o el canal de una reverse shell; suspender un proceso sospechoso; confinar un programa de origen no probado | Automático con `--enforce`. Cada acción se deshace sola a los 60 minutos, salvo el confinamiento, que te espera |
| **2** | Restaurar ficheros críticos, poner en cuarentena lo plantado, bloquear una cuenta y cerrar sus sesiones, terminar un proceso que volvió, quitar un bit SUID | Tú, con tu palabra de autorización |

El software nuevo se juzga por pruebas, no por su ruta. Un programa de un paquete de un repositorio
firmado, íntegro, solo se registra. Uno que no puede demostrarlo se confina: sigue funcionando, sin
red. Solo las señales de daño lo suspenden: una ruta temporal u oculta, un acierto del análisis
estático, haberlo lanzado un servidor web, o venir de un acceso desconocido.

### 9.2 La única excepción

Con un modelo configurado y `--enforce`, si el modelo confirma como amenaza, o como sospecha seria
(70 % o más), un acceso que las reglas ya habían señalado, Arx cierra el acceso de esa cuenta sin
esperar y te avisa con todo el contexto. El modelo no puede elegir a quién: su veredicto solo cuenta
sobre un acceso ya señalado en el mismo lote, y el código valida el resto. Nunca se aplica a root, a
cuentas del sistema ni a la última cuenta que puede administrar el host, sin una sesión viva que Arx
pueda verificar, ni más de dos veces por hora. Se desactiva en `arx setup`.

### 9.3 Salvaguardas

- Arx nunca actúa sobre tu puerto SSH, el PID 1, sí mismo, las IPs del propio host, ni una sesión SSH
  autenticada que haya visto persistir.
- Tras 5 acciones automáticas en una hora deja de actuar y solo observa (el freno de seguridad). Los
  hallazgos críticos conservan una pequeña reserva.
- No se puede bloquear una cuenta si eso dejaría a nadie capaz de administrar el servidor.
- Una amenaza que vuelve tras vencer su bloqueo se te consulta a ti; no se rebloquea en bucle.
- Perder el contacto con nuestros servidores nunca desarma Arx: la licencia falla en abierto, como
  mucho a Core.

---

## 10. Herramientas

### 10.1 `arx canaries`: señuelos

```bash
sudo arx canaries plant                          # en la home de cada usuario y en /root
sudo arx canaries plant --in /srv/data --in /opt/app
sudo arx canaries list
sudo arx canaries check                          # comprobarlos ahora
```

Los señuelos son ficheros que un intruso querría abrir (`.aws_credentials`, `id_rsa_backup`,
`db_dump.sql`, `.env.prod`, `wallet.dat`), creíbles e inertes, cada uno con un token único. Nadie
legítimo los abre, así que cualquier acceso es una señal fuerte. Con auditd la alerta nombra el
programa que lo abrió; sin él, las lecturas se notan por la hora de acceso. Los señuelos son también
la forma en que Arx nota un ransomware.

### 10.2 `arx scan`: ¿es malicioso este fichero?

```bash
sudo arx scan /tmp/sospechoso.sh
```

Solo análisis estático: el fichero nunca se ejecuta. Arx mira su tipo, hash, tamaño, entropía,
cadenas y sus propias reglas, y responde `clean`, `suspicious` o `malicious` con las reglas que
casaron. El código de salida 0 significa limpio. «Limpio» solo quiere decir que ninguna regla casó.
En ficheros grandes lee el principio y el final, y lo dice.

### 10.3 `arx forensics`: informe sellado

```bash
sudo arx forensics                               # informe completo, guardado y sellado
sudo arx forensics --since 2026-11-20T00:00:00   # solo incidentes desde entonces (UTC)
sudo arx forensics --verify /var/lib/arx/forensics/forensic-<id>.json
sudo arx forensics --indicators                  # solo IPs públicas, hashes y tipos de ataque
```

El informe reúne la cronología de incidentes, la contención activa, las acciones pendientes, la
evidencia en cuarentena y el contexto del host, y se guarda en `/var/lib/arx/forensics/`. Va sellado
con una cadena de hashes y un HMAC con una clave local del host, así que se detectan los cambios
posteriores. `--indicators` no contiene nada de tu host y se puede compartir. El sello no cubre los
cambios hechos al registro antes del informe, y root en el mismo host puede volver a firmar uno.

### 10.4 `arx vaccines`

```bash
sudo arx vaccines              # aplicadas y rechazadas
sudo arx vaccines update       # comprobar ahora
sudo arx vaccines remove <id>
```

Actualizaciones firmadas con lo que aprendieron otros hosts Arx. Cada una se valida en tu host antes
de aplicarse, y en Core una vacuna son datos, nunca código. El canal aún no está abierto.

### 10.5 `arx proposals`

```bash
sudo arx proposals                 # lo que Arx sugiere
sudo arx proposals apply <id>      # pide tu palabra
sudo arx proposals revert <id>     # deshacer una aplicada
```

Dos clases: normalizar lo que lleva días viéndose sin que nadie diga nada (nunca de severidad alta),
y cerrar lo que un ataque demostró abierto (hoy, la configuración de SSH). Nada se aplica solo, y un
cambio de SSH nunca se ofrece si te podría dejar fuera.

### 10.6 `arx metrics`: cuánto ruido hace

```bash
sudo arx metrics
sudo arx metrics --days 30
sudo arx metrics --json        # solo cifras, sin rutas, nombres ni IPs: se puede compartir
```

El objetivo es menos de 0,1 falsos positivos altos por host y día. Una alerta cuenta como falso
positivo solo cuando la marcas tú (`arx accept`, `arx unlock`). Lo que nadie revisó se muestra como
«sin revisar».

---

## 11. El programa de mejora

Arx puede enviar un informe de uso anónimo cada pocos días, **solo si dices que sí**. Por defecto no
se envía nada.

```bash
sudo arx telemetry             # si participas y cuándo salió el último informe
sudo arx telemetry show        # exactamente lo que se enviaría, en JSON
sudo arx telemetry enable      # unirte
sudo arx telemetry disable     # salir y borrar el id de instalación
sudo arx telemetry send        # enviar uno ahora (solo si participas)
```

Se pregunta una sola vez en el instalador (solo en una terminal) y en el paso 8 de `arx setup`. Un
informe lleva cifras y valores fijos: versión de Arx, distribución, núcleo, arquitectura, modo, salud
de los vigilantes y contadores de ruido. Nunca nombres de host, IPs, rutas, usuarios, comandos, textos
de hallazgos ni secretos. El id de instalación es aleatorio y se borra al salir. `ARX_TELEMETRY=off`
o `DO_NOT_TRACK=1` lo apagan diga lo que diga la configuración.

La lista completa de campos, y adónde van los informes: [docs/telemetry.md](telemetry.md) (en
inglés).

---

## 12. Licencias y ediciones

Core es gratuita y no necesita clave. Pro y Business abren después de la fase de pruebas de Core.

```bash
sudo arx license status                # tier, clave (redactada), caducidad, última comprobación
sudo arx license activate <CLAVE>      # activar una clave Pro/Business en este servidor
sudo arx license deactivate            # liberar la activación (antes de reinstalar el servidor)
```

La licencia se vuelve a comprobar cada 24 horas. Sin conexión, Arx mantiene su tier un tiempo y,
como mucho, vuelve a Core: la defensa nunca se detiene.

**Flota (Business):**

```bash
sudo arx fleet enroll --console <URL> --token <TOKEN>
sudo arx fleet status
sudo arx fleet sync            # latido e incidentes ahora
```

---

## 13. Actualizar y desinstalar

### 13.1 Actualizar

```bash
sudo apt install ./arx_all.deb     # o vuelve a ejecutar install.sh
```

El paquete nuevo detiene Arx antes de sustituir sus ficheros y lo vuelve a arrancar después, solo si
estaba en marcha. Si el arranque falla, el paquete queda a medio configurar; corrige la causa y
ejecuta `sudo dpkg --configure -a`. Si la parada falla, la actualización se aborta y la versión
anterior sigue funcionando.

### 13.2 Desinstalar

Antes de desinstalar:

```bash
sudo arx canaries list       # anota los señuelos que plantaste y bórralos
sudo arx unlock              # desbloquea las cuentas que dejaste bloqueadas
sudo arx proposals           # deshaz los cambios aplicados: arx proposals revert <id>
```

Después:

```bash
sudo apt remove arx          # quita el programa y conserva /etc/arx y /var/lib/arx
sudo apt purge arx           # borra también la configuración y el estado (evidencia y bóveda)
```

Desinstalar devuelve la red a todo lo que Arx confinó y se lleva sus units, drop-ins y su tabla de
nftables. Sus reglas de auditd desaparecen al reiniciar. auditd sigue instalado; quítalo con
`sudo apt autoremove` si nada más lo necesita.

---

## 14. Ficheros y variables de entorno

### 14.1 Ficheros

| Ruta | Qué |
|---|---|
| `/etc/arx/config.json` | configuración (0600) |
| `/etc/arx/secrets.json` | claves del modelo, token del bot, claves locales (0600) |
| `/var/lib/arx/baseline.json` | la línea base |
| `/var/lib/arx/incidents.jsonl` | todos los incidentes, un JSON por línea |
| `/var/lib/arx/findings.json` | hallazgos conocidos y sus ids |
| `/var/lib/arx/watch.json` | estado de los vigilantes, tal como lo muestra `arx status` |
| `/var/lib/arx/forensics/` | informes sellados |
| `/var/lib/arx/vault/` | copias de los ficheros críticos y evidencia en cuarentena |
| `/var/lib/arx/telemetry.json` | estado del programa de mejora (solo si participas) |
| `/var/lib/arx/audit-tail.json` | por dónde va Arx leyendo el log de auditd |
| `~/.arx_history` | historial de `arx shell` |
| `/etc/systemd/system/arx*.service`, `arx-revive.timer`, `arx-maintenance.slice` | los units |

Sin root, la configuración y el estado van a `~/.arx/` y `~/.arx/state/`.

### 14.2 Variables de entorno

| Variable | Efecto |
|---|---|
| `ARX_LANG` | idioma de la salida (`es`, `en`) |
| `ARX_COLOR` | `always` o `never` (por defecto: colores solo en una terminal) |
| `NO_COLOR` | sin colores |
| `ARX_TELEMETRY` | `off` apaga el programa de mejora |
| `DO_NOT_TRACK` | `1` apaga el programa de mejora |
| `ARX_OPENAI_API_KEY`, `ARX_ANTHROPIC_API_KEY`, `ARX_KIMI_API_KEY` | claves del modelo sin escribirlas a disco |
| `ARX_CONFIG_DIR`, `ARX_STATE_DIR` | otros directorios de configuración y de estado |
| `ARX_DEB_URL`, `ARX_DEB_PATH` | solo el instalador (ver [2.1](#21-con-el-instalador-recomendado)) |

---

## 15. Problemas frecuentes

**`arx status` dice «configurado no», pero ejecuté setup.** Lo ejecutaste sin `sudo`. Sin root la
configuración va a `~/.arx`. Vuelve a ejecutar `sudo arx setup`.

**El servicio no arranca.** `journalctl -u arx -n 50` dice por qué. «No hay línea base sellada»
significa ejecutar antes `sudo arx learn` y `sudo arx learn --seal`.

**No llegan alertas.** `sudo arx notify test`. Si Telegram dice `ok` pero no llega nada, revisa el
chat id en `sudo arx setup --show`. Por debajo de la severidad que elegiste, los hallazgos no se
envían.

**«auditd is installed but not running».** En un contenedor el núcleo no deja arrancarlo. En una
máquina: `systemctl status auditd`. Sin él quedan apagadas las alertas de ficheros de identidad,
señuelos y lecturas denegadas; todo lo demás funciona.

**`ficheros sensibles parcial` o `degradada` en `arx status`.** No se pudieron vigilar algunos
sistemas de ficheros, o el núcleo no ofrece eventos de permiso de fanotify (algunos núcleos de
contenedor). Arx lo dice en vez de presumir una cobertura que no tiene.

**Mi propia aplicación en `/opt` se quedó sin red.** No puede demostrar su origen, así que
`--enforce` la confinó. Sigue funcionando. `sudo arx accept <id>` le devuelve la red.

**Algo está bloqueado y no quiero esperar 60 minutos.** `sudo arx unblock <ip|id>`, y después
`sudo arx accept <id>` para que no se vuelva a bloquear.

**`⚠ FRENO DE SEGURIDAD activo`.** Cinco acciones automáticas en una hora. Por ahora Arx solo avisa.
Revisa `sudo arx status` y los incidentes; se rearma solo.

**No veo colores.** La salida no es una terminal, o están puestos `NO_COLOR` o `ARX_COLOR=never`, o
`TERM=dumb`. Fuérzalos con `ARX_COLOR=always`.

**Los colores se ven raros con mi tema.** Arx usa el azul, el amarillo y el verde de tu terminal, así
que el tono exacto lo decide tu tema. Quítalos con `NO_COLOR=1`.

**Solo `ufw`, sin nftables.** Entonces los bloqueos no cortan las conexiones ya abiertas, y cortar
una reverse shell necesita nftables: `sudo apt install nftables`.

**Arx dentro de un contenedor.** Ejecútalo en el host. Dentro de un contenedor que comparte el árbol
de cgroups del host, la vigilancia de comportamiento no funciona. Los contenedores LXC funcionan como
una máquina.

**Perdí mi palabra de autorización.** Vuelve a ejecutar `sudo arx setup` y pon una nueva.

---

## 16. Referencia de comandos

| Comando | Opciones | Qué |
|---|---|---|
| `arx setup` | `--show` | asistente de configuración; `--show` la muestra con los secretos redactados |
| `arx recon` | `--json <ruta>`, `--no-save` | el mapa del servidor |
| `arx learn` | `--samples <n>`, `--interval <s>`, `--seal`, `--status` | aprender la línea base |
| `arx guard` | `--enforce`, `--interval <s>`, `--once`, `--verbose`, `--chat` | vigilar, detectar, responder |
| `arx service` | `install [--enforce] [--exec <ruta>]`, `uninstall`, `status` | funcionar 24/7 con systemd |
| `arx status` | `--json` | cómo está todo |
| `arx accept` | `[<id>] [--dir \| --children]` | aceptar un cambio legítimo |
| `arx authorize` | `[<id>]` | aprobar una acción Tier 2 (palabra) |
| `arx unblock` | `[<ip\|id>]` | levantar un bloqueo antes de tiempo (palabra) |
| `arx unlock` | `[<cuenta>]` | desbloquear una cuenta (palabra) |
| `arx restore` | `[<id>]` | devolver un fichero de la cuarentena (palabra) |
| `arx canaries` | `plant [--in <dir>]…`, `list`, `check` | señuelos |
| `arx scan` | `<ruta>` | análisis estático, nunca ejecuta el fichero |
| `arx forensics` | `--since <iso>`, `--verify <ruta>`, `--indicators` | informe sellado |
| `arx vaccines` | `list`, `update`, `remove <id>` | vacunas firmadas |
| `arx proposals` | `list`, `apply <id>`, `revert <id>` | lo que Arx sugiere (palabra) |
| `arx metrics` | `--days <n>`, `--json` | ruido en este host |
| `arx notify` | `test` | probar los canales de alerta |
| `arx telemetry` | `status`, `show`, `enable`, `disable`, `send` | programa de mejora |
| `arx license` | `activate <CLAVE>`, `status`, `deactivate` | licencia |
| `arx fleet` | `enroll --console <URL> --token <TOKEN>`, `status`, `sync` | consola de flota (Business) |
| `arx shell` | | consola interactiva |

**Códigos de salida.** 0 cuando el comando hizo lo pedido; 1 cuando no pudo, o la respuesta es
negativa (una palabra equivocada, un fichero que no está limpio, nada enviado); 2 ante un error de
uso.
