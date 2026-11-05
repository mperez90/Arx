# Arx — arquitectura

## 1. Dos capas

**Capa rápida (determinista).** Sensores + reglas en barridos periódicos (30 s por defecto),
sin modelo en el hot path: estado del sistema, integridad, pista de escaneo en el kernel
(nftables) y, si están instalados, auditd y Falco (eBPF). Produce eventos normalizados.

**Capa lenta (razonamiento).** El motor de Arx (cliente LLM propio, con las claves del
cliente) trabaja **fuera del hot path** y **solo cuando la capa rápida encuentra algo
nuevo**: recibe el expediente completo (hallazgos, respuesta aplicada, contexto del host,
historial reciente), correlaciona, redacta el porqué en lenguaje natural y propone el
siguiente paso. Agrupa lo nuevo en ventanas y respeta un presupuesto diario: un servidor
tranquilo no gasta tokens. La telemetría se le entrega marcada como dato no confiable
(defensa ante inyección de prompt). Nunca bloquea la detección.

Regla: si la capa rápida puede decidir sola y es reversible, actúa ya; el razonamiento
explica y refina después. Nunca es requisito para contener.

Tiene un único poder, y acotado: con `--enforce`, su veredicto sobre un acceso que la capa rápida
ya señaló puede cerrar esa cuenta (ver Tier 2). No elige a quién, y su respuesta se valida por código.

## 2. Respuesta por niveles

| Tier | Ejemplos | Autoridad |
|------|----------|-----------|
| **0** | registrar evidencia y alertar | automático, siempre |
| **1** | bloquear IP, puerto o canal de reverse shell; suspender un proceso sospechoso | automático con `--enforce`, **se deshace solo a los 60 min** |
| **2** | restaurar ficheros críticos, poner en cuarentena lo plantado, bloquear una cuenta y cerrar sus sesiones, terminar un proceso que reapareció, quitar un bit SUID | **humano + palabra** |

"Voluntad de acero" = Tier 0/1 implacables y sin fatiga. Lo irreversible es del humano, con una
excepción: si el modelo confirma como amenaza un acceso ya señalado, se cierra esa cuenta sin esperar
y se informa con todo el contexto. Nunca sobre root, cuentas de sistema o la última cuenta de
administración, ni sin una sesión viva comprobada, ni más de dos veces por hora. Una cuenta bloqueada
no se desbloquea sola: lo decide una persona con `arx unlock`.

Un binario nuevo en un directorio de sistema es señal de baja confianza y solo se registra
(Tier 0): suspenderlo congelaría todos sus procesos. Un canal de reverse shell se corta con
DROP en nftables, no destruyendo el socket: al expirar, el flujo se reanuda.

## 3. Línea base de comportamiento

**Software** (ejecutables por ruta real, servicios), **red** (puertos en escucha),
**usuarios** (sesiones) y **medidores** (carga, memoria, disco, conexiones). Aprender >
bloquear durante la ventana. Integridad de arranque para no aprender a un intruso como
"normal". Horarios y flujos de red todavía no se modelan.

## 4. Ejecución de herramientas aislada (defensivo) — *planificado*

Las herramientas del propio agente (recon, verificación de exposición) **no** corren con
capacidades amplias en el proceso principal: se ejecutan en **contenedores hermanos
efímeros con capacidades mínimas**, acotadas al propio host/segmento de Arx, y se destruyen
al terminar. Menor superficie, aislamiento y auditabilidad.

**Core es solo defensivo.** No incluye herramientas ofensivas de ningún tipo.

**Evaluación autorizada, solo de pago y solo sobre activos propios** (*planificada*): Pro
añade un auto-pentest curado del propio host; Business, una evaluación con herramientas de
Kali/Parrot sobre la flota enrolada del cliente. Con puertas duras siempre: alcance impuesto
por código, aprobación humana por ejercicio, dry-run primero, kill-switch y auditoría. Sin
C2 ni pivoting empaquetados, y su código no vive en este repositorio.

**Nunca contra terceros:** no hay hack-back en ningún tier, ni siquiera contra quien te
ataca (la IP atacante suele ser otra víctima).

## 5. Lado cliente vs. lado servidor

- **En el host del cliente (Core):** motor, wizard, recon, baseline, sensores, respuesta,
  canarios, chat de consola. El cliente pone sus **propias** claves de modelo → coste de
  inferencia cero, y su telemetría no sale de la máquina más allá del modelo que elija.
- **Del lado del servicio (tiers superiores):** inteligencia gestionada, licencias,
  y consola de flota.

## 6. Config y secretos en el host

Config y **hash** de la palabra de autorización: root-only, permisos estrictos e
inmutables tras el setup. La palabra nunca se guarda en claro. Redactor de secretos
siempre activo: ninguna clave ni credencial sale en logs, incidentes ni al modelo.
