# Arx — arquitectura

## 1. Dos capas

**Capa rápida (determinista).** Sensores + reglas en tiempo real, sin modelo en el hot
path: estado del sistema, syscalls/ficheros, comportamiento en kernel (eBPF), integridad.
Produce eventos normalizados.

**Capa lenta (razonamiento).** Un core de razonamiento open-source (MIT) trabaja **async,
fuera del hot path**: correlaciona eventos, decide, redacta el porqué en lenguaje natural,
propone respuesta. Nunca bloquea la detección.

Regla: si la capa rápida puede decidir sola y es reversible, actúa ya; el razonamiento
explica y refina después. Nunca es requisito para contener.

## 2. Respuesta por niveles

| Tier | Ejemplos | Autoridad |
|------|----------|-----------|
| **0** | aislar proceso, snapshot, throttle, tarpit | auto, siempre reversible |
| **1** | cortar conexión, bloquear puerto nuevo | auto alta-confianza, **auto-expira** |
| **2** | borrar, rotar credenciales durables | **humano + palabra** |

"Voluntad de acero" = Tier 0/1 implacables y sin fatiga. Lo irreversible es del humano.

## 3. Línea base de comportamiento (UEBA)

No solo red: **software** (procesos, binarios, servicios, cron, paquetes), **hardware**
(perfiles de uso y horarios), **red** (flujos, destinos, puertos), **usuarios** (accesos,
privilegios, horarios). Aprender > bloquear durante la ventana. Integridad de arranque
para no aprender a un intruso como "normal". Deriva controlada.

## 4. Ejecución de herramientas aislada (defensivo)

Las herramientas del propio agente (recon, verificación de exposición) **no** corren con
capacidades amplias en el proceso principal: se ejecutan en **contenedores hermanos
efímeros con capacidades mínimas**, acotadas al propio host/segmento de Arx, y se destruyen
al terminar. Menor superficie, aislamiento y auditabilidad.

**Línea dura — sin arsenal ofensivo.** Arx **no** empaqueta herramientas ofensivas de red
(MITM, envenenamiento de credenciales, pivoting hacia otros hosts) en **ningún** tier.
Razones: control de exportación / doble uso, responsabilidad legal y coherencia con el
posicionamiento defensivo. Un instalable con privilegios altos + arsenal ofensivo a escala
es una plataforma armable, no un guardián.

**El "red" que sí existe (Pro+):** auto-pentest **autorizado del propio host** — Arx prueba
sus propias defensas, con aprobación humana (Tier 2). Nunca contra terceros.

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
