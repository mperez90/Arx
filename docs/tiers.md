# Arx — matriz de tiers

El **Core** es defensa real y gratuita, y es lo único disponible hoy. **Pro** y **Business**
están **planificados**: abren después de la fase de pruebas públicas de Core, y esta tabla
describe lo previsto, no lo que ya se puede comprar. Cada ✅ de pago debe existir y estar
probado antes de abrir su venta.

| Capacidad | Core (gratis) | Pro (1 dispositivo) | Business (por dispositivo) |
|---|---|---|---|
| Wizard de instalación (consola) | ✅ | ✅ | ✅ |
| Reconocimiento inicial + inventario | ✅ | ✅ | ✅ |
| Línea base (ejecutables·puertos·servicios·usuarios + medidores) | ✅ | ✅ | ✅ |
| Canarios / honeytokens | ✅ | ✅ | ✅ |
| Sensores (osquery·auditd·Falco, si están instalados) | ✅ | ✅ | ✅ |
| Respuesta Tier 0/1 (automática y reversible) | ✅ | ✅ | ✅ |
| Respuesta Tier 2 (humano + palabra) | ✅ | ✅ | ✅ |
| Bloqueo de cuentas: cierra sesiones y accesos, solo una persona lo levanta | ✅ | ✅ | ✅ |
| El modelo (tu clave) puede confirmar una amenaza y cerrar esa cuenta, con salvaguardas | ✅ | ✅ | ✅ |
| Gobierno desde Telegram, con código de un solo uso | ✅ | ✅ | ✅ |
| Propuestas (normalizar, endurecer SSH): Arx propone, tú apruebas | ✅ | + autónomo con rollback | + autónomo con rollback |
| Vacunas firmadas, validadas en cada host (el canal aún no está abierto) | ✅ | ✅ | ✅ |
| Análisis estático de ficheros (`arx scan`) | ✅ | ✅ | ✅ |
| Informe forense sellado (`arx forensics`) | ✅ | ✅ | ✅ |
| Intel de amenazas | comunitaria, por las vacunas (el canal aún no está abierto) | **gestionada, tiempo real** | gestionada + privada |
| Detecciones avanzadas por TTP | básicas | ✅ | ✅ |
| Auto-pentest del propio host | — | ✅ (curado) | ✅ |
| Evaluación autorizada de los activos propios (Kali/Parrot) | — | — | ✅ |
| Informes de postura | básico | ✅ | compliance (SOC2/ISO) |
| Consola central + correlación entre hosts | — | — | ✅ |
| Hosts que se defienden entre sí | — | — | ✅ |
| Integración SIEM/SOAR · RBAC · auditoría | — | — | ✅ |
| Soporte | comunidad | estándar | SLA (+MDR opcional, por contrato aparte) |

**Core es solo defensivo.** Los tiers de pago añaden evaluación autorizada de los activos
propios, con alcance impuesto por código y aprobación humana por ejercicio. Sin C2 ni
pivoting empaquetados, y nunca contra terceros: no hay hack-back en ningún tier. El código
de esa evaluación no vive en este repositorio.
