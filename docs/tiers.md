# Arx — matriz de tiers

El **Core** es defensa real y completa en lo esencial. **Pro** y **Business** añaden
inteligencia gestionada, detecciones avanzadas y operación de flota — lo que un usuario o
una empresa serios necesitan.

| Capacidad | Core (libre) | Pro (3 años · 3 activ.) | Business (2 años · por servidor) |
|---|---|---|---|
| Wizard de instalación (consola) | ✅ | ✅ | ✅ |
| Reconocimiento inicial + inventario | ✅ | ✅ | ✅ |
| Línea base de comportamiento (SW·HW·red·usuarios) | ✅ | ✅ | ✅ |
| Canarios / honeytokens | ✅ | ✅ | ✅ |
| Sensores (osquery·auditd·Falco) | ✅ | ✅ | ✅ |
| Respuesta Tier 0/1 (auto reversible) | ✅ | ✅ | ✅ |
| Respuesta Tier 2 (humano + palabra) | ✅ | ✅ | ✅ |
| Intel de amenazas | comunitaria (retraso) | **gestionada, tiempo real** | gestionada + privada |
| Detecciones avanzadas (playbooks purple) | básicas | ✅ | ✅ |
| Auto-pentest autorizado del propio host | — | ✅ | ✅ |
| Reportes de incidente / postura | básico | ✅ | compliance (SOC2/ISO) |
| Hosts | 1 | 1–pocos | **flota + consola central** |
| Correlación entre hosts | — | — | ✅ |
| Integración SIEM/SOAR · RBAC · auditoría | — | — | ✅ |
| Modelo local / air-gap | — | — | ✅ (a futuro) |
| Soporte | comunidad | estándar | **SLA + MDR opcional** |

Nota: **ninguna herramienta ofensiva de red** (MITM, envenenamiento, pivoting) se distribuye en
ningún tier. El "red" del producto = auto-prueba autorizada del propio host. Ver README §Alcance.
