"""Arx Core — módulos de defensa.

recon    · reconocimiento inicial e inventario del host
baseline · aprendizaje de "lo normal" (SW·HW·red·usuarios) + integridad
sensors  · captación en vivo (osquery·auditd·Falco) → eventos normalizados
response · motor de respuesta por niveles (Tier 0/1 auto reversible · Tier 2 humano)
canaries · señuelos y honeytokens
sandbox  · ejecución de herramientas en contenedor hermano efímero, caps mínimas
           (patrón rawrun adaptado a uso defensivo — ver docs/arquitectura.md)
"""
