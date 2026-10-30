"""Arx Core — módulos de defensa.

recon    · reconocimiento inicial e inventario del host
baseline · aprendizaje de "lo normal" (SW·HW·red·usuarios) + integridad
sensors  · captación en vivo (osquery·auditd·Falco) → eventos normalizados
response · motor de respuesta por niveles (Tier 0/1 auto reversible · Tier 2 humano)
canaries · señuelos y honeytokens
guard    · bucle operativo: capa rápida determinista + capa lenta (LLM) bajo demanda
service  · integración systemd (24/7)
fleet    · cliente de flota (Business)
"""
