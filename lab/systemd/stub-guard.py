#!/usr/bin/env python3
"""Arx guard con la respuesta del modelo simulada, para probar lo que hace Arx con ella bajo el
unit real y su endurecimiento. Sustituye solo la llamada al proveedor: nada más cambia."""
import json
import sys

sys.path.insert(0, "/usr/lib/arx/arx.pyz")

from arx.modules import guard  # noqa: E402


def _verdicts(batch):
    ids = [o["fp"] for f, o in batch if f.get("kind") == "login_users"]
    return ids, [{"id": i, "verdict": "threat", "confidence": 95, "reason": "simulated in the lab"} for i in ids]


def answer(batch, base, cfg):
    return "Simulated answer.\nVERDICTS: " + json.dumps(_verdicts(batch)[1])


def verdicts(batch, base, cfg):
    """El veredicto por su canal estructurado (B79), validado con el mismo `checked_verdicts` de producción: la línea
    VERDICTS del análisis se ignora a propósito, y sin esto el servicio no recibía ningún veredicto."""
    ids, vs = _verdicts(batch)
    return guard.checked_verdicts({"verdicts": vs}, set(ids))


guard._assess_with_engine = answer
guard._verdicts_with_engine = verdicts
sys.exit(guard.run(enforce=True))
