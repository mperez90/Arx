#!/usr/bin/env python3
"""Arx guard con la respuesta del modelo simulada, para probar lo que hace Arx con ella bajo el
unit real y su endurecimiento. Sustituye solo la llamada al proveedor: nada más cambia."""
import json
import sys

sys.path.insert(0, "/usr/lib/arx/arx.pyz")

from arx.modules import guard  # noqa: E402


def answer(batch, base, cfg):
    ids = [o["fp"] for f, o in batch if f.get("kind") == "login_users"]
    return "Simulated answer.\nVERDICTS: " + json.dumps(
        [{"id": i, "verdict": "threat", "confidence": 95, "reason": "simulated in the lab"} for i in ids])


guard._assess_with_engine = answer
sys.exit(guard.run(enforce=True))
