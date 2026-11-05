"""Arx · redact — redactor de secretos.

Limpia secretos ANTES de que salgan a logs, incidentes o a un prompt del LLM. Cubre
las API keys del usuario, la license key y el activation_id. Estrategia: reemplazo por
coincidencia EXACTA de los secretos conocidos (cero falsos positivos — no toca hashes
SHA de la baseline) + unos pocos patrones de prefijo de llave por si aparece uno que no
está en la config.
"""
from __future__ import annotations

import re

from arx import config
from arx.i18n import tr

REDACTED = tr("«redacted»")

# Prefijos de llave habituales, como red de seguridad ante secretos no registrados.
_PREFIX_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"polar_[A-Za-z0-9_\-]{12,}"),
]


def known_secrets() -> list[str]:
    """Valores exactos a redactar: secretos de config + llave/activation_id de licencia."""
    vals: list[str] = []
    for v in config.load_secrets().values():
        if isinstance(v, str) and len(v) >= 6:
            vals.append(v)
    try:
        from arx import license as lic  # import perezoso: evita ciclo en el arranque

        st = lic.load()
        for k in ("key", "activation_id"):
            v = st.get(k)
            if isinstance(v, str) and len(v) >= 6:
                vals.append(v)
    except Exception:
        pass
    # los más largos primero: evita redacciones parciales solapadas
    return sorted(set(vals), key=len, reverse=True)


def scrub(text: str) -> str:
    if not text:
        return text
    for sec in known_secrets():
        text = text.replace(sec, REDACTED)
    for pat in _PREFIX_PATTERNS:
        text = pat.sub(REDACTED, text)
    return text


def printable(text) -> str:
    """Datos del host (rutas, usuarios, salidas de sensores) → texto seguro de mostrar.

    Quien controla un nombre de fichero controla estos bytes: un salto de línea inyectaría
    líneas falsas en la salida, un ESC manejaría el terminal y un byte no UTF-8 tumbaría a
    Arx al codificarlo. Se escapan los no imprimibles; el texto normal queda intacto.
    """
    text = str(text)
    if text.isprintable():
        return text
    return "".join(c if c.isprintable()
                   else c.encode("unicode_escape", "backslashreplace").decode("ascii")
                   for c in text)

