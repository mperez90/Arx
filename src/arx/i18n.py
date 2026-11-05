"""Arx · idioma de la salida. El texto fuente está en inglés; el español vive en `locale_es`.

Orden: $ARX_LANG → `lang` en la configuración → locale del sistema → inglés. El servicio no hereda
el locale del operador, por eso `arx setup` deja el idioma escrito en la configuración.

La plantilla de `tr` es siempre un literal del código: formatear un texto que venga del host dejaría
a un atacante leer atributos de los argumentos (`{x.__class__}`). Los datos van en los argumentos.
"""
from __future__ import annotations

import os

SUPPORTED = ("en", "es")
_lang: str | None = None


def _from_config() -> str | None:
    from arx import config  # perezoso: config también traduce sus mensajes

    try:
        return config.load_config().get("lang")
    except (Exception, SystemExit):
        return None


def _resolve() -> str:
    env = os.environ.get("ARX_LANG") or _from_config() or os.environ.get("LC_ALL") \
        or os.environ.get("LC_MESSAGES") or os.environ.get("LANG") or ""
    return "es" if str(env).lower().startswith("es") else "en"


def lang() -> str:
    global _lang
    if _lang is None:
        _lang = "en"  # si resolver el idioma necesita un mensaje, ese sale en inglés: sin recursión
        _lang = _resolve()
    return _lang


def set_lang(value: str | None) -> None:
    """Fija el idioma de este proceso (None: volver a resolverlo). Lo usa `arx setup`."""
    global _lang
    _lang = value


def tr(text: str, **values) -> str:
    if lang() == "es":
        from arx.locale_es import ES

        text = ES.get(text, text)
    return text.format(**values) if values else text
