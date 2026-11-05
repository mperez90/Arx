"""Arx · engine — motor de razonamiento LLM con fallback entre proveedores.

Intenta los proveedores en el orden configurado (por defecto OpenAI → Anthropic →
KIMI) hasta que uno responde. El cliente pone sus PROPIAS claves → coste de
inferencia cero para Arx.

Sin dependencias externas: habla el REST de cada proveedor con urllib (el Core no
arrastra SDKs que cambian). El transporte (`post`) es inyectable para poder testear
la lógica de fallback sin red.

Este motor es la capa LENTA: razona fuera del hot path de detección, y `guard` solo lo
despierta cuando la capa determinista encuentra algo NUEVO.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from arx import __version__, config
from arx.i18n import tr

# Endpoints compatibles con el esquema OpenAI (chat/completions).
OPENAI_LIKE = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "kimi": "https://api.moonshot.ai/v1/chat/completions",
}
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class ProviderError(Exception):
    """Ningún proveedor pudo atender la petición."""


def _http_post(url: str, headers: dict, payload: dict, timeout: int = 180) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={**headers, "Content-Type": "application/json", "User-Agent": f"arx/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (URL fija, no input externo)
        return json.loads(r.read().decode())


def _build(prov: str, key: str, model: str, system: str | None,
           messages: list[dict], max_tokens: int) -> tuple[str, dict, dict]:
    if prov == "anthropic":
        payload = {"model": model, "max_tokens": max_tokens, "messages": messages}
        if system:
            payload["system"] = system
        return ANTHROPIC_URL, {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION}, payload
    base = OPENAI_LIKE.get(prov)
    if not base:
        raise ProviderError(tr("unknown provider: {prov}", prov=prov))
    msgs = ([{"role": "system", "content": system}] if system else []) + messages
    payload = {"model": model, "messages": msgs}
    # Los modelos de razonamiento gastan tokens pensando: un tope bajo devuelve respuesta vacía.
    # OpenAI (serie gpt-5) usa max_completion_tokens; Kimi (compatible OpenAI) usa max_tokens.
    payload["max_completion_tokens" if prov == "openai" else "max_tokens"] = max_tokens
    return base, {"Authorization": f"Bearer {key}"}, payload


def _parse(prov: str, resp: dict) -> str:
    if prov == "anthropic":
        if resp.get("stop_reason") == "refusal":
            raise ProviderError(tr("the model declined the request"))
        # Los modelos actuales pueden abrir con un bloque `thinking`: tomar el primer `text`.
        text = next((b.get("text") for b in resp["content"] if b.get("type") == "text"), None)
    else:
        text = resp["choices"][0]["message"]["content"]
    if not text:
        raise ProviderError(tr("empty response"))
    return text


class Engine:
    def __init__(self, cfg: dict | None = None, post=_http_post, max_tokens: int = 16000):
        self.cfg = cfg if cfg is not None else config.load_config()
        self._post = post
        self.max_tokens = max_tokens

    def providers_in_order(self) -> list[str]:
        return self.cfg.get("fallback_order") or list(self.cfg.get("providers", {}))

    def ask(self, messages: list[dict], system: str | None = None) -> tuple[str, str]:
        """Devuelve (respuesta, proveedor_usado). Lanza ProviderError si todos fallan."""
        errors: list[str] = []
        for prov in self.providers_in_order():
            key = config.get_api_key(prov)
            model = self.cfg.get("providers", {}).get(prov)
            if not key or not model:
                errors.append(tr("{prov}: no key or model", prov=prov))
                continue
            try:
                url, headers, payload = _build(prov, key, model, system, messages, self.max_tokens)
                return _parse(prov, self._post(url, headers, payload)), prov
            except (urllib.error.URLError, KeyError, IndexError, ProviderError, TimeoutError, OSError) as e:
                errors.append(f"{prov}: {e}")
                continue
        raise ProviderError(tr("no provider responded: ") + "; ".join(errors))
