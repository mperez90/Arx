"""Arx · engine — motor de razonamiento LLM con fallback entre proveedores.

Intenta los proveedores en el orden configurado (por defecto OpenAI → Anthropic →
KIMI) hasta que uno responde. El cliente pone sus PROPIAS claves → coste de
inferencia cero para Arx.

Sin dependencias externas: habla el REST de cada proveedor con urllib (el Core no
arrastra SDKs que cambian). El transporte (`post`) es inyectable para poder testear
la lógica de fallback sin red.

Este motor es la capa LENTA: razona fuera del hot path de detección, y `guard` solo lo
despierta cuando la capa determinista encuentra algo NUEVO.

Dos formas de preguntar: `ask` (texto libre, para la persona) y `ask_json` (un objeto JSON para la máquina,
por la salida estructurada nativa de cada proveedor y, si falla, una segunda llamada que pide solo el JSON).
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from arx import __version__, config, redact
from arx.i18n import tr

# Endpoints compatibles con el esquema OpenAI (chat/completions).
OPENAI_LIKE = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "kimi": "https://api.moonshot.ai/v1/chat/completions",
}
# "local": cualquier servidor compatible con OpenAI en tu red (Ollama, LM Studio, llama.cpp). Tu telemetría
# no sale del sitio. La URL es de la configuración; por defecto, la de Ollama.
LOCAL_DEFAULT_URL = "http://127.0.0.1:11434/v1/chat/completions"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# Salida estructurada (ask_json)
JSON_MIN_TOKENS = 4000       # un modelo que razona gasta tokens pensando: con un tope bajo devuelve contenido vacío
NATIVE_RETRY_S = 3600        # cuánto se deja de probar el formato nativo de un proveedor que lo rechazó
_NATIVE_REJECTED: dict[str, float] = {}  # proveedor → monotonic hasta el que no se prueba su formato nativo
_REJECTING_STATUS = (400, 404, 415, 422)  # «no entiendo este parámetro»: no es un fallo del proveedor


class ProviderError(Exception):
    """Ningún proveedor pudo atender la petición."""


class ModelDeclined(ProviderError):
    """El modelo se negó a contestar: repetir la pregunta con otro formato no lo cambia."""


def _http_post(url: str, headers: dict, payload: dict, timeout: int = 180) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={**headers, "Content-Type": "application/json", "User-Agent": f"arx/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (URL fija, no input externo)
        return json.loads(r.read().decode())


def _local_url(cfg: dict) -> str:
    url = str(cfg.get("local_url") or LOCAL_DEFAULT_URL)
    if not url.startswith(("http://", "https://")):
        raise ProviderError(tr("local_url must be http(s)"))
    return url


def _build(prov: str, key: str, model: str, system: str | None,
           messages: list[dict], max_tokens: int, cfg: dict | None = None) -> tuple[str, dict, dict]:
    if prov == "anthropic":
        payload = {"model": model, "max_tokens": max_tokens, "messages": messages}
        if system:
            payload["system"] = system
        return ANTHROPIC_URL, {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION}, payload
    base = _local_url(cfg or {}) if prov == "local" else OPENAI_LIKE.get(prov)
    if not base:
        raise ProviderError(tr("unknown provider: {prov}", prov=prov))
    msgs = ([{"role": "system", "content": system}] if system else []) + messages
    payload = {"model": model, "messages": msgs}
    # Los modelos de razonamiento gastan tokens pensando: un tope bajo devuelve respuesta vacía.
    # OpenAI (serie gpt-5) usa max_completion_tokens; Kimi (compatible OpenAI) usa max_tokens.
    payload["max_completion_tokens" if prov == "openai" else "max_tokens"] = max_tokens
    return base, ({"Authorization": f"Bearer {key}"} if key else {}), payload


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


# ── salida estructurada ──────────────────────────────────────────────────────
_THINK_RE = re.compile(r"\A\s*<think>.*?</think>", re.S)
_FENCE_RE = re.compile(r"\A```(?:json)?[ \t]*\n(.*)\n```\Z", re.S)


def _json_object(text: str | None) -> dict:
    """El objeto JSON que es TODA la respuesta (si acaso, dentro de un único bloque de código o tras un bloque
    `<think>`). Un JSON enterrado en prosa no se extrae: el modelo lee datos que escribió un atacante."""
    if not text or not text.strip():
        raise ProviderError(tr("empty response"))
    body = _THINK_RE.sub("", text, count=1).strip()
    fenced = _FENCE_RE.match(body)
    if fenced:
        body = fenced.group(1).strip()
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError):
        raise ProviderError(tr("the answer is not a JSON object")) from None
    if not isinstance(obj, dict):
        raise ProviderError(tr("the answer is not a JSON object"))
    return obj


def _schema_hint(schema: dict) -> str:
    return json.dumps(schema, ensure_ascii=False, separators=(",", ":"))


def _with_instruction(messages: list[dict], text: str) -> list[dict]:
    """La instrucción va en el último mensaje del usuario: dos seguidos no los admiten todos los proveedores."""
    out = [dict(m) for m in messages]
    for m in reversed(out):
        if m.get("role") == "user":
            m["content"] = f"{m['content']}\n\n{text}"
            return out
    return out + [{"role": "user", "content": text}]


def _build_json(prov: str, key: str, model: str, system: str | None, messages: list[dict], max_tokens: int,
                cfg: dict, schema: dict, name: str) -> tuple[str, dict, dict]:
    """La petición con el formato estructurado NATIVO de cada proveedor."""
    if prov == "anthropic":  # una herramienta obligada: el resultado llega como `input`, ya decodificado
        url, headers, payload = _build(prov, key, model, system, messages, max_tokens, cfg)
        payload["tools"] = [{"name": name, "description": "Report the result.", "input_schema": schema}]
        payload["tool_choice"] = {"type": "tool", "name": name}
        return url, headers, payload
    if prov == "openai":
        url, headers, payload = _build(prov, key, model, system, messages, max_tokens, cfg)
        payload["response_format"] = {"type": "json_schema",
                                      "json_schema": {"name": name, "strict": True, "schema": schema}}
        return url, headers, payload
    if prov == "local":  # Ollama, LM Studio, llama.cpp: el esquema, sin `strict` (no todos lo entienden)
        url, headers, payload = _build(prov, key, model, system, messages, max_tokens, cfg)
        payload["response_format"] = {"type": "json_schema", "json_schema": {"name": name, "schema": schema}}
        return url, headers, payload
    # Kimi (y lo compatible que no hace esquemas): modo JSON, que exige que el texto pida JSON
    hint = "Reply with a single JSON object that follows this JSON schema, and nothing else: " + _schema_hint(schema)
    url, headers, payload = _build(prov, key, model, system, _with_instruction(messages, hint), max_tokens, cfg)
    payload["response_format"] = {"type": "json_object"}
    return url, headers, payload


def _parse_json(prov: str, resp: dict, name: str) -> dict:
    if prov == "anthropic":
        if resp.get("stop_reason") == "refusal":
            raise ModelDeclined(tr("the model declined the request"))
        for block in resp["content"]:
            if block.get("type") == "tool_use" and block.get("name") == name:
                if not isinstance(block.get("input"), dict):
                    raise ProviderError(tr("the answer is not a JSON object"))
                return block["input"]
        raise ProviderError(tr("empty response"))
    choice = resp["choices"][0]
    message = choice["message"]
    if message.get("refusal"):
        raise ModelDeclined(tr("the model declined the request"))
    if choice.get("finish_reason") == "length":  # cortado por el tope de tokens: un JSON a medias no se decodifica
        raise ProviderError(tr("the answer was cut off"))
    return _json_object(message.get("content"))


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
            key = config.get_api_key(prov) or ("" if prov == "local" else None)  # un servidor local puede no pedir clave
            model = self.cfg.get("providers", {}).get(prov)
            if key is None or not model:
                errors.append(tr("{prov}: no key or model", prov=prov))
                continue
            try:
                url, headers, payload = _build(prov, key, model, system, messages, self.max_tokens, self.cfg)
                return _parse(prov, self._post(url, headers, payload)), prov
            except (urllib.error.URLError, KeyError, IndexError, ProviderError, TimeoutError, OSError) as e:
                errors.append(f"{prov}: {redact.scrub(str(e))}")  # una URL con credenciales no sale en el error
                continue
        raise ProviderError(tr("no provider responded: ") + "; ".join(errors))

    def ask_json(self, messages: list[dict], system: str | None, schema: dict, name: str = "result",
                 max_tokens: int | None = None) -> tuple[dict, str, str]:
        """Pide un objeto JSON que siga `schema`. Devuelve (objeto, proveedor, vía) con vía «native» o «fallback».

        Primero la salida estructurada nativa del proveedor (esquema JSON en OpenAI y locales, modo JSON en Kimi,
        una herramienta obligada en Anthropic). Si la rechaza o no devuelve un objeto, una segunda llamada corta que
        pide SOLO el JSON, con margen de tokens para los modelos que razonan. Si un proveedor falla, el siguiente.
        El objeto sale sin validar: quien lo usa lo valida con tolerancia cero. Lanza ProviderError si ninguno
        devuelve un objeto JSON; nunca se inventa uno."""
        tokens = max(max_tokens or self.max_tokens, JSON_MIN_TOKENS)
        errors: list[str] = []
        for prov in self.providers_in_order():
            key = config.get_api_key(prov) or ("" if prov == "local" else None)
            model = self.cfg.get("providers", {}).get(prov)
            if key is None or not model:
                errors.append(tr("{prov}: no key or model", prov=prov))
                continue
            try:
                obj, how = self._json_from(prov, key, model, system, messages, schema, name, tokens)
                return obj, prov, how
            except (urllib.error.URLError, KeyError, IndexError, TypeError, ProviderError, TimeoutError,
                    OSError) as e:
                errors.append(f"{prov}: {redact.scrub(str(e))}")
        raise ProviderError(tr("no provider responded: ") + "; ".join(errors))

    def _json_from(self, prov: str, key: str, model: str, system: str | None, messages: list[dict], schema: dict,
                   name: str, tokens: int) -> tuple[dict, str]:
        rejected = False
        if time.monotonic() >= _NATIVE_REJECTED.get(prov, 0.0):
            try:
                url, headers, payload = _build_json(prov, key, model, system, messages, tokens, self.cfg, schema, name)
                return _parse_json(prov, self._post(url, headers, payload), name), "native"
            except ModelDeclined:
                raise  # otro formato no cambia una negativa
            except urllib.error.HTTPError as e:
                if e.code not in _REJECTING_STATUS:
                    raise  # clave, límite de uso o caída: un fallo del proveedor, no del formato
                rejected = True
            except ProviderError:  # vacío, cortado o sin JSON: la segunda llamada puede salir mejor
                pass
        plain = _with_instruction(
            messages, "Reply with ONLY a JSON object that follows this JSON schema: " + _schema_hint(schema)
            + ". No prose, no explanation, no extra text.")
        url, headers, payload = _build(prov, key, model, system, plain, tokens, self.cfg)
        obj = _json_object(_parse(prov, self._post(url, headers, payload)))
        if rejected:  # la segunda llamada sí funcionó: el formato nativo era el problema
            _NATIVE_REJECTED[prov] = time.monotonic() + NATIVE_RETRY_S
        return obj, "fallback"
