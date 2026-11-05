"""Arx · totp — códigos de un solo uso (RFC 6238), solo con la stdlib.

Para autorizar desde un chat: la palabra de autorización nunca debe viajar por él ni quedar en su
historial, y quien robe la cuenta del chat no debe poder actuar sobre el servidor.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_S = 30
DIGITS = 6


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def _code(key: bytes, counter: int, digits: int = DIGITS) -> str:
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    value = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def counter_for(code: str, secret: str, now: float | None = None) -> int | None:
    """El contador con el que casa el código (±1 paso de reloj), o None. Quien lo llama recuerda el
    último usado: un código visto en el historial del chat no debe servir dos veces."""
    if not (isinstance(code, str) and code.isdigit() and len(code) == DIGITS):
        return None
    try:
        key = base64.b32decode(secret)
    except (ValueError, TypeError):
        return None
    current = int((time.time() if now is None else now) // STEP_S)
    for counter in (current, current - 1, current + 1):
        if hmac.compare_digest(_code(key, counter), code):
            return counter
    return None


def uri(secret: str, account: str) -> str:
    """Para añadirlo a una app de autenticación (Google Authenticator, Aegis, 1Password…)."""
    return f"otpauth://totp/Arx:{quote(account)}?secret={secret}&issuer=Arx&digits={DIGITS}&period={STEP_S}"
