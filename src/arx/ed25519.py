"""Arx · ed25519 — verificación de firmas Ed25519 (RFC 8032), solo con la stdlib.

La biblioteca estándar de Python no verifica firmas asimétricas, y un HMAC no sirve para vacunas:
con la misma clave, cualquier receptor podría firmar. Aquí solo se VERIFICA: no hay ningún secreto
en juego, así que tiempo constante no aplica. La firma se hace fuera del agente, con la clave
offline (scripts/vaccine_tool.py). Probado contra los vectores de la RFC y contra OpenSSL.
"""
from __future__ import annotations

import hashlib

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)  # raíz cuadrada de -1


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % _P)


def add(a: tuple, b: tuple) -> tuple:
    p, q = (a[1] - a[0]) * (b[1] - b[0]) % _P, (a[1] + a[0]) * (b[1] + b[0]) % _P
    r, s = 2 * a[3] * b[3] * _D % _P, 2 * a[2] * b[2] % _P
    e, f, g, h = q - p, s - r, s + r, q + p
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def mul(scalar: int, point: tuple) -> tuple:
    out = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            out = add(out, point)
        point = add(point, point)
        scalar >>= 1
    return out


def compress(point: tuple) -> bytes:
    zinv = pow(point[2], _P - 2, _P)
    x, y = point[0] * zinv % _P, point[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(data: bytes) -> tuple | None:
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def hash_mod_q(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True solo si `signature` es la firma de `message` con la clave `public`."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _Q:  # s >= Q: firma maleable, se rechaza
        return False
    h = hash_mod_q(signature[:32] + public + message)
    left, right = mul(s, G), add(r, mul(h, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 \
        and (left[1] * right[2] - right[1] * left[2]) % _P == 0
