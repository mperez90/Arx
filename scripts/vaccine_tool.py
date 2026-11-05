#!/usr/bin/env python3
"""Herramienta de ASL para el canal de vacunas: crear la clave offline y firmar. Solo stdlib.

La clave privada NO va en el agente ni en este repositorio. Úsala en una máquina aparte y guárdala
sin conexión: quien la tenga puede repartir reglas a todos los Arx del mundo.

    python3 scripts/vaccine_tool.py genkey asl-vaccines.key    # crea la clave (0600) y dice la pública
    python3 scripts/vaccine_tool.py pubkey asl-vaccines.key    # la pública, para ASL_PUBKEY en vaccines.py
    python3 scripts/vaccine_tool.py sign feed.json asl-vaccines.key -o feed.signed.json

El firmado no es de tiempo constante: es Python puro, para una máquina offline y sin atacante
midiendo tiempos. Por eso esto no vive en el agente, que solo verifica.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from arx import ed25519  # noqa: E402


def _expand(secret: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    return ed25519.compress(ed25519.mul(_expand(secret)[0], ed25519.G))


def sign(secret: bytes, message: bytes) -> bytes:
    a, prefix = _expand(secret)
    pub = public_key(secret)
    r = ed25519.hash_mod_q(prefix + message)
    big_r = ed25519.compress(ed25519.mul(r, ed25519.G))
    h = ed25519.hash_mod_q(big_r + pub + message)
    return big_r + ((r + h * a) % ed25519._Q).to_bytes(32, "little")


def signed_feed(feed: dict, secret: bytes) -> dict:
    """El receptor verifica estos bytes exactos ANTES de interpretar nada de su contenido."""
    payload = json.dumps(feed, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return {"payload": base64.b64encode(payload).decode(), "sig": sign(secret, payload).hex()}


def _read_key(path: str) -> bytes:
    return bytes.fromhex(open(path, encoding="ascii").read().strip())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("genkey").add_argument("key")
    sub.add_parser("pubkey").add_argument("key")
    s = sub.add_parser("sign")
    s.add_argument("feed")
    s.add_argument("key")
    s.add_argument("-o", "--out", required=True)
    args = ap.parse_args()
    if args.cmd == "genkey":
        secret = secrets.token_bytes(32)
        fd = os.open(args.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # nunca pisa una clave
        with os.fdopen(fd, "w") as f:
            f.write(secret.hex() + "\n")
        print(f"Clave en {args.key}. Guárdala sin conexión.\nPública: {public_key(secret).hex()}")
    elif args.cmd == "pubkey":
        print(public_key(_read_key(args.key)).hex())
    else:
        with open(args.feed, encoding="utf-8") as f:
            feed = json.load(f)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(signed_feed(feed, _read_key(args.key)), f)
        print(f"Firmado: {args.out} (serial {feed.get('serial')}, {len(feed.get('vaccines', []))} vacunas)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
