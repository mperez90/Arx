#!/usr/bin/env python3
"""Herramienta de ASL para el canal de vacunas: crear la clave offline y firmar. Solo stdlib.

La clave privada NO va en el agente ni en este repositorio. Úsala en una máquina aparte y guárdala
sin conexión: quien la tenga puede repartir reglas a todos los Arx del mundo.

    python3 scripts/vaccine_tool.py genkey asl-vaccines.key    # crea la clave (0600) y dice la pública
    python3 scripts/vaccine_tool.py pubkey asl-vaccines.key    # la pública, para ASL_PUBKEY en vaccines.py
    python3 scripts/vaccine_tool.py sign feed.json asl-vaccines.key -o feed.signed.json
    python3 scripts/vaccine_tool.py delegate <pública-auto> asl-vaccines.key --serial 7 \\
        --roster roster.json -o delegation.json

`delegate` autoriza la clave automática del servidor de consenso por pocos días (30 como mucho: cada
Arx rechaza más) y firma con ella la lista de votantes (revísala: es la que usan los Arx para
recontar). Para cortarla antes, `auto_revoked` en el paquete firmado con la maestra.

La firma es la de `arx.ed25519` (cegada y con pasos fijos). Aun así, la clave maestra se usa en una
máquina offline: nadie mide tiempos donde no hay red.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from arx import consensus, ed25519  # noqa: E402


public_key, sign = ed25519.public_key, ed25519.sign


def signed_feed(feed: dict, secret: bytes) -> dict:
    """El receptor verifica estos bytes exactos ANTES de interpretar nada de su contenido."""
    return consensus.seal(feed, secret)


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
    d = sub.add_parser("delegate")
    d.add_argument("auto_pubkey")
    d.add_argument("key")
    d.add_argument("--serial", type=int, required=True)
    d.add_argument("--days", type=int, default=30)
    d.add_argument("--roster", required=True, help="votantes exportados por el servidor (roster)")
    d.add_argument("-o", "--out", required=True)
    args = ap.parse_args()
    if args.cmd == "genkey":
        secret = secrets.token_bytes(32)
        fd = os.open(args.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # nunca pisa una clave
        with os.fdopen(fd, "w") as f:
            f.write(secret.hex() + "\n")
        print(f"Clave en {args.key}. Guárdala sin conexión.\nPública: {public_key(secret).hex()}")
    elif args.cmd == "pubkey":
        print(public_key(_read_key(args.key)).hex())
    elif args.cmd == "delegate":
        start = datetime.now(timezone.utc)
        with open(args.roster, encoding="utf-8") as f:
            voters = json.load(f)
        claim = {"kind": "auto-delegation", "auto_key": args.auto_pubkey, "serial": args.serial, "roster": voters,
                 "not_before": start.isoformat(timespec="seconds"),
                 "not_after": (start + timedelta(days=args.days)).isoformat(timespec="seconds")}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(consensus.seal(claim, _read_key(args.key)), f)
        print(f"Delegación: {args.out} (serial {args.serial}, hasta {claim['not_after']})")
    else:
        with open(args.feed, encoding="utf-8") as f:
            feed = json.load(f)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(signed_feed(feed, _read_key(args.key)), f)
        print(f"Firmado: {args.out} (serial {feed.get('serial')}, {len(feed.get('vaccines', []))} vacunas)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
