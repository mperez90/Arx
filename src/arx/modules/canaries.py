"""Arx · canaries — señuelos / honeytokens.

Planta ficheros-cebo con nombres que un atacante querría abrir (`.aws_credentials`,
`id_rsa_backup`, …). Contenido inerte pero VEROSÍMIL y sin ninguna marca que delate que
es un señuelo; cada uno lleva un token único (registrado en el estado de Arx) para poder
rastrear una fuga si alguien lo usa fuera. Nadie legítimo los toca → cualquier acceso es
señal fuerte de intruso.

Detección, de mejor a peor:
  · auditd (regla -p rwa, clave arx_canary): lectura/escritura con el PROCESO que la hizo
    — lo emite `sensors.read_auditd_events`.
  · Sondeo por `stat` (portable, sin abrir el fichero para no contaminar la señal):
    borrado, recreado (inode), modificado (tamaño/mtime) y LEÍDO (atime avanza; con
    `relatime`, la primera lectura tras plantarlo siempre actualiza atime).
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from arx import config
from arx.modules import recon

DECOY_NAMES = [".aws_credentials", "id_rsa_backup", "db_dump.sql", ".env.prod", "wallet.dat"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _path():
    return config.state_dir() / "canaries.json"


def _load() -> dict:
    return config.read_json(_path())


def _save(d: dict) -> None:
    config.write_json(_path(), d)


def _decoy_content(name: str, token: str) -> str:
    """Contenido creíble según el tipo de cebo. El token es único por señuelo."""
    if name == ".aws_credentials":
        return ("[default]\n"
                f"aws_access_key_id = AKIA{token[:16].upper()}\n"
                f"aws_secret_access_key = {base64.b64encode(bytes.fromhex(token)).decode()[:40]}\n"
                "region = us-east-1\n")
    if name == "id_rsa_backup":
        body = base64.b64encode(bytes.fromhex(token) * 18).decode()
        lines = "\n".join(body[i:i + 70] for i in range(0, len(body), 70))
        return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{lines}\n-----END OPENSSH PRIVATE KEY-----\n"
    if name == "db_dump.sql":
        return ("-- MySQL dump 10.13\n"
                "CREATE TABLE `users` (`id` int, `email` varchar(255), `password_hash` varchar(255));\n"
                f"INSERT INTO `users` VALUES (1,'admin@internal','$2y$10${token[:53]}');\n")
    if name == ".env.prod":
        return (f"DATABASE_URL=postgres://app:{token[:24]}@db.internal:5432/app\n"
                f"SECRET_KEY={token}\nSTRIPE_SECRET=sk_live_{token[:24]}\n")
    return f"wallet_seed={token}\n"


def default_locations() -> list[str]:
    locs = [u["home"] for u in recon.collect_users().get("human_users", [])]
    locs.append("/root")
    return [l for l in locs if l and Path(l).is_dir()]


def _stat_record(p: Path) -> dict:
    st = p.stat()
    return {"inode": st.st_ino, "size": st.st_size, "mtime_ns": st.st_mtime_ns,
            "atime_ns": st.st_atime_ns}


def plant(locations: list[str]) -> list[dict]:
    st = _load()
    planted = st.get("canaries", [])
    known = {c["path"] for c in planted}
    for i, loc in enumerate(locations):
        d = Path(loc)
        if not d.is_dir():
            continue
        name = DECOY_NAMES[(len(planted) + i) % len(DECOY_NAMES)]
        p = d / name
        if str(p) in known or p.exists():
            continue
        token = secrets.token_hex(20)
        content = _decoy_content(name, token)
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(content)
            rec = _stat_record(p)
        except OSError:
            continue
        planted.append({"path": str(p), "token": token,
                        "sha256": hashlib.sha256(content.encode()).hexdigest(),
                        "planted_at": _now(), **rec})
        known.add(str(p))
    st["canaries"] = planted
    _save(st)
    from arx.modules import sensors

    sensors.ensure_audit_rules([c["path"] for c in planted])
    return planted


def _finding(sev: str, detail: str, why: str, path: str) -> dict:
    return {"sev": sev, "kind": "canary", "detail": detail, "why": why, "target": {"path": path}}


def check() -> list[dict]:
    findings: list[dict] = []
    st = _load()
    dirty = False
    for c in st.get("canaries", []):
        p = Path(c["path"])
        try:
            cur = _stat_record(p)
        except FileNotFoundError:
            findings.append(_finding("high", f"señuelo DESAPARECIDO: {c['path']}",
                                     "un honeytoken borrado indica manipulación o barrido de un intruso",
                                     c["path"]))
            continue
        except OSError:
            continue
        if "size" not in c:  # señuelo plantado por una versión antigua: solo hash de contenido
            try:
                if hashlib.sha256(p.read_bytes()).hexdigest() != c["sha256"]:
                    findings.append(_finding("high", f"señuelo MODIFICADO: {c['path']}",
                                             "nadie legítimo edita un honeytoken → acceso de atacante",
                                             c["path"]))
            except OSError:
                pass
            continue
        if cur["inode"] != c["inode"]:
            findings.append(_finding("med", f"señuelo RECREADO: {c['path']}",
                                     "el fichero-cebo fue reemplazado (inode distinto)", c["path"]))
        elif cur["size"] != c["size"] or cur["mtime_ns"] != c["mtime_ns"]:
            findings.append(_finding("high", f"señuelo MODIFICADO: {c['path']}",
                                     "nadie legítimo edita un honeytoken → acceso de atacante", c["path"]))
        elif cur["atime_ns"] > c["atime_ns"]:
            when = datetime.fromtimestamp(cur["atime_ns"] / 1e9, timezone.utc).strftime("%Y-%m-%d %H:%M")
            findings.append(_finding("high", f"señuelo LEÍDO: {c['path']} ({when} UTC)",
                                     "alguien abrió un honeytoken (posible búsqueda de credenciales). "
                                     "Ojo: un backup que lea el disco entero también lo dispara.",
                                     c["path"]))
            c["atime_ns"] = cur["atime_ns"]  # la próxima lectura será un hallazgo distinto
            dirty = True
    if dirty:
        _save(st)
    return findings


def run(action: str, locations: list[str] | None = None) -> int:
    if action == "plant":
        locs = locations or default_locations()
        if not locs:
            print("No hay ubicaciones válidas donde plantar. Usa: arx canaries plant --in <DIR>")
            return 1
        planted = plant(locs)
        print(f"✓ {len(planted)} señuelo(s) activo(s):")
        for c in planted:
            print("   ", c["path"])
        return 0
    if action == "list":
        cs = _load().get("canaries", [])
        print(f"▸ {len(cs)} señuelo(s):")
        for c in cs:
            print(f"   {c['path']}  (plantado {c.get('planted_at', '?')[:10]})")
        return 0
    if action == "check":
        f = check()
        if not f:
            print("✓ Todos los señuelos intactos.")
            return 0
        for x in f:
            print(f"  [{x['sev']}] {x['detail']}")
        return 0
    return 1
