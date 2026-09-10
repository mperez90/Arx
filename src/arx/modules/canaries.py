"""Arx · canaries — señuelos / honeytokens.

Planta ficheros-cebo con nombres que un atacante querría abrir (`.aws_credentials`,
`id_rsa_backup`, …). Contenido inerte pero verosímil, con un marcador único. Nadie
legítimo los toca → cualquier modificación/borrado es señal fuerte de intruso.

MVP: verificación por sondeo (sha256 + inode), portable a cualquier SO. En Linux el
objetivo de producción es inotify en tiempo real (lo consume `guard`); el sondeo es el
respaldo. `check()` devuelve hallazgos en el mismo formato que el resto de detección.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from arx import config
from arx.modules import recon

DECOY_NAMES = [".aws_credentials", "id_rsa_backup", "wallet.dat", "db_dump.sql", ".env.prod"]
MARKER = "ARX-CANARY-DO-NOT-EDIT"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _path():
    return config.state_dir() / "canaries.json"


def _load() -> dict:
    try:
        return json.loads(_path().read_text())
    except (OSError, ValueError):
        return {}


def _save(d: dict) -> None:
    _path().write_text(json.dumps(d, indent=2, ensure_ascii=False))
    try:
        _path().chmod(0o600)
    except OSError:
        pass


def _decoy_content(token: str) -> str:
    return (
        f"# {MARKER} {token}\n"
        "# honeytoken de Arx — cualquier acceso o edición queda registrado\n"
        f"aws_access_key_id=AKIA{token[:16].upper()}\n"
        f"aws_secret_access_key={token}\n"
    )


def default_locations() -> list[str]:
    locs = [u["home"] for u in recon.collect_users().get("human_users", [])]
    locs.append("/root")
    return [l for l in locs if l and Path(l).is_dir()]


def plant(locations: list[str]) -> list[dict]:
    st = _load()
    planted = st.get("canaries", [])
    known = {c["path"] for c in planted}
    for i, loc in enumerate(locations):
        d = Path(loc)
        if not d.is_dir():
            continue
        p = d / DECOY_NAMES[(len(planted) + i) % len(DECOY_NAMES)]
        if str(p) in known or p.exists():
            continue
        token = secrets.token_hex(20)
        try:
            p.write_text(_decoy_content(token))
            p.chmod(0o600)
            stt = p.stat()
        except OSError:
            continue
        planted.append(
            {
                "path": str(p),
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                "inode": stt.st_ino,
                "planted_at": _now(),
            }
        )
        known.add(str(p))
    st["canaries"] = planted
    _save(st)
    return planted


def check() -> list[dict]:
    findings: list[dict] = []
    for c in _load().get("canaries", []):
        p = Path(c["path"])
        if not p.exists():
            findings.append(
                {"sev": "high", "kind": "canary", "detail": f"señuelo DESAPARECIDO: {c['path']}",
                 "why": "un honeytoken borrado indica manipulación o barrido de un intruso",
                 "target": {"path": c["path"]}}
            )
            continue
        try:
            cur = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            continue
        if cur != c["sha256"]:
            findings.append(
                {"sev": "high", "kind": "canary", "detail": f"señuelo MODIFICADO: {c['path']}",
                 "why": "nadie legítimo edita un honeytoken → acceso de atacante",
                 "target": {"path": c["path"]}}
            )
        elif p.stat().st_ino != c["inode"]:
            findings.append(
                {"sev": "med", "kind": "canary", "detail": f"señuelo RECREADO: {c['path']}",
                 "why": "el fichero-cebo fue reemplazado (inode distinto)",
                 "target": {"path": c["path"]}}
            )
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
            print(f"   {c['path']}  (sha {c['sha256'][:8]}…)")
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
