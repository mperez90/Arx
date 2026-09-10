"""Arx · config — configuración y secretos del host.

Producción: /etc/arx (root, 0700) con config.json y secrets.json a 0600,
inmutables (chattr +i) tras el setup. Desarrollo/sin permiso: ~/.arx.

Reglas de seguridad:
  · La palabra de autorización NUNCA se guarda en claro — solo salt + hash scrypt.
  · Las claves de API se leen primero de entorno (ARX_<PROV>_API_KEY) y, si no,
    de secrets.json — así se puede operar sin escribir la clave a disco.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path


def config_dir() -> Path:
    """Preferencia: $ARX_CONFIG_DIR → /etc/arx (root) → ~/.arx (dev/sin permiso)."""
    env = os.environ.get("ARX_CONFIG_DIR")
    candidates = [Path(env)] if env else [Path("/etc/arx"), Path.home() / ".arx"]
    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            try:
                p.chmod(0o700)
            except OSError:
                pass
            return p
        except OSError:
            continue
    return Path.cwd()


def config_path() -> Path:
    return config_dir() / "config.json"


def secrets_path() -> Path:
    return config_dir() / "secrets.json"


def state_dir() -> Path:
    """Estado operativo (inventario, baseline, incidentes). Separado de la config.

    Producción: /var/lib/arx (root). Desarrollo/sin permiso: ~/.arx/state.
    """
    env = os.environ.get("ARX_STATE_DIR")
    candidates = [Path(env)] if env else [Path("/var/lib/arx"), Path.home() / ".arx" / "state"]
    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            return p
        except OSError:
            continue
    return Path.cwd()


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _save_private(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_config() -> dict:
    return _load(config_path())


def save_config(d: dict) -> None:
    _save_private(config_path(), d)


def load_secrets() -> dict:
    return _load(secrets_path())


def save_secrets(d: dict) -> None:
    _save_private(secrets_path(), d)


# ── palabra de autorización (solo hash) ──────────────────────────────────────
def hash_word(word: str) -> dict:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(word.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return {"algo": "scrypt", "n": 2**14, "r": 8, "p": 1, "salt": salt.hex(), "hash": h.hex()}


def verify_word(word: str, stored: dict) -> bool:
    if not stored or stored.get("algo") != "scrypt":
        return False
    h = hashlib.scrypt(
        word.encode(), salt=bytes.fromhex(stored["salt"]),
        n=stored["n"], r=stored["r"], p=stored["p"], dklen=32,
    )
    return secrets.compare_digest(h.hex(), stored["hash"])


# ── claves de API ─────────────────────────────────────────────────────────────
def get_api_key(provider: str) -> str | None:
    env = os.environ.get(f"ARX_{provider.upper()}_API_KEY")
    return env if env else load_secrets().get(provider)


def redact(key: str | None) -> str:
    if not key:
        return "—"
    return f"{'•' * 8}{key[-4:]}" if len(key) > 4 else "•" * len(key)
