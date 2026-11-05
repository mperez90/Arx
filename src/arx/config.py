"""Arx · config — configuración y secretos del host.

Producción: /etc/arx (root, 0700) con config.json y secrets.json a 0600.
Desarrollo/sin permiso: ~/.arx.

Reglas de seguridad:
  · La palabra de autorización NUNCA se guarda en claro — solo salt + hash scrypt.
  · Las claves de API se leen primero de entorno (ARX_<PROV>_API_KEY) y, si no,
    de secrets.json — así se puede operar sin escribir la clave a disco.
  · Toda escritura de estado es ATÓMICA (temporal + rename) y nace con 0600: un corte
    a mitad no deja JSON corrupto, y un secreto nunca existe ni un instante legible.
  · `locked()` serializa a los escritores concurrentes (servicio `guard` + CLI).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
from pathlib import Path

from arx.i18n import tr

try:
    import fcntl
except ImportError:  # no-POSIX: sin bloqueo entre procesos (Arx apunta a Linux/macOS)
    fcntl = None


def _first_writable(candidates: list[Path], private: bool) -> Path:
    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            if private:
                try:
                    p.chmod(0o700)
                except OSError:
                    pass
            return p
        except OSError:
            continue
    # Nunca caer al directorio actual: ahí acabarían secretos en sitios imprevisibles.
    raise SystemExit(tr("Arx cannot find a writable directory for its state ({v}). Use "
                        "ARX_CONFIG_DIR / ARX_STATE_DIR.", v=', '.join(map(str, candidates))))


def config_dir() -> Path:
    """Preferencia: $ARX_CONFIG_DIR → /etc/arx (root) → ~/.arx (dev/sin permiso)."""
    env = os.environ.get("ARX_CONFIG_DIR")
    return _first_writable([Path(env)] if env else [Path("/etc/arx"), Path.home() / ".arx"], True)


def config_path() -> Path:
    return config_dir() / "config.json"


def secrets_path() -> Path:
    return config_dir() / "secrets.json"


def state_dir() -> Path:
    """Estado operativo (inventario, baseline, incidentes). Separado de la config.

    Producción: /var/lib/arx (root). Desarrollo/sin permiso: ~/.arx/state.
    """
    env = os.environ.get("ARX_STATE_DIR")
    return _first_writable(
        [Path(env)] if env else [Path("/var/lib/arx"), Path.home() / ".arx" / "state"], True)


# ── E/S de estado: atómica, privada y con bloqueo ────────────────────────────
def read_json(path: Path, default=None):
    """Lee JSON; ante fichero ausente o corrupto devuelve `default` (copia nueva)."""
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {} if default is None else default


def write_json(path: Path, data) -> None:
    """Escritura atómica: temporal 0600 en el mismo dir → fsync → rename."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    text = json.dumps(data, indent=2, ensure_ascii=False)
    try:
        raw = text.encode("utf-8")
    except UnicodeEncodeError:  # ruta no UTF-8 de un atacante: se escapa (ida y vuelta exacta)
        raw = json.dumps(data, indent=2).encode("ascii")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@contextlib.contextmanager
def locked(name: str = "state"):
    """Bloqueo exclusivo entre procesos sobre un fichero de estado (`flock`)."""
    if fcntl is None:
        yield
        return
    fd = os.open(state_dir() / f".{name}.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load_config() -> dict:
    return read_json(config_path())


def save_config(d: dict) -> None:
    write_json(config_path(), d)


def load_secrets() -> dict:
    return read_json(secrets_path())


def save_secrets(d: dict) -> None:
    write_json(secrets_path(), d)


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
