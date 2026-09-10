"""Arx · license — activación/validación de licencia sobre Polar (Customer Portal API).

El binario NO lleva secretos nuestros: los endpoints son públicos y se autentican con la
propia llave del cliente. Doctrina **FALLAR ABIERTO**: si no se puede validar (red caída,
DNS envenenado, Polar fuera), Arx NO desarma la defensa — degrada a Core (gratis) solo
tras el periodo de gracia, y de inmediato SOLO ante un `revoked` explícito del servidor.

La caché de validación se firma con HMAC (secreto local por-máquina). Nota honesta: el
Core es source-available, así que esto frena manipulación casual, no al dueño-root; la
licencia es honestidad/conveniencia, no DRM.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone

from arx import __version__, config

GRACE_DAYS = 14
CONDITIONS = {"license_gen": 0}  # desacoplado de la versión de software — ver docs/respuesta-arx-polar.md §5

# IDs por entorno. Producción se fija antes del release (los IDs difieren de sandbox).
POLAR = {
    "sandbox": {
        "base": "https://sandbox-api.polar.sh/v1",
        "organization_id": "3a247f62-c3ab-433e-949d-76e7234fc2e5",
        # CUATRO benefits: cada línea tiene edición Founding (primeros 100) + estándar.
        # Founding y estándar dan el MISMO tier; solo difieren en el término, que Arx
        # NO deduce del tier — lo lee de expires_at en la respuesta de validación.
        "benefits": {
            "ad29f387-ccae-44c7-aea5-af1879f512dd": "pro",       # Pro Founding (3 años)
            "e03995ef-5765-4fd7-abb9-2350f275aed8": "pro",       # Pro (2 años)
            "ff44b95d-e43c-41a4-a9cf-aee5a4668288": "business",  # Business Founding (2 años)
            "81882e82-5547-479a-a969-4ae6a514faed": "business",  # Business (1 año)
        },
    },
    "production": {
        "base": "https://api.polar.sh/v1",
        "organization_id": "",  # TODO release: fijar org_id de producción
        "benefits": {},          # TODO release: fijar benefit_id → tier de producción
    },
}

# feature → tier mínimo que la habilita
_FEATURE_TIER = {
    "managed_intel": "pro",
    "advanced_detections": "pro",
    "self_pentest": "pro",
    "incident_reports": "pro",
    "fleet": "business",
    "console": "business",
    "cross_host": "business",
    "compliance": "business",
}
_ORDER = {"core": 0, "pro": 1, "business": 2}


def _env() -> dict:
    name = os.environ.get("ARX_POLAR_ENV") or config.load_config().get("polar_env") or "sandbox"
    return POLAR.get(name, POLAR["sandbox"])


def _path():
    return config.state_dir() / "license.json"


def load() -> dict:
    try:
        return json.loads(_path().read_text())
    except (OSError, ValueError):
        return {}


def save(d: dict) -> None:
    _path().write_text(json.dumps(d, indent=2, ensure_ascii=False))
    try:
        _path().chmod(0o600)
    except OSError:
        pass


# ── firma de la caché (HMAC local) ───────────────────────────────────────────
def _hmac_key() -> bytes:
    s = config.load_secrets()
    k = s.get("license_cache_hmac")
    if not k:
        k = os.urandom(32).hex()
        s["license_cache_hmac"] = k
        config.save_secrets(s)
    return bytes.fromhex(k)


def _sign(cache: dict) -> str:
    core = {k: v for k, v in cache.items() if k != "sig"}
    return hmac.new(_hmac_key(), json.dumps(core, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def _verify(cache: dict) -> bool:
    sig = cache.get("sig")
    return bool(sig) and hmac.compare_digest(sig, _sign(cache))


# ── HTTP (inyectable para test) ──────────────────────────────────────────────
def _post(url: str, payload: dict, timeout: int = 15) -> dict:
    data = json.dumps(payload).encode()
    # User-Agent propio: sin él, Cloudflare (delante de api.polar.sh) responde 403 (error 1010)
    # y toda activación/validación fallaría en silencio.
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"arx/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read().decode())


# ── activación / validación ──────────────────────────────────────────────────
def activate(key: str, hostname: str, os_str: str, version: str, post=_post) -> dict:
    env = _env()
    try:
        resp = post(
            f"{env['base']}/customer-portal/license-keys/activate",
            {
                "key": key,
                "organization_id": env["organization_id"],
                "label": hostname,
                "conditions": CONDITIONS,
                "meta": {"os": os_str, "arx_version": version},
            },
        )
    except urllib.error.HTTPError as e:
        if e.code in (403, 409):
            return {"ok": False, "reason": "esa llave ya está en uso en otro servidor — "
                    "libérala con 'arx license deactivate' allí, o desde tu portal de Polar"}
        if e.code == 404:
            return {"ok": False, "reason": "llave no reconocida — revisa que la pegaste completa"}
        return {"ok": False, "reason": f"la consola rechazó la activación (HTTP {e.code})"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "reason": f"sin conexión con Polar: {e}"}
    activation_id = resp.get("id")
    if not activation_id:
        return {"ok": False, "reason": "Polar no devolvió activation_id"}
    st = load()
    st.update({"key": key, "activation_id": activation_id, "conditions": CONDITIONS})
    save(st)
    return {"ok": True, "activation_id": activation_id}


def validate(post=_post, now: datetime | None = None) -> dict:
    st = load()
    if not st.get("key") or not st.get("activation_id"):
        return {"ok": False, "reason": "sin licencia activada"}
    env = _env()
    now = now or datetime.now(timezone.utc)
    try:
        resp = post(
            f"{env['base']}/customer-portal/license-keys/validate",
            {
                "key": st["key"],
                "organization_id": env["organization_id"],
                "activation_id": st["activation_id"],
                "conditions": st.get("conditions", CONDITIONS),
            },
        )
    except urllib.error.HTTPError as e:
        # el servidor RESPONDIÓ (y dijo que no) → NO es offline. 4xx degrada; 5xx = caída.
        if 400 <= e.code < 500:
            cache = {"status": "denied", "http": e.code, "tier": "core",
                     "last_validated_at": now.isoformat(timespec="seconds")}
            cache["sig"] = _sign(cache)
            st["cache"] = cache
            save(st)
            return {"ok": False, "status": "denied", "http": e.code, "tier": "core"}
        return {"ok": False, "offline": True, "reason": f"servidor {e.code}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "offline": True, "reason": f"sin conexión: {e}"}

    status = resp.get("status")
    tier = env["benefits"].get(resp.get("benefit_id"), "core")  # sin benefit_id → Core
    if status == "granted":
        cache = {
            "status": "granted",
            "tier": tier,
            "benefit_id": resp.get("benefit_id"),
            "expires_at": resp.get("expires_at"),
            "last_validated_at": now.isoformat(timespec="seconds"),
        }
    else:  # respuesta explícita negativa (revoked, etc.)
        cache = {"status": status or "denied", "tier": "core",
                 "last_validated_at": now.isoformat(timespec="seconds")}
    cache["sig"] = _sign(cache)
    st["cache"] = cache
    save(st)
    return {"ok": status == "granted", "status": status, "tier": cache["tier"]}


# ── tier efectivo (fallar-abierto) ───────────────────────────────────────────
def _parse_iso(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def effective_tier(now: datetime | None = None) -> tuple[str, str]:
    """Devuelve (tier_efectivo, razón). Núcleo de la doctrina fallar-abierto."""
    st = load()
    if not st.get("key"):
        return "core", "sin licencia (Core)"
    cache = st.get("cache") or {}
    if cache.get("sig") and not _verify(cache):
        return "core", "caché de licencia manipulada → Core"
    if cache.get("status") == "revoked":
        return "core", "licencia revocada por el servidor"
    if cache.get("status") == "denied":
        return "core", f"rechazada por el servidor (HTTP {cache.get('http', '?')})"

    now = now or datetime.now(timezone.utc)
    last = _parse_iso(cache.get("last_validated_at", ""))
    if cache.get("status") == "granted" and last:
        age_days = (now - last).total_seconds() / 86400
        exp = _parse_iso(cache.get("expires_at", "") or "")
        # Reloj retrocedido = "no pude preguntar", no "me dijeron que no" → no desarmar.
        # (Un salto ADELANTE no se distingue localmente de una expiración real → degrada a
        #  Core, nunca a "sin protección"; un host en línea se autocorrige al revalidar.)
        if age_days < -1:
            return cache.get("tier", "core"), "anomalía de reloj (retroceso) — mantengo el tier"
        if exp and exp < now:
            return "core", "licencia expirada por fecha"
        if age_days <= GRACE_DAYS:
            return cache.get("tier", "core"), f"válida (validada hace {int(max(age_days, 0))} d)"
        return "core", f"gracia agotada ({int(age_days)} d sin validar) → Core"
    return "core", "sin validación exitosa previa → Core"


def tier_allows(feature: str, tier: str | None = None) -> bool:
    tier = tier or effective_tier()[0]
    return _ORDER.get(tier, 0) >= _ORDER.get(_FEATURE_TIER.get(feature, "core"), 0)


def deactivate(post=_post) -> dict:
    """Libera la activación en Polar y luego olvida el estado local (para reinstalar).

    Con Pro a 1 activación, reinstalar es un camino NORMAL: si no se libera en Polar, la
    reactivación choca con el límite. Si la llamada falla, NO se borra el estado local: se
    avisa y se apunta al portal, en vez de dejar la activación colgada en silencio.
    """
    st = load()
    if st.get("key") and st.get("activation_id"):
        env = _env()
        try:
            post(
                f"{env['base']}/customer-portal/license-keys/deactivate",
                {"key": st["key"], "organization_id": env["organization_id"],
                 "activation_id": st["activation_id"]},
            )
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
            return {"ok": False, "released": False,
                    "reason": f"no se pudo liberar en Polar ({e}). Libérala desde tu portal de Polar."}
    st.pop("activation_id", None)
    st.pop("cache", None)
    save(st)
    return {"ok": True, "released": True}
