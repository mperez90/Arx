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
from arx.i18n import tr

GRACE_DAYS = 14
DENY_CODES = {400, 401, 404, 410, 422}  # respuestas que significan "esta licencia no vale"
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
        "organization_id": "658f3fab-d2e5-4415-9e5a-e6eb41856c8b",  # Advanced Systems Laboratories
        # Suscripciones (D7): UN benefit por tier, compartido por founding/estándar y
        # mensual/anual. La suscripción gobierna la vigencia: al cancelar, Polar revoca
        # el benefit y la validación degrada a Core (falla-abierto con gracia).
        "benefits": {
            "f3b4fe6c-34fa-4edb-91f8-d610aff86158": "pro",       # Arx Pro — suscripción (1 dispositivo)
            "6349dc31-3239-434a-a58d-1fbe377f4b79": "business",  # Arx Business — suscripción (flota)
        },
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
    "arsenal": "business",
}
_ORDER = {"core": 0, "pro": 1, "business": 2}


def _env() -> dict:
    name = os.environ.get("ARX_POLAR_ENV") or config.load_config().get("polar_env") or "sandbox"
    return POLAR.get(name, POLAR["sandbox"])


def _path():
    return config.state_dir() / "license.json"


def load() -> dict:
    return config.read_json(_path())


def save(d: dict) -> None:
    config.write_json(_path(), d)


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
            return {"ok": False, "reason": tr("that key is already in use on another server: "
                                              "release it with 'arx license deactivate' there, or "
                                              "from your Polar portal")}
        if e.code == 404:
            return {"ok": False, "reason": tr("key not recognized: check that you pasted all of it")}
        return {"ok": False, "reason": tr("the console rejected the activation (HTTP {code})",
                                          code=e.code)}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "reason": tr("no connection to Polar: {e}", e=e)}
    activation_id = resp.get("id")
    if not activation_id:
        return {"ok": False, "reason": tr("Polar did not return an activation_id")}
    st = load()
    st.update({"key": key, "activation_id": activation_id, "conditions": CONDITIONS})
    save(st)
    return {"ok": True, "activation_id": activation_id}


def validate(post=_post, now: datetime | None = None) -> dict:
    st = load()
    if not st.get("key") or not st.get("activation_id"):
        return {"ok": False, "reason": tr("no license activated")}
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
        # Solo un "no" DEFINITIVO del servidor degrada al instante. 403 (WAF/Cloudflare),
        # 408, 429 (rate-limit) y 5xx son "no pude preguntar" → gracia, como sin red.
        if e.code in DENY_CODES:
            cache = {"status": "denied", "http": e.code, "tier": "core",
                     "last_validated_at": now.isoformat(timespec="seconds")}
            cache["sig"] = _sign(cache)
            st["cache"] = cache
            save(st)
            return {"ok": False, "status": "denied", "http": e.code, "tier": "core"}
        return {"ok": False, "offline": True, "reason": tr("server {code}", code=e.code)}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "offline": True, "reason": tr("no connection: {e}", e=e)}

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
        return "core", tr("no license (Core)")
    cache = st.get("cache") or {}
    if cache.get("sig") and not _verify(cache):
        return "core", tr("tampered license cache → Core")
    if cache.get("status") == "revoked":
        return "core", tr("license revoked by the server")
    if cache.get("status") == "denied":
        return "core", tr("rejected by the server (HTTP {http})", http=cache.get('http', '?'))

    now = now or datetime.now(timezone.utc)
    last = _parse_iso(cache.get("last_validated_at", ""))
    if cache.get("status") == "granted" and last:
        age_days = (now - last).total_seconds() / 86400
        exp = _parse_iso(cache.get("expires_at", "") or "")
        # Reloj retrocedido = "no pude preguntar", no "me dijeron que no" → no desarmar.
        # (Un salto ADELANTE no se distingue localmente de una expiración real → degrada a
        #  Core, nunca a "sin protección"; un host en línea se autocorrige al revalidar.)
        if age_days < -1:
            return cache.get("tier", "core"), tr("clock anomaly (went backwards): keeping the tier")
        if exp and exp < now:
            return "core", tr("license expired by date")
        if age_days <= GRACE_DAYS:
            return cache.get("tier", "core"), tr("valid (validated {v} d ago)",
                                                 v=int(max(age_days, 0)))
        return "core", tr("grace period over ({age_days} d without validating) → Core",
                          age_days=int(age_days))
    return "core", tr("no previous successful validation → Core")


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
                    "reason": tr("could not release it in Polar ({e}). Release it from your Polar "
                                 "portal.", e=e)}
    st.pop("activation_id", None)
    st.pop("cache", None)
    save(st)
    return {"ok": True, "released": True}
