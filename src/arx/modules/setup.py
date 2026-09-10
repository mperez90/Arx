"""Arx · setup — wizard de configuración (lado usuario, consola).

Configura, en orden:
  1) proveedores LLM y orden de fallback (OpenAI → Anthropic → KIMI),
  2) palabra de autorización (se guarda solo su hash),
  3) alcance y fuera-de-límites,
  4) ventana de baseline,
  5) licencia (core/pro/business).

Escribe config.json + secrets.json (0600) en el dir de Arx. `arx setup --show`
muestra la configuración actual con los secretos redactados.
"""
from __future__ import annotations

import getpass

from arx import config

# (proveedor, modelo por defecto). El orden es también el orden de fallback base.
PROVIDERS = [
    ("openai", "gpt-5.4-mini"),
    ("anthropic", "claude-sonnet-5"),
    ("kimi", "kimi-k3"),
]


def _ask(prompt: str, default: str | None = None) -> str:
    d = f" [{default}]" if default else ""
    return input(f"{prompt}{d}: ").strip() or (default or "")


def _ask_secret(prompt: str) -> str:
    return getpass.getpass(f"{prompt}: ").strip()


def show() -> int:
    cfg = config.load_config()
    if not cfg:
        print("Arx no está configurado todavía. Ejecuta:  arx setup")
        return 0
    print("\n▸ Configuración de Arx")
    print(f"  dir            {config.config_dir()}")
    print(f"  orden fallback {' → '.join(cfg.get('fallback_order', [])) or '(ninguno)'}")
    for prov, model in cfg.get("providers", {}).items():
        print(f"  {prov:<12} modelo {model}  ·  clave {config.redact(config.get_api_key(prov))}")
    print(f"  palabra auth   {'configurada' if cfg.get('auth_word') else 'NO configurada'}")
    print(f"  alcance        {cfg.get('scope', '(todo el host)')}")
    print(f"  fuera-límites  {cfg.get('out_of_bounds', '(ninguno)')}")
    print(f"  baseline       {cfg.get('baseline_days', '?')} días")
    print(f"  licencia       {cfg.get('license_tier', 'core')}\n")
    return 0


def run(show_only: bool = False) -> int:
    if show_only:
        return show()

    cfg = config.load_config()
    store = config.load_secrets()
    print("\n═ Arx · configuración ═")

    print("\n1) Proveedores LLM  (Enter en la clave = omitir ese proveedor)")
    providers: dict[str, str] = {}
    for prov, default_model in PROVIDERS:
        key = _ask_secret(f"   Clave API de {prov} (vacío = omitir)")
        if key:
            store[prov] = key
        if key or prov in store:
            providers[prov] = _ask(f"   Modelo de {prov}", default_model)
    if not providers:
        print("   ⚠ Sin proveedores: Arx no podrá razonar hasta que configures al menos uno.")
    order = [p for p, _ in PROVIDERS if p in providers]

    print("\n2) Palabra de autorización  (para acciones irreversibles · Tier 2)")
    while True:
        w1 = _ask_secret("   Palabra")
        if not w1:
            print("   No puede quedar vacía.")
            continue
        if w1 != _ask_secret("   Repite la palabra"):
            print("   No coinciden, reintenta.")
            continue
        break
    auth = config.hash_word(w1)

    print("\n3) Alcance")
    scope = _ask("   Qué defiende Arx", "todo el host")
    oob = _ask("   Fuera de límites (rutas/servicios que NO debe tocar)", "(ninguno)")

    print("\n4) Aprendizaje")
    days = _ask("   Días de ventana de baseline", "7")

    print("\n5) Licencia")
    tier = _ask("   Tier (core/pro/business)", "core").lower()
    if tier in ("pro", "business"):
        key = _ask_secret("   Clave de licencia (Enter para activar más tarde)")
        if key:
            import platform
            import socket

            from arx import __version__
            from arx import license as lic_mod

            try:
                res = lic_mod.activate(key, socket.gethostname(), platform.platform(), __version__)
                if res.get("ok"):
                    lic_mod.validate()
                    et, _ = lic_mod.effective_tier()
                    print(f"   ✓ Licencia activada en este servidor · tier {et}")
                else:
                    store["license_key"] = key
                    print(f"   ⚠ No pude activar ahora ({res.get('reason')}). "
                          "Guardada; reintenta:  arx license activate <LLAVE>")
            except Exception as e:  # sin conexión, etc.
                store["license_key"] = key
                print(f"   ⚠ Sin conexión para activar ({e}). "
                      "Guardada; reintenta:  arx license activate <LLAVE>")

    cfg.update(
        {
            "providers": providers,
            "fallback_order": order,
            "auth_word": auth,
            "scope": scope,
            "out_of_bounds": oob,
            "baseline_days": int(days) if days.isdigit() else 7,
            "license_tier": tier if tier in ("core", "pro", "business") else "core",
        }
    )
    config.save_config(cfg)
    config.save_secrets(store)

    print("\n✓ Configuración guardada:")
    print(f"    {config.config_path()}  (0600)")
    print(f"    {config.secrets_path()}  (0600)")
    print("    En producción Arx los deja inmutables (chattr +i) tras el setup.")
    print("\nSiguiente paso:  arx recon\n")
    return 0
