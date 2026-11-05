"""Arx · setup — wizard de configuración (lado usuario, consola).

Configura, en orden:
  1) proveedores LLM y orden de fallback (OpenAI → Anthropic → KIMI),
  2) palabra de autorización (se guarda solo su hash),
  3) alcance y fuera-de-límites,
  4) ventana de baseline y presupuesto del motor LLM,
  5) licencia (core/pro/business),
  6) alertas salientes (Telegram / webhook),
  7) respuesta automática (qué hacer con un escaneo; si el modelo puede bloquear cuentas).

Escribe config.json + secrets.json (0600) en el dir de Arx. `arx setup --show`
muestra la configuración actual con los secretos redactados.
"""
from __future__ import annotations

import getpass
import socket

from arx import config, totp
from arx.modules import telegram

# (proveedor, modelo por defecto). El orden es también el orden de fallback base.
PROVIDERS = [
    ("openai", "gpt-5.4-mini"),
    ("anthropic", "claude-sonnet-5-5"),
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
    print(f"  LLM            solo ante hallazgos nuevos · máx {cfg.get('llm_daily_budget', 48)}/día")
    n = cfg.get("notify") or {}
    tg = "sí" if n.get("telegram_chat_id") and config.load_secrets().get("telegram_bot_token") else "no"
    print(f"  alertas        telegram {tg} · webhook {'sí' if n.get('webhook_url') else 'no'} "
          f"· desde sev {n.get('min_sev', 'high')}")
    print(f"  gobierno chat  {'sí, con código de un solo uso' if n.get('telegram_interactive') else 'no'}")
    print(f"  ante escaneo   {cfg.get('ip_response', 'block')}")
    print(f"  modelo bloquea {'no' if cfg.get('llm_identity_actions') is False else 'sí, con --enforce'}"
          f" · desde {cfg.get('llm_lock_min_confidence', 70)}% de confianza")
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
    oob = _ask("   Fuera de límites — puertos, rutas, procesos o cuentas que NUNCA debe tocar, "
               "separados por coma (el puerto SSH ya está protegido)", cfg.get("out_of_bounds", "(ninguno)"))

    print("\n4) Aprendizaje y motor")
    days = _ask("   Días de ventana de baseline", "7")
    budget = _ask("   Máximo de consultas al LLM por día (solo se usa ante hallazgos nuevos)",
                  str(cfg.get("llm_daily_budget", 48)))

    print("\n5) Licencia")
    tier = _ask("   Tier (core/pro/business)", "core").lower()
    if tier in ("pro", "business"):
        key = _ask_secret("   Clave de licencia (Enter para activar más tarde)")
        if key:
            import platform

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

    print("\n6) Alertas  (Enter = omitir)")
    notify_cfg = dict(cfg.get("notify") or {})
    print("   Telegram: en la app, habla con @BotFather, envíale /newbot y sigue sus pasos. Te dará un token.\n"
          "   Crea un bot solo para Arx: es tuyo, y nadie más que tú pasa por él.")
    tg_token = _ask_secret("   Token del bot de Telegram (vacío = mantener/omitir)")
    if tg_token:
        store["telegram_bot_token"] = tg_token
        name = telegram.bot_name(tg_token)
        if name:
            print(f"   ✓ Bot @{name}. Envíale ahora cualquier mensaje desde tu móvil (espero 90 s)…")
            chat = telegram.detect_chat_id(tg_token)
            if chat:
                notify_cfg["telegram_chat_id"] = chat
                print(f"   ✓ Tu chat es el {chat}. Solo este chat podrá hablar con Arx.")
            else:
                print("   No llegó ningún mensaje: escribe el chat_id a mano.")
        else:
            print("   ⚠ No pude comprobar ese token ahora (¿es correcto? ¿hay conexión?). Se guarda igualmente.")
    if tg_token or store.get("telegram_bot_token"):
        notify_cfg["telegram_chat_id"] = _ask("   chat_id de Telegram al que avisar",
                                              notify_cfg.get("telegram_chat_id"))
        interactive = _ask("   ¿Gobernar Arx desde ese chat? (consultar, y autorizar con código de un solo uso) (s/n)",
                           "s" if notify_cfg.get("telegram_interactive") else "n").lower() == "s"
        notify_cfg["telegram_interactive"] = interactive
        if interactive and not store.get("telegram_totp"):
            store["telegram_totp"] = totp.new_secret()
            print("   Añade esta clave a tu app de autenticación (Google Authenticator, Aegis, 1Password…):")
            print(f"     {store['telegram_totp']}")
            print(f"     {totp.uri(store['telegram_totp'], socket.gethostname())}")
            print("   Es lo que te pedirá Arx para actuar desde el chat: tu palabra nunca viaja por él.")
    notify_cfg["webhook_url"] = _ask("   URL de webhook (Slack/Discord/n8n…)", notify_cfg.get("webhook_url"))
    notify_cfg["min_sev"] = _ask("   Avisar desde severidad (crit/high/med)", notify_cfg.get("min_sev", "high"))

    print("\n7) Respuesta automática  (solo actúa con --enforce)")
    ip_response = _ask("   Ante un escaneo: block (cortar la IP) o tarpit (estrangularla: útil si la IP "
                       "puede ser compartida)", cfg.get("ip_response", "block")).lower()
    llm_acts = True
    if providers:
        print("   Si el modelo confirma como amenaza un acceso desconocido, Arx puede bloquear esa cuenta "
              "y\n   cerrar sus sesiones sin esperarte, y te avisa con todo el contexto. Nunca toca root,\n"
              "   cuentas de sistema ni la última cuenta de administración.")
        llm_acts = _ask("   ¿Permitirlo? (s/n)", "n" if cfg.get("llm_identity_actions") is False else "s").lower() != "n"

    cfg.update(
        {
            "ip_response": ip_response if ip_response in ("block", "tarpit") else "block",
            "llm_identity_actions": llm_acts,
            "providers": providers,
            "fallback_order": order,
            "auth_word": auth,
            "scope": scope,
            "out_of_bounds": oob,
            "baseline_days": int(days) if days.isdigit() else 7,
            "llm_daily_budget": int(budget) if budget.isdigit() else 48,
            "notify": {k: v for k, v in notify_cfg.items() if v},
            "license_tier": tier if tier in ("core", "pro", "business") else "core",
        }
    )
    config.save_config(cfg)
    config.save_secrets(store)

    print("\n✓ Configuración guardada:")
    print(f"    {config.config_path()}  (0600)")
    print(f"    {config.secrets_path()}  (0600)")
    print("\nSiguiente paso:  arx recon\n")
    return 0
