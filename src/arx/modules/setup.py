"""Arx · setup — wizard de configuración (lado usuario, consola).

Configura, en orden:
  1) proveedores LLM y orden de fallback (OpenAI → Anthropic → KIMI),
  2) palabra de autorización (se guarda solo su hash),
  3) alcance y fuera-de-límites,
  4) ventana de baseline y presupuesto del motor LLM,
  5) licencia (core/pro/business),
  6) alertas salientes (Telegram / webhook),
  7) respuesta automática (qué hacer con un escaneo; si el modelo puede bloquear cuentas),
  8) programa de mejora (informes de uso anónimos, solo con un «sí»).

Escribe config.json + secrets.json (0600) en el dir de Arx. `arx setup --show`
muestra la configuración actual con los secretos redactados.
"""
from __future__ import annotations

import getpass
import socket

from arx import config, telemetry, totp
from arx.i18n import SUPPORTED, lang, set_lang, tr
from arx.modules import telegram

# (proveedor, modelo por defecto). El orden es también el orden de fallback base.
PROVIDERS = [
    ("openai", "gpt-5.4-mini"),
    ("anthropic", "claude-sonnet-5-5"),
    ("kimi", "kimi-k3"),
]


def _ask(prompt: str, default: str | None = None) -> str:
    d = f" [{default}]" if default else ""
    try:
        return input(f"{prompt}{d}: ").strip() or (default or "")
    except EOFError:  # entrada cerrada (respuestas por tubería que no llegan a este paso): el valor por defecto
        print()
        return default or ""


def _ask_secret(prompt: str) -> str:
    return getpass.getpass(f"{prompt}: ").strip()


def show() -> int:
    cfg = config.load_config()
    if not cfg:
        print(tr("Arx is not configured yet. Run:  arx setup"))
        return 0
    print(tr("\n▸ Arx configuration"))
    print(f"  lang           {lang()}")
    print(f"  dir            {config.config_dir()}")
    print(tr("  fallback order {v}", v=' → '.join(cfg.get('fallback_order', [])) or tr("(none)")))
    for prov, model in cfg.get("providers", {}).items():
        print(tr("  {prov:<12} model {model}  ·  key {v}",
                 prov=prov, model=model, v=config.redact(config.get_api_key(prov))))
    print(tr("  auth word      {v}",
             v=tr("configured") if cfg.get('auth_word') else tr("NOT configured")))
    print(tr("  scope          {scope}", scope=cfg.get('scope', tr("(the whole host)"))))
    print(tr("  out-of-bounds  {out_of_bounds}",
             out_of_bounds=cfg.get('out_of_bounds', tr("(none)"))))
    print(tr("  baseline       {baseline_days} days", baseline_days=cfg.get('baseline_days', '?')))
    print(tr("  LLM            only on new findings · max {llm_daily_budget}/day",
             llm_daily_budget=cfg.get('llm_daily_budget', 48)))
    n = cfg.get("notify") or {}
    tg = tr("yes") if n.get("telegram_chat_id") and config.load_secrets().get("telegram_bot_token") else "no"
    print(tr("  alerts         telegram {tg} · webhook {v} · from sev {min_sev}",
             tg=tg, v=tr("yes") if n.get('webhook_url') else 'no', min_sev=n.get('min_sev', 'high')))
    print(tr("  chat control   {v}",
             v=tr("yes, with a one-time code") if n.get('telegram_interactive') else 'no'))
    print(tr("  on a scan      {ip_response}", ip_response=cfg.get('ip_response', 'block')))
    print(tr("  model locks    {v} · from {llm_lock_min_confidence}% confidence",
             v='no' if cfg.get('llm_identity_actions') is False else tr("yes, with --enforce"),
             llm_lock_min_confidence=cfg.get('llm_lock_min_confidence', 70)))
    print(tr("  license        {license_tier}", license_tier=cfg.get('license_tier', 'core')))
    print(tr("  improvement    {v}\n", v=tr("joined") if telemetry.consent(cfg) == "yes" else tr("not joined")))
    return 0


def run(show_only: bool = False) -> int:
    if show_only:
        return show()

    cfg = config.load_config()
    store = config.load_secrets()
    chosen = _ask("Language / Idioma (en/es)", cfg.get("lang") or lang()).lower()
    set_lang(chosen if chosen in SUPPORTED else lang())
    print(tr("\n═ Arx · configuration ═"))

    print(tr("\n1) LLM providers  (Enter on the key = skip that provider)"))
    providers: dict[str, str] = {}
    for prov, default_model in PROVIDERS:
        key = _ask_secret(tr("   API key for {prov} (empty = skip)", prov=prov))
        if key:
            store[prov] = key
        if key or prov in store:
            providers[prov] = _ask(tr("   Model for {prov}", prov=prov), default_model)
    if not providers:
        print(tr("   ⚠ No providers: Arx cannot reason until you configure at least one."))
    order = [p for p, _ in PROVIDERS if p in providers]

    print(tr("\n2) Authorization word  (for irreversible actions · Tier 2)"))
    for _ in range(5):  # sin terminal (entrada cerrada) las respuestas vacías no se acaban nunca
        w1 = _ask_secret(tr("   Word"))
        if not w1:
            print(tr("   It cannot be empty."))
            continue
        if w1 != _ask_secret(tr("   Repeat the word")):
            print(tr("   They do not match, try again."))
            continue
        break
    else:
        raise SystemExit(tr("No authorization word: setup cancelled, nothing was saved."))
    auth = config.hash_word(w1)

    print(tr("\n3) Scope"))
    scope = _ask(tr("   What Arx defends"), tr("the whole host"))
    oob = _ask(tr("   Out of bounds: ports, paths, processes or accounts it must NEVER touch, "
                  "comma-separated (the SSH port is already protected)"), cfg.get("out_of_bounds", tr("(none)")))

    print(tr("\n4) Learning and engine"))
    days = _ask(tr("   Baseline window in days"), "7")
    budget = _ask(tr("   Maximum LLM queries per day (only used on new findings)"),
                  str(cfg.get("llm_daily_budget", 48)))

    print(tr("\n5) License"))
    tier = _ask("   Tier (core/pro/business)", "core").lower()
    if tier in ("pro", "business"):
        key = _ask_secret(tr("   License key (Enter to activate later)"))
        if key:
            import platform

            from arx import __version__
            from arx import license as lic_mod

            try:
                res = lic_mod.activate(key, socket.gethostname(), platform.platform(), __version__)
                if res.get("ok"):
                    lic_mod.validate()
                    et, _ = lic_mod.effective_tier()
                    print(tr("   ✓ License activated on this server · tier {et}", et=et))
                else:
                    store["license_key"] = key
                    print(tr("   ⚠ Could not activate now ({reason}). Saved; retry:  arx license "
                             "activate <KEY>", reason=res.get('reason')))
            except Exception as e:  # sin conexión, etc.
                store["license_key"] = key
                print(tr("   ⚠ No connection to activate ({e}). Saved; retry:  arx license "
                         "activate <KEY>", e=e))

    print(tr("\n6) Alerts  (Enter = skip)"))
    notify_cfg = dict(cfg.get("notify") or {})
    print(tr("   Telegram: in the app, talk to @BotFather, send it /newbot and follow its steps. "
             "It will give you a token.\n   Create a bot just for Arx: it is yours, and nobody but "
             "you goes through it."))
    tg_token = _ask_secret(tr("   Telegram bot token (empty = keep/skip)"))
    if tg_token:
        store["telegram_bot_token"] = tg_token
        name = telegram.bot_name(tg_token)
        if name:
            print(tr("   ✓ Bot @{name}. Send it any message from your phone now (waiting 90 s)…",
                     name=name))
            chat = telegram.detect_chat_id(tg_token)
            if chat:
                notify_cfg["telegram_chat_id"] = chat
                print(tr("   ✓ Your chat is {chat}. Only this chat can talk to Arx.", chat=chat))
            else:
                print(tr("   No message arrived: type the chat_id by hand."))
        else:
            print(tr("   ⚠ Could not check that token now (is it right? is there a connection?). "
                     "Saving it anyway."))
    if tg_token or store.get("telegram_bot_token"):
        notify_cfg["telegram_chat_id"] = _ask(tr("   Telegram chat_id to alert"),
                                              notify_cfg.get("telegram_chat_id"))
        interactive = _ask(tr("   Control Arx from that chat? (query, and authorize with a "
                              "one-time code) (y/n)"),
                           tr("y") if notify_cfg.get("telegram_interactive") else "n").lower() in ("y", "s")
        notify_cfg["telegram_interactive"] = interactive
        if interactive and not store.get("telegram_totp"):
            store["telegram_totp"] = totp.new_secret()
            print(tr("   Add this key to your authenticator app (Google Authenticator, Aegis, "
                     "1Password…):"))
            print(f"     {store['telegram_totp']}")
            print(f"     {totp.uri(store['telegram_totp'], socket.gethostname())}")
            print(tr("   This is what Arx will ask for to act from the chat: your word never "
                     "travels through it."))
    notify_cfg["webhook_url"] = _ask(tr("   Webhook URL (Slack/Discord/n8n…)"), notify_cfg.get("webhook_url"))
    notify_cfg["min_sev"] = _ask(tr("   Alert from severity (crit/high/med)"), notify_cfg.get("min_sev", "high"))

    print(tr("\n7) Automatic response  (only acts with --enforce)"))
    ip_response = _ask(tr("   On a scan: block (cut the IP) or tarpit (throttle it: useful if the "
                          "IP may be shared)"), cfg.get("ip_response", "block")).lower()
    llm_acts = True
    if providers:
        print(tr("   If the model confirms unknown access as a threat, Arx can lock that account "
                 "and\n   close its sessions without waiting for you, and alerts you with the full "
                 "context. It never touches root,\n   system accounts or the last admin account."))
        llm_acts = _ask(tr("   Allow it? (y/n)"), "n" if cfg.get("llm_identity_actions") is False else tr("y")).lower() != "n"

    print(tr("\n8) Improvement program  (optional · nothing is sent unless you say yes)"))
    print(tr("   Arx can send an anonymous usage report every few days: version, system, how its "
             "watchers\n   are doing and how much noise it makes. Never host names, IPs, paths, "
             "users, commands or\n   secrets. See it exactly:  arx telemetry show"))
    joined = (cfg.get("telemetry") or {}).get("consent") == "yes"
    join = _ask(tr("   Join? (y/n)"), tr("y") if joined else "n").lower() in ("y", "s")
    if not join:
        telemetry.forget_state()

    cfg.update(
        {
            "telemetry": telemetry.decide(join, cfg.get("telemetry")),
            "lang": lang(),
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

    print(tr("\n✓ Configuration saved:"))
    print(f"    {config.config_path()}  (0600)")
    print(f"    {config.secrets_path()}  (0600)")
    print(tr("\nNext step:  arx recon\n"))
    return 0
