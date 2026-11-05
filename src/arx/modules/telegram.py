"""Arx · telegram — gobernar Arx desde el móvil sin abrir ningún puerto (§6, D6).

Arx no tiene interfaz gráfica: la consola para todo, y este chat para enterarte y decidir desde
donde estés. Bot propio de cada cliente, por long-polling: el agente solo hace conexiones salientes.

  · Solo manda el chat configurado; a cualquier otro no se le contesta ni se le dice que existe.
  · Lo que actúa sobre el servidor exige un código TOTP de un solo uso. La palabra de autorización
    jamás viaja por el chat, y quien robe la cuenta de Telegram no puede hacer nada con ella.
  · Tras 5 códigos fallidos se deja de aceptarlos durante 15 minutos, y se avisa.
  · Falla-abierto: si Telegram cae, la defensa local no se entera.

Lo que se recibe no se interpreta salvo como estos comandos: nunca llega a un actuador por otro
camino. El texto libre va al modelo, que no tiene actuadores.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from arx import __version__, config, notify, redact, totp
from arx.i18n import tr

API = "https://api.telegram.org"
POLL_S = 25
MAX_FAILS = 5
LOCKOUT_S = 900
MAX_MUTE_H = 72
HELP = (tr("Commands:\n/status · /findings · /pending · /report\n"
           "/mute <hours>: silence non-critical alerts\n"
           "With your 6-digit code:\n/authorize <id> <code>\n"
           "/unlock <account> <code>\n/accept <id> <code>\n"
           "/mode observe|protect <code>\nAny other text goes to the model, if there is one. It "
           "cannot act."))


# Los comandos en español siguen valiendo, sea cual sea el idioma de la salida
_ALIASES = {"/ayuda": "/help", "/estado": "/status", "/hallazgos": "/findings", "/pendientes": "/pending",
            "/informe": "/report", "/callar": "/mute", "/autorizar": "/authorize", "/desbloquear": "/unlock",
            "/aceptar": "/accept", "/modo": "/mode"}
_MODES = {"observe": False, "protect": True, "observar": False, "proteger": True}


class Conflict(Exception):
    """Otro programa está leyendo los mensajes de este bot."""


def _state_path():
    return config.state_dir() / "telegram.json"


def _load() -> dict:
    return config.read_json(_state_path(), {}) or {}


def _save(st: dict) -> None:
    config.write_json(_state_path(), st)


def _post(url: str, payload: dict, timeout: int = 15) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": f"arx/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (API fija o de config del operador)
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        if e.code == 409:
            raise Conflict() from e
        raise


def enabled(cfg: dict | None = None) -> bool:
    cfg = cfg if cfg is not None else config.load_config()
    n = cfg.get("notify") or {}
    sec = config.load_secrets()
    return bool(n.get("telegram_interactive") and n.get("telegram_chat_id")
                and sec.get("telegram_bot_token") and sec.get("telegram_totp"))


def _api(cfg: dict, method: str, payload: dict, post=_post, timeout: int = 15) -> dict:
    base = (cfg.get("notify") or {}).get("telegram_api") or API
    token = config.load_secrets().get("telegram_bot_token", "")
    return post(f"{base}/bot{token}/{method}", payload, timeout=timeout)


def _reply(cfg: dict, chat_id, text: str, post=_post) -> None:
    _api(cfg, "sendMessage", {"chat_id": chat_id, "text": redact.scrub(text)[:3900],
                              "disable_web_page_preview": True}, post)


# ── códigos ──────────────────────────────────────────────────────────────────
def _check_code(code: str, now: float | None = None) -> str | None:
    """None si el código vale; si no, por qué. Un código usado no sirve dos veces."""
    now = time.time() if now is None else now
    st = _load()
    if now < st.get("locked_until", 0):
        return tr("Too many failed codes: none accepted for another {v} min.",
                  v=int(st['locked_until'] - now) // 60 + 1)
    secret = config.load_secrets().get("telegram_totp", "")
    counter = totp.counter_for(code, secret, now)
    if counter is None or counter <= st.get("last_counter", -1):
        st["fails"] = st.get("fails", 0) + 1
        if st["fails"] >= MAX_FAILS:
            st["locked_until"], st["fails"] = now + LOCKOUT_S, 0
        _save(st)
        return tr("Wrong or already used code. Nothing was done.")
    st["last_counter"], st["fails"] = counter, 0
    _save(st)
    return None


# ── comandos ─────────────────────────────────────────────────────────────────
def _estado() -> str:
    from arx.modules import baseline, guard, response

    base = baseline.load()
    pend, locked = response.list_pending(), response.locked_accounts()
    lines = [tr("Arx on guard") if base and base["meta"].get("sealed") else tr("Arx without a sealed baseline"),
             tr("Mode: {v}", v=tr("protect") if guard.mode_seen() else tr("observe")),
             tr("Active blocks: {n}", n=len(response._load_blocks())) + (tr(" · ⚠ BRAKE") if response.breaker_tripped() else ""),
             tr("Waiting on your decision: {n}", n=len(pend))]
    if locked:
        lines.append(tr("Locked accounts: ") + ", ".join(a["user"] for a in locked))
    return "\n".join(lines)


def _hallazgos() -> str:
    from arx.modules import response

    rows = sorted(response.load_findings().items(), key=lambda kv: kv[1].get("last_seen", ""), reverse=True)[:12]
    if not rows:
        return tr("No findings.")
    return "\n".join(f"{fp}  {redact.printable(e.get('detail'))[:90]}" for fp, e in rows)


def _pendientes() -> str:
    from arx.modules import response

    pend, locked = response.list_pending(), response.locked_accounts()
    if not pend and not locked:
        return tr("Nothing is waiting on your decision.")
    lines = [f"{p['id']} [{p.get('sev')}] {redact.printable(p.get('detail'))[:90]}\n  → {p.get('remediation')}" for p in pend]
    if pend:
        lines.append(tr("Authorize with: /authorize <id> <code>"))
    lines += [tr("Locked account: {user}: /unlock {user} <code>", user=a['user']) for a in locked]
    return "\n".join(lines)


def _informe() -> str:
    from arx.modules import forensics, metrics

    m = metrics.compute(7)
    r = forensics.build_report()["summary"]
    return (tr("Last {days_covered} days: {alerts_high} high or critical alerts, {false_positives} "
               "false positives, {unreviewed_high} unreviewed, {automatic_actions} automatic "
               "actions.\nActive containment: {active_containment} · in quarantine: "
               "{quarantined_evidence}\nThe full sealed forensic report: arx forensics, on the "
               "server.",
               days_covered=m['days_covered'], alerts_high=m['alerts_high'],
               false_positives=m['false_positives'], unreviewed_high=m['unreviewed_high'],
               automatic_actions=m['automatic_actions'],
               active_containment=r.get('active_containment', '—'),
               quarantined_evidence=r.get('quarantined_evidence', '—')))


def daily_text() -> str:
    return tr("Daily summary\n") + _informe() + "\n\n" + _pendientes()


def _ask_model(text: str, cfg: dict) -> str:
    from arx import engine
    from arx.modules import guard

    eng = engine.Engine(cfg)
    if not eng.providers_in_order():
        return tr("No model configured. ") + HELP
    if guard._budget_left(cfg) <= 0:
        return tr("The model query budget for today is used up.")
    guard._spend_budget()
    try:
        return eng.ask([{"role": "user", "content": redact.scrub(text)}], system=guard.SYSTEM_PROMPT)[0]
    except engine.ProviderError:
        return tr("No model provider responded.")


def handle_text(text: str, cfg: dict, now: float | None = None) -> str:
    """La respuesta a un mensaje del dueño. Lo que actúa exige un código válido antes de nada."""
    from arx.modules import response

    parts = text.strip().split()
    if not parts:
        return HELP
    typed = parts[0].split("@")[0].lower()
    cmd = _ALIASES.get(typed, typed)
    args = parts[1:]
    if not cmd.startswith("/"):
        return _ask_model(text, cfg)
    if cmd in ("/start", "/help"):
        return HELP
    if cmd == "/status":
        return _estado()
    if cmd == "/findings":
        return _hallazgos()
    if cmd == "/pending":
        return _pendientes()
    if cmd == "/report":
        return _informe()
    if cmd == "/mute":
        hours = args[0].rstrip("h") if args else ""
        if not (hours.isdigit() and 0 <= int(hours) <= MAX_MUTE_H):
            return tr("Usage: /mute <hours>, up to {MAX_MUTE_H}. /mute 0 turns them back on.",
                      MAX_MUTE_H=MAX_MUTE_H)
        notify.mute(int(hours), now)
        return tr("Non-critical alerts silenced for {hours} h. Critical ones still arrive.",
                  hours=hours) if int(hours) else tr("Alerts on.")
    if cmd not in ("/authorize", "/unlock", "/accept", "/mode"):
        return tr("I don't know that command. ") + HELP
    if len(args) != 2:
        return tr("Usage: {cmd} <{v}> <6-digit code>",
                  cmd=typed, v=tr("account") if cmd == "/unlock" else "id")
    target, code = args
    problem = _check_code(code, now)
    if problem:
        return problem
    response.record({"kind": "telegram_command", "detail": f"{typed} {redact.printable(target)}"})
    if cmd == "/authorize":
        item = response.authorize_pending(target)
        return tr("Authorized: {detail}\n{executed}",
                  detail=item['detail'], executed=item.get('executed', '—')) if item else tr("No pending action with id {target}.",
                                                                                              target=target)
    if cmd == "/unlock":
        done = response.unlock_account(target)
        return tr("Account {target}: {done}", target=target, done=done) if done else tr("Arx has not locked account {target}.",
                                                          target=target)
    if cmd == "/accept":
        msg = response.accept(target)
        return msg or tr("No acceptable finding with id {target}.", target=target)
    if target not in _MODES:
        return tr("Usage: /mode observe|protect <code>")
    set_mode(target)
    return tr("Mode {target}: applies on the next sweep.", target=target)


# ── modo: el servicio arranca con uno; el dueño puede cambiarlo desde el chat ─
def _mode_path():
    return config.state_dir() / "mode.json"


def set_mode(mode: str) -> None:
    config.write_json(_mode_path(), {"mode": mode, "at": time.time()})


def effective_enforce(started_with: bool | None) -> bool:
    mode = config.read_json(_mode_path(), {}).get("mode")
    if mode in _MODES:
        return _MODES[mode]
    return bool(started_with)


# ── bucle ────────────────────────────────────────────────────────────────────
def poll_once(cfg: dict, post=_post, now: float | None = None, timeout: int = POLL_S) -> int:
    """Una ronda de long-polling. Devuelve cuántos mensajes atendió."""
    st = _load()
    res = _api(cfg, "getUpdates", {"offset": st.get("offset", 0), "timeout": timeout, "allowed_updates": ["message"]},
               post, timeout=timeout + 10)
    allowed = str((cfg.get("notify") or {}).get("telegram_chat_id"))
    handled = 0
    for up in res.get("result") or []:
        st = _load()
        st["offset"] = int(up.get("update_id", 0)) + 1  # antes de actuar: un mensaje nunca se atiende dos veces
        _save(st)
        msg = up.get("message") or {}
        chat = (msg.get("chat") or {}).get("id")
        if str(chat) != allowed or not isinstance(msg.get("text"), str):
            continue  # a un desconocido no se le contesta: ni se le confirma que aquí hay un Arx
        try:
            answer = handle_text(msg["text"], config.load_config() or cfg, now)
        except Exception as e:  # un comando roto no puede parar el canal
            answer = tr("Could not handle it ({name}).", name=type(e).__name__)
        _reply(cfg, chat, answer, post)
        handled += 1
    return handled


def loop(cfg: dict) -> None:
    """Para un hilo aparte: nada de lo que pase aquí puede afectar a la defensa local."""
    warned = False
    while True:
        try:
            poll_once(cfg)
        except Conflict:
            if not warned:
                print(tr("  ⚠ Another program is reading this bot's messages: Telegram stays for "
                         "outgoing alerts only."))
                warned = True
            time.sleep(60)
        except Exception:
            time.sleep(15)


# ── asistente de `arx setup` ─────────────────────────────────────────────────
def bot_name(token: str, post=_post, base: str = API) -> str | None:
    try:
        r = post(f"{base}/bot{token}/getMe", {}, timeout=15)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError, Conflict):
        return None
    return (r.get("result") or {}).get("username") if r.get("ok") else None


def detect_chat_id(token: str, post=_post, base: str = API, wait_s: int = 90) -> str | None:
    """Espera el primer mensaje que reciba el bot y devuelve su chat_id."""
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        try:
            r = post(f"{base}/bot{token}/getUpdates", {"timeout": 10, "allowed_updates": ["message"]}, timeout=20)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError, Conflict):
            return None
        for up in reversed(r.get("result") or []):
            chat = ((up.get("message") or {}).get("chat") or {}).get("id")
            if chat is not None:
                return str(chat)
    return None
