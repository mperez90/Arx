"""Arx · notify — alertas salientes (Telegram y webhook genérico).

Sin alertas, "Arx te avisa a las 3 a.m." sería un print en un log. Este módulo manda los
hallazgos NUEVOS (no cada barrido) por los canales que el operador configuró en el setup:

  · Telegram: bot token (secrets.json → `telegram_bot_token`) + chat_id (config). Para gobernar
    Arx desde el chat (modules/telegram.py) el bot debe ser solo suyo: Telegram solo deja a un
    programa leer sus mensajes.
  · Webhook: POST JSON {"source": "arx", "host", "text"} a la URL configurada
    (Slack/Discord/n8n/lo que sea detrás).

Todo pasa por el redactor de secretos antes de salir. Falla-abierto: un canal caído nunca
detiene la defensa. Transporte inyectable para test (sin red).
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request

from arx import __version__, config, redact

SEV_RANK = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}
_ICON = {"crit": "🔴", "high": "🟠", "med": "🟡", "low": "⚪", "info": "⚪"}


def _post(url: str, payload: dict, timeout: int = 15) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"arx/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (URL de config del operador)
        body = r.read().decode() or "{}"
    try:
        return json.loads(body)
    except ValueError:
        return {}


def settings(cfg: dict | None = None) -> dict:
    cfg = cfg if cfg is not None else config.load_config()
    return cfg.get("notify") or {}


def channels(cfg: dict | None = None) -> list[str]:
    n = settings(cfg)
    out = []
    if n.get("telegram_chat_id") and config.load_secrets().get("telegram_bot_token"):
        out.append("telegram")
    if n.get("webhook_url"):
        out.append("webhook")
    return out


def _mute_path():
    return config.state_dir() / "notify_mute.json"


def mute(hours: int, now: float | None = None) -> None:
    now = time.time() if now is None else now
    config.write_json(_mute_path(), {"until": now + hours * 3600})


def muted(now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return now < config.read_json(_mute_path(), {}).get("until", 0)


def send(text: str, cfg: dict | None = None, post=_post) -> dict:
    """Envía `text` (redactado) por todos los canales. Devuelve {canal: ok|error}."""
    n = settings(cfg)
    text = redact.scrub(text)[:3900]  # límite de Telegram: 4096
    host = socket.gethostname()
    results: dict = {}
    for ch in channels(cfg):
        try:
            if ch == "telegram":
                token = config.load_secrets()["telegram_bot_token"]
                post(f"{n.get('telegram_api') or 'https://api.telegram.org'}/bot{token}/sendMessage",
                     {"chat_id": n["telegram_chat_id"], "text": f"🛡 Arx · {host}\n{text}",
                      "disable_web_page_preview": True})
            else:
                post(n["webhook_url"], {"source": "arx", "host": host, "text": text})
            results[ch] = "ok"
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, ValueError) as e:
            # el error puede contener la URL con el token del bot → redactar también
            results[ch] = redact.scrub(f"error: {e}")
    return results


def min_sev(cfg: dict | None = None) -> str:
    return settings(cfg).get("min_sev", "high")


def worth_alerting(sev: str | None, cfg: dict | None = None) -> bool:
    if muted() and sev != "crit":  # /callar: lo crítico llega siempre
        return False
    return SEV_RANK.get(sev or "info", 9) <= SEV_RANK.get(min_sev(cfg), 1)


def format_findings(pairs: list[tuple[dict, dict]], assessment: str | None = None) -> str:
    """Mensaje compacto: hallazgo → qué hizo Arx; y, si lo hay, el análisis del motor."""
    lines = []
    for f, o in pairs:
        lines.append(f"{_ICON.get(f.get('sev'), '•')} {f.get('detail')}")
        lines.append(f"   → Tier {o.get('tier')}: {o.get('status')}")
    if assessment:
        lines += ["", "Análisis:", assessment.strip()]
    return "\n".join(lines)
