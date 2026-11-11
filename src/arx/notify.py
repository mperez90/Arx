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
from arx.i18n import tr

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


RETRY_WAITS = (2, 5)  # VPS real: un «Connection reset by peer» suelto perdía la alerta (B42)


def _deliver(fn, deadline: float | None = None) -> None:
    """Un corte transitorio (reset, timeout, 5xx, 429) se reintenta; un 4xx (token o chat mal), no.

    Con plazo, ni otra espera ni otro intento pueden cruzarlo: el llamador necesita tiempo para
    persistir el resultado antes de que systemd termine su unit.
    """
    for wait in (*RETRY_WAITS, None):
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("notification deadline exceeded")
        try:
            return fn()
        except urllib.error.HTTPError as e:
            if wait is None or (400 <= e.code < 500 and e.code != 429):
                raise
        except (urllib.error.URLError, TimeoutError, OSError):
            if wait is None:
                raise
        if deadline is not None and time.monotonic() + wait >= deadline:
            raise TimeoutError("notification deadline exceeded")
        time.sleep(wait)


def send(text: str, cfg: dict | None = None, post=None, budget_s: float | None = None) -> dict:
    """Envía `text` (redactado) por todos los canales. Devuelve {canal: ok|error}.

    `budget_s` reparte el tiempo restante entre los canales pendientes; el transporte real recibe
    ese resto como timeout de socket. Así un canal lento no deja al siguiente sin intento ni al
    llamador sin margen para escribir la evidencia.
    """
    post = _post if post is None else post
    n = settings(cfg)
    text = redact.scrub(text)[:3900]  # límite de Telegram: 4096
    host = socket.gethostname()
    results: dict = {}
    pending = channels(cfg)
    deadline = time.monotonic() + max(0.0, budget_s) if budget_s is not None else None
    for index, ch in enumerate(pending):
        channel_deadline = None
        if deadline is not None:
            now = time.monotonic()
            channel_deadline = now + max(0.0, deadline - now) / (len(pending) - index)
        try:
            if ch == "telegram":
                token = config.load_secrets()["telegram_bot_token"]
                url = f"{n.get('telegram_api') or 'https://api.telegram.org'}/bot{token}/sendMessage"
                body = {"chat_id": n["telegram_chat_id"], "text": f"🛡 Arx · {host}\n{text}",
                        "disable_web_page_preview": True}
            else:
                url = n["webhook_url"]
                body = {"source": "arx", "host": host, "text": text}

            def attempt():
                if post is _post:
                    timeout = 15
                    if channel_deadline is not None:
                        timeout = max(0.05, min(15, channel_deadline - time.monotonic()))
                    return post(url, body, timeout=timeout)
                return post(url, body)  # transportes inyectados en pruebas conservan su firma

            _deliver(attempt, channel_deadline)
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
        lines += ["", tr("Analysis:"), assessment.strip()]
    return "\n".join(lines)
