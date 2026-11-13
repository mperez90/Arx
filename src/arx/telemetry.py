"""Arx · programa de mejora: informes de uso anónimos, solo con el permiso del dueño.

Nada sale sin un «sí» explícito: en la instalación con una terminal delante, en `arx setup` o con
`arx telemetry enable`. Sin respuesta no se envía nada. `ARX_TELEMETRY=off` o `DO_NOT_TRACK=1`
lo apagan por encima de todo.

Qué se envía: exactamente lo que imprime `arx telemetry show`. Solo cifras y valores de una lista
cerrada: versión, distribución, núcleo, arquitectura, modo, salud de los vigilantes y contadores de
ruido. Nunca nombres de host, IPs, rutas, usuarios, comandos, hallazgos en texto, claves ni
configuración. El saneado final descarta todo texto que no sea un identificador corto y cualquier
valor que parezca una IP o el nombre del host, aunque un error futuro lo colara.

El identificador de instalación es aleatorio: nace con el «sí» y se borra con el «no». El recolector
propone la cadencia (1–30 días, 7 por defecto); el contenido solo cambia con una versión de Arx.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import platform
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from arx import __version__, config
from arx.i18n import lang, tr

ENDPOINT = "https://telemetry.adsyslabs.com/v1/report"
SCHEMA = 1
INTERVAL_DAYS = 7
MIN_DAYS, MAX_DAYS = 1, 30
FIRST_DELAY_S = 86400   # el primer informe, tras un día de guardia: antes no hay nada que contar
RETRY_S = 6 * 3600      # un envío fallido se reintenta, como mucho, cada 6 h
TIMEOUT_S = 10
MAX_DEPTH = 4
HEALTH_KINDS = ("self_down", "self_stopped", "self_tamper", "self_check_unavailable")
_KEY = re.compile(r"[a-z0-9_]{1,40}")
_TEXT = re.compile(r"[A-Za-z0-9._+:-]{0,40}")
_DROP = object()
_lock = threading.Lock()


# ── permiso ──────────────────────────────────────────────────────────────────
def env_off() -> bool:
    return (os.environ.get("ARX_TELEMETRY", "").strip().lower() in ("0", "off", "no", "false", "never")
            or os.environ.get("DO_NOT_TRACK", "").strip() not in ("", "0"))


def consent(cfg: dict | None = None) -> str | None:
    cfg = config.load_config() if cfg is None else cfg
    value = (cfg.get("telemetry") or {}).get("consent")
    return value if value in ("yes", "no") else None


def enabled(cfg: dict | None = None) -> bool:
    return bool(ENDPOINT) and consent(cfg) == "yes" and not env_off()


def decide(yes: bool, current: dict | None = None) -> dict:
    """El registro de la decisión. Con «no» se olvida el identificador: volver a entrar da otro."""
    rec = dict(current or {})
    rec["consent"] = "yes" if yes else "no"
    rec["decided_at"] = datetime.now(timezone.utc).date().isoformat()
    if yes:
        if not re.fullmatch(r"[0-9a-f]{32}", str(rec.get("install_id", ""))):
            rec["install_id"] = secrets.token_hex(16)
    else:
        rec.pop("install_id", None)
    return rec


def set_consent(yes: bool) -> dict:
    with config.locked("telemetry"):
        cfg = config.load_config()
        cfg["telemetry"] = decide(yes, cfg.get("telemetry"))
        config.save_config(cfg)
    if not yes:
        forget_state()
    return cfg["telemetry"]


def _state_path() -> Path:
    return config.state_dir() / "telemetry.json"


def forget_state() -> None:
    try:
        _state_path().unlink()
    except OSError:
        pass


def _clamp(days) -> int:
    try:
        return max(MIN_DAYS, min(MAX_DAYS, int(days)))
    except (TypeError, ValueError):
        return INTERVAL_DAYS


# ── el informe ───────────────────────────────────────────────────────────────
def _os_release() -> dict:
    out = {}
    try:
        for line in Path("/etc/os-release").read_text(errors="replace").splitlines():
            k, _, v = line.partition("=")
            if k in ("ID", "VERSION_ID"):
                out[k] = v.strip().strip('"')
    except OSError:
        pass
    return {"os": out.get("ID") or sys.platform, "os_version": out.get("VERSION_ID")}


def _platform() -> dict:
    kernel = ".".join(platform.release().split(".")[:2]).split("-")[0]
    return {**_os_release(), "kernel": kernel, "arch": platform.machine(),
            "python": "{}.{}".format(*sys.version_info[:2]),
            "systemd": Path("/run/systemd/system").is_dir(), "lang": lang()}


def _setup(cfg: dict) -> dict:
    from arx import license as lic
    from arx import notify
    from arx.modules import baseline, guard

    seen = guard.mode_seen()
    base = baseline.load()
    n = cfg.get("notify") or {}
    chans = notify.channels(cfg)
    return {"configured": bool(cfg),
            "tier": lic.effective_tier()[0], "llm_providers": len(cfg.get("providers") or {}),
            "telegram": "telegram" in chans, "webhook": "webhook" in chans,
            "telegram_control": bool(n.get("telegram_interactive")),
            "mode": "none" if seen is None else "enforce" if seen else "observe",
            "baseline_sealed": bool(base and base["meta"].get("sealed")),
            "ip_response": cfg.get("ip_response", "block"),
            "llm_identity_actions": cfg.get("llm_identity_actions") is not False}


def _watch() -> dict:
    from arx.modules import sensors

    w = config.read_json(config.state_dir() / "watch.json", {})
    proc = w.get("process") or {}
    cap = proc.get("capture") or {}
    files = w.get("sensitive_files") or {}
    sens = sensors.available()
    return {"process": proc.get("mode") or "unknown", "netlink_lost": proc.get("lost", 0),
            "exec_capture": cap.get("mode") or "unknown",
            "exec_marks": len(cap.get("marks") or ()), "exec_marks_failed": len(cap.get("failed") or ()),
            **{f"exec_{k}": cap.get(k, 0) for k in ("captured", "dropped", "expired", "overflow", "late",
                                                    "errors")},
            "files": files.get("mode") or "unknown",
            "files_marks": len(files.get("marks") or ()), "files_marks_failed": len(files.get("failed") or ()),
            **{f"files_{k}": files.get(k, 0) for k in ("overflow", "late", "errors")},
            "auditd": bool(sens.get("auditd")), "osquery": bool(sens.get("osquery")),
            "falco": bool(sens.get("falco"))}


def _noise(days: int) -> dict:
    from arx.modules import metrics

    m = metrics.compute(days)
    keep = ("days_covered", "findings_new", "alerts_high", "false_positives", "unreviewed_high",
            "automatic_actions", "accounts_locked_by_model", "high_by_kind", "within_target")
    return {k: m.get(k) for k in keep}


def _health(days: int, now: float | None = None) -> dict:
    from arx.modules import metrics

    since = (time.time() if now is None else now) - days * 86400
    out = {k: 0 for k in HEALTH_KINDS}
    restarts: dict[str, int] = {}
    delivery: dict[str, dict[str, int]] = {}
    for e in metrics._events():
        t = metrics._when(e)
        if t is None or t.timestamp() < since:
            continue
        kind = e.get("kind")
        if kind in out:
            out[kind] += 1
        if kind == "self_down":
            state = str(e.get("restart_state") or "unknown")
            restarts[state] = restarts.get(state, 0) + 1
        if kind == "notify_result" and isinstance(e.get("results"), dict):
            for ch, r in e["results"].items():
                d = delivery.setdefault(str(ch), {"ok": 0, "failed": 0})
                d["ok" if r == "ok" else "failed"] += 1
    return {**out, "restart_state": restarts, "alert_delivery": delivery}


def _counts() -> dict:
    from arx.modules import canaries, proposals, response, vaccines

    return {"canaries": len(canaries._load().get("canaries", [])),
            "vaccines": len(vaccines._load().get("applied") or {}),
            "proposals": len(proposals.all_proposals()),
            "blocks": len(response._load_blocks()), "findings_known": len(response.load_findings()),
            "pending_tier2": len(response.list_pending()), "quarantine": len(response.list_quarantine()),
            "locked_accounts": len(response.locked_accounts()), "breaker": bool(response.breaker_tripped())}


def _section(fn, *args) -> dict:
    try:
        return fn(*args)
    except Exception:  # un colector roto deja su sección vacía, nunca el informe sin enviar ni el guardián
        return {"error": True}


def build(cfg: dict | None = None, now: float | None = None) -> dict:
    cfg = config.load_config() if cfg is None else cfg
    days = _clamp(config.read_json(_state_path(), {}).get("interval_days", INTERVAL_DAYS))
    report = {"schema": SCHEMA, "install_id": (cfg.get("telemetry") or {}).get("install_id"),
              "arx": __version__, "period_days": days, **_section(_platform),
              "setup": _section(_setup, cfg), "watch": _section(_watch), "noise": _section(_noise, days),
              "health": _section(_health, days, now), "counts": _section(_counts)}
    return sanitize(report)


def _host_names() -> set[str]:
    try:
        host = socket.gethostname().lower()
    except OSError:
        return set()
    return {h for h in (host, host.split(".")[0]) if h}


def _forbidden(text: str, hosts: set[str]) -> bool:
    if not _TEXT.fullmatch(text) or text.lower() in hosts:
        return True
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def sanitize(obj, depth: int = 0, hosts: set[str] | None = None):
    """Solo sobrevive lo que es una cifra, un booleano o un identificador corto. Lo demás desaparece."""
    hosts = _host_names() if hosts is None else hosts
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return round(obj, 3) if math.isfinite(obj) else None
    if isinstance(obj, str):
        return _DROP if _forbidden(obj, hosts) else obj
    if isinstance(obj, dict) and depth < MAX_DEPTH:
        out = {}
        for k, v in obj.items():
            if not (isinstance(k, str) and _KEY.fullmatch(k)) or k in hosts:
                continue
            clean = sanitize(v, depth + 1, hosts)
            if clean is not _DROP:
                out[k] = clean
        return out
    return _DROP


# ── el envío ─────────────────────────────────────────────────────────────────
def due(now: float | None = None, cfg: dict | None = None) -> bool:
    if not enabled(cfg):
        return False
    now = time.time() if now is None else now
    st = config.read_json(_state_path(), {})
    if "since" not in st:  # desde que hay permiso y guardián: el primer informe espera un día
        st["since"] = now
        config.write_json(_state_path(), st)
        return False
    if now - st.get("last_attempt", 0) < RETRY_S:
        return False
    if st.get("last_sent"):
        return now - st["last_sent"] >= _clamp(st.get("interval_days", INTERVAL_DAYS)) * 86400
    return now - st["since"] >= FIRST_DELAY_S


def _post(url: str, body: dict) -> dict:
    if not url.startswith("https://"):
        raise ValueError("the improvement program only reports over https")
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": f"arx/{__version__}"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:  # noqa: S310 (URL fija, https)
        raw = r.read(4096)
    try:
        reply = json.loads(raw or b"{}")
    except ValueError:
        return {}
    return reply if isinstance(reply, dict) else {}


def send(cfg: dict | None = None, now: float | None = None, post=None) -> str:
    """Envía un informe. Nunca lanza: devuelve «ok», «disabled», «busy» o «error: <tipo>»."""
    if not enabled(cfg):
        return "disabled"
    if not _lock.acquire(blocking=False):
        return "busy"
    try:
        now = time.time() if now is None else now
        st = config.read_json(_state_path(), {})
        st.setdefault("since", now)
        st["last_attempt"] = now
        config.write_json(_state_path(), st)
        try:
            reply = (post or _post)(ENDPOINT, build(cfg, now))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            result = f"error: {type(e).__name__}"
        else:
            result = "ok"
            st["last_sent"] = now
            interval = reply.get("interval_days") if isinstance(reply, dict) else None
            if isinstance(interval, int) and not isinstance(interval, bool):
                st["interval_days"] = _clamp(interval)
        st["last_result"] = result
        config.write_json(_state_path(), st)
        return result
    finally:
        _lock.release()


def send_safely() -> None:
    try:
        send()
    except Exception:
        pass  # el programa de mejora nunca molesta a la defensa


# ── consola ──────────────────────────────────────────────────────────────────
def _when(ts) -> str:
    if not ts:
        return tr("never")
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _explain() -> None:
    print(tr("  Arx would send an anonymous report every few days: its version, the system "
             "(distribution,\n  kernel, architecture), how its watchers are doing and how much "
             "noise it makes. Never host\n  names, IPs, paths, users, commands, findings or "
             "secrets. See it exactly:  arx telemetry show"))


def ask() -> int:
    """La pregunta del instalador: una sola vez, solo con una terminal delante; sin respuesta, «no»."""
    if consent() is not None or env_off() or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return 0
    print(tr("\n▸ Arx improvement program (optional)"))
    _explain()
    try:
        answer = input(tr("  Join? (y/N): ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if answer in ("y", "yes", "s", "si", "sí"):
        set_consent(True)
        print(tr("  ✓ Thank you. Leave whenever you want:  arx telemetry disable"))
    else:
        set_consent(False)
        print(tr("  Nothing will be sent. Join later with:  arx telemetry enable"))
    return 0


def status() -> int:
    c = consent()
    st = config.read_json(_state_path(), {})
    print(tr("\n▸ Arx: improvement program"))
    print(tr("  joined         {v}", v={"yes": tr("yes"), "no": "no"}.get(c, tr("not decided (nothing is sent)"))))
    print(tr("  reports to     {url}", url=ENDPOINT))
    print(tr("  every          {n} days", n=_clamp(st.get("interval_days", INTERVAL_DAYS))))
    if c == "yes":
        print(tr("  last report    {when}  {result}", when=_when(st.get("last_sent")),
                 result=st.get("last_result", "")))
    if env_off():
        print(tr("  ⚠ ARX_TELEMETRY=off or DO_NOT_TRACK is set: nothing is sent."))
    print(tr("  See exactly what would be sent:  arx telemetry show\n"))
    return 0


def run(action: str = "status") -> int:
    if action == "show":
        print(json.dumps(build(), ensure_ascii=False, indent=1, sort_keys=True))
        if not enabled():
            print(tr("(not sent: you have not joined the improvement program)"), file=sys.stderr)
        return 0
    if action == "enable":
        rec = set_consent(True)
        print(tr("✓ Joined. Arx will send an anonymous report every {n} days (installation id {id}…).",
                 n=_clamp(config.read_json(_state_path(), {}).get("interval_days", INTERVAL_DAYS)),
                 id=rec["install_id"][:8]))
        print(tr("  See it:  arx telemetry show   ·   leave:  arx telemetry disable"))
        if env_off():
            print(tr("  ⚠ ARX_TELEMETRY=off or DO_NOT_TRACK is set: nothing is sent."))
        return 0
    if action == "disable":
        set_consent(False)
        print(tr("✓ Done: nothing else will be sent, and the installation id was deleted."))
        return 0
    if action == "send":
        if not enabled():
            print(tr("Nothing sent: you have not joined. Join with:  arx telemetry enable"))
            return 1
        result = send()
        print(("✓ " if result == "ok" else "⚠ ") + result)
        return 0 if result == "ok" else 1
    if action == "ask":
        return ask()
    return status()
