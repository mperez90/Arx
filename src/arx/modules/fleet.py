"""Arx · fleet — cliente de flota (Business).

Enrola el host en una consola central y le envía heartbeats + incidentes. Es la base
del tier Business (flota, correlación entre hosts, MDR). Vive en el Core (open) pero
solo se activa con licencia **Business** (`tier_allows("fleet")`); en Core/Pro es inerte.

Doctrina de datos: por defecto Arx no saca telemetría del host. La flota es una
**decisión explícita del cliente Business**; aun así, todo lo que sale pasa por el
redactor de secretos. La consola central es la parte cerrada del producto — este
cliente solo define el protocolo. Transporte inyectable para test (sin red).
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone

from arx import __version__, config, redact
from arx import license as lic
from arx.i18n import tr


def _path():
    return config.state_dir() / "fleet.json"


def _load() -> dict:
    return config.read_json(_path())


def _save(d: dict) -> None:
    config.write_json(_path(), d)


def _post(url: str, headers: dict, payload: dict, timeout: int = 15) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={**headers, "Content-Type": "application/json", "User-Agent": f"arx/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read().decode())


def enabled() -> bool:
    """La flota solo opera con licencia Business."""
    return lic.tier_allows("fleet")


def _auth(st: dict) -> dict:
    return {"Authorization": f"Bearer {st.get('agent_token', '')}"}


def status_summary() -> dict:
    from arx.modules import baseline, response, sensors

    base = baseline.load()
    return {
        "hostname": socket.gethostname(),
        "tier": lic.effective_tier()[0],
        "baseline_sealed": bool(base and base["meta"].get("sealed")),
        "sensors": [k for k, v in sensors.available().items() if v],
        "pending_tier2": len(response.list_pending()),
        "active_blocks": len(response._load_blocks()),
        "watch": config.read_json(config.state_dir() / "watch.json", {}),
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def enroll(console_url: str, token: str, post=_post) -> dict:
    if not enabled():
        return {"ok": False, "reason": tr("the fleet requires a Business license")}
    console_url = console_url.rstrip("/")
    try:
        resp = post(
            f"{console_url}/v1/agents/enroll",
            {"Authorization": f"Bearer {token}"},
            {"hostname": socket.gethostname()},
        )
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "reason": tr("could not reach the console: {e}", e=e)}
    agent_id = resp.get("agent_id")
    if not agent_id:
        return {"ok": False, "reason": tr("the console did not return an agent_id")}
    st = _load()
    st.update({"console_url": console_url, "agent_id": agent_id, "agent_token": resp.get("agent_token", "")})
    _save(st)
    return {"ok": True, "agent_id": agent_id}


def heartbeat(status: dict, post=_post) -> dict:
    st = _load()
    if not (enabled() and st.get("agent_id")):
        return {"ok": False, "reason": tr("not enrolled or no Business license")}
    try:
        post(f"{st['console_url']}/v1/agents/{st['agent_id']}/heartbeat", _auth(st), status)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "reason": str(e)}
    return {"ok": True}


def _scrub_deep(v):
    """Redacta TODOS los campos de texto (detail, why, target, status…), no solo `detail`."""
    if isinstance(v, str):
        return redact.scrub(v)
    if isinstance(v, dict):
        return {k: _scrub_deep(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_scrub_deep(x) for x in v]
    return v


def report(incidents: list[dict], post=_post) -> dict:
    st = _load()
    if not (enabled() and st.get("agent_id")):
        return {"ok": False, "reason": tr("not enrolled or no Business license")}
    # redactar SIEMPRE antes de que nada salga del host
    safe = [_scrub_deep(i) for i in incidents]
    try:
        post(f"{st['console_url']}/v1/agents/{st['agent_id']}/events", _auth(st), {"events": safe})
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "reason": str(e)}
    return {"ok": True, "sent": len(safe)}


def sync(post=_post) -> dict:
    """Heartbeat + últimos incidentes → consola. Para cron o el bucle de guard (Business)."""
    st = _load()
    if not (enabled() and st.get("agent_id")):
        return {"ok": False, "reason": tr("not enrolled or no Business license")}
    heartbeat(status_summary(), post=post)
    events = []
    try:
        for line in (config.state_dir() / "incidents.jsonl").read_text().splitlines()[-50:]:
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
    except OSError:
        pass
    if events:
        report(events, post=post)
    return {"ok": True, "events": len(events)}
