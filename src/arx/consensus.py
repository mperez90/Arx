"""Arx · consensus — votos firmados entre nodos y su recuento (Pro/Business votan; todos reciben).

Una propuesta (una vacuna candidata) solo sale por el canal automático si la valida, cada uno en su
propio host, una supermayoría de organizaciones con licencia de pago. Lo que hace segura la cuenta:

  · Votan nodos Pro/Business, cada uno con una llave propia ligada a su licencia; se cuenta por
    organización, no por equipo: un cliente con 500 hosts no decide solo.
  · Más de 2/3 de las organizaciones que votan, no el 51 %. El atacante vota siempre y los honestos
    no todos: con el 51 % y poca participación, una minoría decidida gana.
  · Quórum: un mínimo de organizaciones y una fracción de las que podrían votar.
  · Licencias con antigüedad, redes distintas entre las que aprueban (la red de cada nodo se fija al
    darlo de alta y va en la lista firmada), y una ventana de tiempo: los votos no se compran de un día
    para otro ni se meten todos de golpe.
  · Un voto «hostil» manda la propuesta a una persona, si trae evidencia comprobable y su organización
    no ha agotado su cupo de vetos (que nadie bloquee todo vetándolo todo).
  · El servidor no es de fiar: el paquete automático lleva los votos firmados y cada Arx repite el
    recuento con la lista de votantes que firma la clave maestra (offline), no con la del servidor.

Votar es validar: el nodo pasa la propuesta por `vaccines.validate`, que no ejecuta nada. Del host
sale el veredicto y nada más (la razón no: podría nombrar ficheros del host). Lo de arriba de
`participate` es puro, sin red ni host: lo usan igual el agente y el servidor de recuento.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
from datetime import datetime, timedelta, timezone

from arx import ed25519

SUPERMAJORITY = (2, 3)        # estrictamente más de 2/3 de las organizaciones que votan
MIN_ORGS = 5
MIN_PARTICIPATION = 0.2       # de las organizaciones que podrían votar
MIN_NETWORKS = 3              # redes distintas entre las organizaciones que aprueban
MIN_LICENSE_DAYS = 30
MIN_OPEN_H = 6                # antes no se cierra: los nodos lentos también votan, y pueden vetar
MAX_OPEN_DAYS = 7
CLOCK_SKEW_S = 300
VERDICTS = ("valid", "insufficient", "hostile")
EVIDENCE = ("structure", "host_binary")  # lo que cualquiera comprueba con la propia propuesta
VETO_BUDGET = 3               # vetos con evidencia por organización en la ventana máxima
VOTING_TIERS = ("pro", "business")
PARTICIPATE_EVERY_S = 6 * 3600  # así cada nodo pasa al menos una vez por la ventana mínima
MAX_PROPOSALS = 20
MAX_BYTES = 2 * 1024 * 1024


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse(s) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(s))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── sellar y abrir ───────────────────────────────────────────────────────────
def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def seal(obj: dict, secret: bytes) -> dict:
    """El receptor verifica estos bytes exactos ANTES de interpretar nada de su contenido."""
    payload = canonical(obj)
    return {"payload": base64.b64encode(payload).decode(), "sig": ed25519.sign(secret, payload).hex()}


def unseal(sealed, public_hex: str) -> dict | None:
    """El contenido si la firma es de `public_hex`; si no, None y no se interpreta nada."""
    try:
        if isinstance(sealed, (bytes, str)):
            sealed = json.loads(sealed)
        payload = base64.b64decode(sealed["payload"], validate=True)
        signature = bytes.fromhex(sealed["sig"])
        public = bytes.fromhex(public_hex)
    except (ValueError, KeyError, TypeError):
        return None
    if not ed25519.verify(public, payload, signature):
        return None
    try:
        obj = json.loads(payload)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def proposal_id(vaccine: dict) -> str:
    """El id lo calcula cada uno a partir del contenido: nadie vota una cosa creyendo votar otra."""
    return hashlib.sha256(canonical(vaccine)).hexdigest()


# ── votar ────────────────────────────────────────────────────────────────────
def _structural(vaccine: dict) -> bool:
    """Hostil sin mirar ningún host: lo comprueba cualquiera, el servidor y cada Arx."""
    from arx.modules.vaccines import validate
    try:
        return validate(vaccine, samples=[])[0] == "hostile"
    except Exception:
        return True


def _evidence(vaccine: dict) -> dict | None:
    """Por qué es hostil, con algo que está en la propia propuesta (nada más del host)."""
    if _structural(vaccine):
        return {"code": "structure"}
    from arx.modules.vaccines import _host_samples
    marked = set((vaccine.get("iocs") or {}).get("sha256") or [])
    mine = sorted(marked & {sha for _, _, sha in _host_samples()})
    return {"code": "host_binary", "item": mine[0]} if mine else None


def make_vote(vaccine: dict, secret: bytes, now: datetime, validate=None, evidence=None) -> dict:
    """El voto sellado de este nodo sobre `vaccine`, validada aquí mismo."""
    if validate is None:
        from arx.modules.vaccines import validate
    try:
        verdict = validate(vaccine)[0]
    except Exception:  # lo que ni siquiera se deja validar no es válido
        verdict = "hostile"
    node = ed25519.public_key(secret).hex()
    body = {"v": 1, "proposal": proposal_id(vaccine), "verdict": verdict, "node": node, "at": _iso(now)}
    if verdict == "hostile":
        try:
            ev = (evidence or _evidence)(vaccine)
        except Exception:
            ev = None
        if ev:
            body["evidence"] = ev
    return {"node": node, **seal(body, secret)}


def _valid_evidence(ev, vaccine: dict, structural) -> bool:
    if not isinstance(ev, dict) or ev.get("code") not in EVIDENCE:
        return False
    if ev["code"] == "structure":
        return structural(vaccine)
    return ev.get("item") in ((vaccine.get("iocs") or {}).get("sha256") or [])


def _vetoes_spent(org: str, pid: str, proof, registry: dict, opened: datetime, now: datetime) -> int:
    """Vetos con evidencia que esta organización ya usó en OTRAS propuestas, demostrados con sus votos
    firmados: el servidor no puede inventarse que alguien agotó su cupo para callarle."""
    seen = set()
    for vote in proof or []:
        node = vote.get("node") if isinstance(vote, dict) and isinstance(vote.get("node"), str) else ""
        reg = registry.get(node)
        if not reg or reg.get("org") != org:
            continue
        body = unseal(vote, node)
        at = _parse((body or {}).get("at"))
        if body and body.get("node") == node and body.get("verdict") == "hostile" and body.get("evidence") \
                and body.get("proposal") not in (pid, None) and at \
                and opened - timedelta(days=MAX_OPEN_DAYS) <= at <= now + timedelta(seconds=CLOCK_SKEW_S):
            seen.add(body["proposal"])
    return len(seen)


# ── contar ───────────────────────────────────────────────────────────────────
def _voter(reg: dict | None, now: datetime) -> str | None:
    """Por qué este nodo no vota (o None si vota)."""
    if not isinstance(reg, dict):
        return "unregistered"
    if not reg.get("active") or reg.get("tier") not in VOTING_TIERS or not reg.get("org"):
        return "no paid license"
    since = _parse(reg.get("licensed_since"))
    if not since or now - since < timedelta(days=MIN_LICENSE_DAYS):
        return "license too recent"
    return None


def tally(proposal: dict, votes: list, registry: dict, eligible_orgs: int, now: datetime,
          veto_proof: dict | None = None, structural=None) -> dict:
    """Estado de una propuesta: pending, consensus, escalate (a una persona) o expired.

    `votes`: [{"vote": voto sellado, "network": red desde la que llegó, según el servidor (no cuenta)}].
    `registry`: llave pública del nodo → {"org", "tier", "licensed_since", "active", "network"}.
    `veto_proof`: organización → sus votos hostiles firmados en otras propuestas (cupo agotado)."""
    pid = proposal.get("id")
    opened = _parse(proposal.get("opened"))
    vaccine = proposal.get("vaccine") or {}
    structural = structural or _structural
    out = {"state": "pending", "orgs": 0, "valid": 0, "hostile": 0, "networks": 0, "quorum": 0,
           "ignored": {}, "vetoes_spent": 0, "why": ""}
    if not pid or pid != proposal_id(vaccine) or not opened:
        return {**out, "state": "escalate", "why": "malformed proposal"}
    closes = opened + timedelta(days=MAX_OPEN_DAYS)
    latest = {}
    for item in votes:
        vote = (item or {}).get("vote") or {}
        node = vote.get("node") if isinstance(vote.get("node"), str) else ""
        reg = registry.get(node)
        why = _voter(reg, now)
        body = None if why else unseal(vote, node)
        if not why and body is None:
            why = "bad signature"
        if not why and (body.get("node") != node or body.get("proposal") != pid
                        or body.get("verdict") not in VERDICTS):
            why = "malformed vote"
        at = _parse(body.get("at")) if not why else None
        if not why and (not at or at < opened or at > min(now, closes) + timedelta(seconds=CLOCK_SKEW_S)):
            why = "outside the window"
        if why:
            out["ignored"][why] = out["ignored"].get(why, 0) + 1
            continue
        verdict = body["verdict"]
        if verdict == "hostile" and not _valid_evidence(body.get("evidence"), vaccine, structural):
            out["ignored"]["hostile without evidence"] = out["ignored"].get("hostile without evidence", 0) + 1
            verdict = "insufficient"  # no aprueba, pero tampoco veta
        if node not in latest or at >= latest[node][0]:  # vale el último voto de cada nodo
            # la red es la del roster (verificada al dar de alta y firmada offline), no la que diga el servidor
            latest[node] = (at, verdict, reg["org"], str(reg.get("network") or ""))
    orgs = {}
    for _, verdict, org, net in latest.values():
        orgs.setdefault(org, []).append((verdict, net))
    approving_nets = set()
    for org, ballots in orgs.items():
        verdicts = [v for v, _ in ballots]
        if "hostile" in verdicts and \
                _vetoes_spent(org, pid, (veto_proof or {}).get(org), registry, opened, now) >= VETO_BUDGET:
            out["vetoes_spent"] += 1
            verdicts = ["insufficient" if v == "hostile" else v for v in verdicts]
        if "hostile" in verdicts:  # un host al que la propuesta le parece hostil basta para dudar
            out["hostile"] += 1
        elif verdicts.count("valid") * 2 > len(verdicts):
            out["valid"] += 1
            approving_nets.update(n for v, n in zip(verdicts, (n for _, n in ballots)) if v == "valid" and n)
    n = out["orgs"] = len(orgs)
    out["networks"] = len(approving_nets)
    out["quorum"] = quorum = max(MIN_ORGS, math.ceil(MIN_PARTICIPATION * max(eligible_orgs, 0)))
    a, b = SUPERMAJORITY
    if out["hostile"]:
        return {**out, "state": "escalate", "why": "a voter found it hostile"}
    if now >= closes:
        return {**out, "state": "expired", "why": "no consensus within the window"}
    if now - opened < timedelta(hours=MIN_OPEN_H):
        return {**out, "why": "minimum voting time not reached"}
    if n < quorum:
        return {**out, "why": "quorum not reached"}
    if out["valid"] * b <= a * n:
        return {**out, "why": "no supermajority"}
    if out["networks"] < MIN_NETWORKS:
        return {**out, "why": "approvals come from too few networks"}
    return {**out, "state": "consensus", "why": "supermajority of organizations"}


def verify_item(item: dict, roster: dict, now: datetime) -> tuple[dict | None, str]:
    """Lo que hace cada Arx con una vacuna del canal automático: repetir el recuento él mismo, con la
    lista de votantes que firmó la clave maestra. (vacuna, "") si hubo consenso de verdad."""
    vaccine = item.get("vaccine") if isinstance(item, dict) else None
    opened, closed = _parse((item or {}).get("opened")), _parse((item or {}).get("closed"))
    if not isinstance(vaccine, dict) or not opened or not closed:
        return None, "malformed item"
    if closed > now + timedelta(seconds=CLOCK_SKEW_S) or not opened <= closed <= opened + timedelta(days=MAX_OPEN_DAYS):
        return None, "impossible dates"
    eligible = len({r.get("org") for r in roster.values() if isinstance(r, dict) and not _voter(r, closed)})
    t = tally({"id": proposal_id(vaccine), "opened": item["opened"], "vaccine": vaccine},
              item.get("votes") if isinstance(item.get("votes"), list) else [], roster, eligible, closed,
              item.get("veto_proof") if isinstance(item.get("veto_proof"), dict) else None)
    return (vaccine, "") if t["state"] == "consensus" else (None, t["why"] or t["state"])


# ── el nodo: llave propia y participación (Pro/Business) ─────────────────────
def _key_path():
    from arx import config
    return config.state_dir() / "node.key"


def node_secret() -> bytes:
    """La llave del nodo: se crea una vez (0600) y nunca sale del host."""
    path = _key_path()
    try:
        with open(path, encoding="ascii") as f:
            return bytes.fromhex(f.read().strip())
    except FileNotFoundError:
        pass
    secret = os.urandom(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # otro hilo la creó a la vez: vale la suya
        return node_secret()
    with os.fdopen(fd, "w") as f:
        f.write(secret.hex() + "\n")
    return secret


def _state_path():
    from arx import config
    return config.state_dir() / "consensus.json"


def _load() -> dict:
    from arx import config
    st = config.read_json(_state_path(), {})
    return st if isinstance(st, dict) else {}


def _save(st: dict) -> None:
    from arx import config
    config.write_json(_state_path(), st)


def enabled(cfg: dict) -> bool:
    from arx import license
    return bool(cfg.get("consensus_url")) and license.tier_allows("consensus")


def due(cfg: dict, now: datetime | None = None) -> bool:
    if not enabled(cfg):
        return False
    last = _parse(_load().get("last_run"))
    return last is None or ((now or datetime.now(timezone.utc)) - last).total_seconds() >= PARTICIPATE_EVERY_S


def _http(method: str, url: str, body: dict | None = None, timeout: int = 20) -> dict:
    import urllib.request
    from arx import __version__
    data = canonical(body) if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "User-Agent": f"arx/{__version__}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (URL de la configuración)
        raw = r.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("response too large")
    out = json.loads(raw or b"{}")
    return out if isinstance(out, dict) else {}


def _register(url: str, secret: bytes, http) -> bool:
    """Liga la llave del nodo a su licencia. El servidor comprueba la licencia con Polar."""
    from arx import license
    lic = license.load()
    if not lic.get("key") or not lic.get("activation_id"):
        return False
    node = ed25519.public_key(secret).hex()
    claim = {"node": node, "activation_id": lic["activation_id"]}
    resp = http("POST", f"{url}/v1/register", {**seal(claim, secret), "node": node,
                                               "license_key": lic["key"]})
    return resp.get("registered") is True


def participate(cfg: dict, http=_http, now: datetime | None = None, validate=None) -> dict:
    """Valida aquí las propuestas abiertas y manda el voto firmado de cada una. Nunca bloquea nada."""
    now = now or datetime.now(timezone.utc)
    url = str(cfg.get("consensus_url") or "").rstrip("/")
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1"):
        return {"ok": False, "reason": "consensus_url must be https"}
    secret = node_secret()
    st = _load()
    st["last_run"] = _iso(now)
    _save(st)
    if not st.get("registered"):
        if not _register(url, secret, http):
            return {"ok": False, "reason": "not registered"}
        st["registered"] = _iso(now)
    voted = st.setdefault("voted", {})
    proposals = http("GET", f"{url}/v1/proposals").get("proposals") or []
    sent = 0
    for p in proposals[:MAX_PROPOSALS]:
        vaccine = p.get("vaccine") if isinstance(p, dict) else None
        if not isinstance(vaccine, dict):
            continue
        pid = proposal_id(vaccine)
        if pid in voted:
            continue
        http("POST", f"{url}/v1/votes", make_vote(vaccine, secret, now, validate))
        voted[pid] = _iso(now)
        sent += 1
    cutoff = now - timedelta(days=MAX_OPEN_DAYS + 1)
    st["voted"] = {k: v for k, v in voted.items() if (_parse(v) or now) >= cutoff}
    _save(st)
    return {"ok": True, "voted": sent}


def participate_safely(cfg: dict) -> None:
    """Para el hilo de guardia: sin red o sin servidor, la defensa local sigue igual."""
    try:
        participate(cfg)
    except Exception as e:
        from arx.modules import response
        response.record({"kind": "consensus_error", "detail": type(e).__name__})
