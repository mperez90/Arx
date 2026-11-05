"""Arx · vaccines — canal de vacunas firmado y validado en cada receptor (F17, promesa Core).

Lo que un ataque enseña a un Arx debe proteger a todos, también a los gratuitos (§12.3). Y una
vacuna que llega de fuera es potencialmente hostil hasta demostrar lo contrario (§12.4), porque un
canal así es exactamente lo que un atacante querría controlar:

  · Firma Ed25519 de ASL, clave offline. Sin firma válida, el paquete se descarta SIN ABRIRLO.
  · Serial creciente: repetir un paquete antiguo no deshace una retirada.
  · Validación local: cada Arx la comprueba por sí mismo antes de aplicarla. En Core nada se ejecuta
    (D7): una vacuna son DATOS, y su prueba es declarativa. Una regla debe detectar sus muestras, no
    disparar con sus negativos, aportar algo que hoy no se detecta y no casar con binarios del host.
    Resultado: válida, insuficiente u hostil, con la razón.
  · Despliegue escalonado, retirada firmada y retirada automática si el operador la desmiente.

Fail-open: sin red, sin clave o sin canal, la defensa local sigue igual. Del host no sale nada: es
una descarga y nada más. Lo que se comparte, solo a mano (`arx forensics --indicators`).
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from arx import __version__, config, ed25519
from arx.modules import recon, response, sandbox, sensors
from arx.redact import printable

FEED_URL = "https://raw.githubusercontent.com/mperez90/Arx/vaccines/feed.signed.json"
# Clave pública de ASL (hex). La privada vive offline. Vacía: el canal aún no está abierto.
ASL_PUBKEY = ""

UPDATE_EVERY_S = 86400
MAX_FEED_BYTES = 2 * 1024 * 1024
MAX_NEW_PER_UPDATE = 20      # anti-abuso: un canal comprometido no reescribe el host de golpe
MAX_IPS = 5000
MAX_HASHES = 20000
MAX_RULES = 50
MAX_SAMPLE = 4096
FP_ROLLBACK = 3              # desmentida tantas veces por el operador, se retira sola
HOST_SWEEP_BUDGET_S = 5.0
HOST_SWEEP_FILES = 200
HOST_SWEEP_READ = 128 * 1024
HOST_BIN_DIRS = ("/usr/bin", "/usr/sbin")

_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_QUANT_RE = re.compile(r"\{(\d{1,4})(,(\d{1,4})?)?\}")


def _path():
    return config.state_dir() / "vaccines.json"


def _load() -> dict:
    return config.read_json(_path(), {}) or {}


def _save(st: dict) -> None:
    config.write_json(_path(), st)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(s) -> datetime | None:
    try:
        return datetime.fromisoformat(str(s))
    except ValueError:
        return None


# ── abrir el paquete: primero la firma, después todo lo demás ─────────────────
def open_feed(raw: bytes, pubkey: str) -> dict | None:
    """El contenido del paquete si la firma es válida; si no, None y no se interpreta nada."""
    try:
        outer = json.loads(raw)
        payload = base64.b64decode(outer["payload"], validate=True)
        signature = bytes.fromhex(outer["sig"])
        public = bytes.fromhex(pubkey)
    except (ValueError, KeyError, TypeError):
        return None
    if not ed25519.verify(public, payload, signature):
        return None
    try:
        feed = json.loads(payload)
    except ValueError:
        return None
    return feed if isinstance(feed, dict) else None


# ── validación local: cada receptor comprueba por sí mismo ────────────────────
def _unsafe_regex(pattern: str) -> str | None:
    """Por qué esta regex podría colgar a Arx. Estas reglas corren en el bucle de guardia sobre
    ficheros que controla el atacante: solo cuantificadores acotados y nunca sobre un grupo."""
    if len(pattern) > 500:
        return "demasiado larga"
    i, in_class, after_group = 0, False, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            if pattern[i + 1:i + 2].isdigit():
                return "referencia atrás"
            i, after_group = i + 2, False
            continue
        if in_class:
            in_class = c != "]"
            i += 1
            continue
        if c == "[":
            in_class, after_group = True, False
            i += 2 if pattern[i + 1:i + 2] in ("]", "^") else 1
            continue
        if c in "*+":
            return "cuantificador sin límite"
        if c == "(" and pattern[i + 1:i + 2] == "?" and pattern[i + 2:i + 3] != ":":
            return "construcción no permitida"
        if c == "{" and (m := _QUANT_RE.match(pattern, i)):
            if m.group(2) and not m.group(3):
                return "cuantificador sin límite"
            if int(m.group(3) or m.group(1)) > 1024:
                return "cuantificador demasiado grande"
            if after_group:
                return "cuantificador sobre un grupo"
            i, after_group = m.end(), False
            continue
        if c == "?" and after_group:
            return "cuantificador sobre un grupo"
        after_group = c == ")"
        i += 1
    if in_class:
        return "clase sin cerrar"
    try:
        re.compile(pattern)
    except re.error as e:
        return f"no compila: {e}"
    return None


def _host_samples() -> list[tuple[str, bytes, str]]:
    """Binarios reales del host: (ruta, inicio del fichero, sha256), con presupuesto de tiempo."""
    out = []
    deadline = time.monotonic() + HOST_SWEEP_BUDGET_S
    for d in HOST_BIN_DIRS:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names[:HOST_SWEEP_FILES // len(HOST_BIN_DIRS)]:
            if time.monotonic() > deadline:
                return out
            path = os.path.join(d, name)
            try:
                if not os.path.isfile(path) or os.path.getsize(path) > 16 * 1024 * 1024:
                    continue
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            out.append((path, data[:HOST_SWEEP_READ], hashlib.sha256(data).hexdigest()))
    return out


def _already_detected(sample: str) -> bool:
    data = sample.encode("latin-1", "replace")
    return bool(sandbox._rule_hits(data, sample, sandbox.file_type(data), 0.0))


def validate(v: dict, samples: list | None = None) -> tuple[str, str]:
    """(válida|insuficiente|hostil, razón). Nada de lo que dice la vacuna se ejecuta ni se obedece."""
    if not isinstance(v, dict) or not _ID_RE.fullmatch(str(v.get("id", ""))):
        return "hostil", "sin identificador válido"
    if type(v.get("version")) is not int or v["version"] < 1:
        return "hostil", "sin versión válida"
    if not isinstance(v.get("description"), str) or len(v["description"]) > 2000:
        return "hostil", "descripción ausente o desmesurada"
    iocs = v.get("iocs") or {}
    rules = v.get("rules") or []
    if not isinstance(iocs, dict) or not isinstance(rules, list):
        return "hostil", "estructura inesperada"
    ips, hashes = iocs.get("ips") or [], iocs.get("sha256") or []
    if not isinstance(ips, list) or not isinstance(hashes, list):
        return "hostil", "estructura inesperada"
    if len(ips) > MAX_IPS or len(hashes) > MAX_HASHES or len(rules) > MAX_RULES:
        return "hostil", "más indicadores de los que admite una vacuna"
    if not (ips or hashes or rules):
        return "insuficiente", "no aporta ningún indicador ni regla"
    for ip in ips:
        try:
            net = ipaddress.ip_network(str(ip), strict=False)
        except ValueError:
            return "hostil", f"IP inválida: {printable(ip)}"
        if not net.is_global:
            return "hostil", f"apunta a una red que no es pública: {net}"
        if net.prefixlen < (16 if net.version == 4 else 32):
            return "hostil", f"red demasiado amplia: {net}"
    if not all(isinstance(h, str) and _SHA_RE.fullmatch(h) for h in hashes):
        return "hostil", "sha256 inválido"
    seen_new = False
    for rule in rules:
        if not (isinstance(rule, dict) and _ID_RE.fullmatch(str(rule.get("id", "")))
                and rule.get("verdict") in ("sospechoso", "malicioso") and isinstance(rule.get("regex"), str)):
            return "hostil", "regla mal formada"
        problem = _unsafe_regex(rule["regex"])
        if problem:
            return "hostil", f"regla {rule['id']}: {problem}"
        good, bad = rule.get("must_match"), rule.get("must_not_match")
        if not (isinstance(good, list) and good and isinstance(bad, list) and bad
                and all(isinstance(s, str) and len(s) <= MAX_SAMPLE for s in good + bad)):
            return "insuficiente", f"regla {rule['id']}: sin prueba (faltan muestras y negativos)"
        pattern = re.compile(rule["regex"])
        if not all(pattern.search(s) for s in good):
            return "insuficiente", f"regla {rule['id']}: no detecta sus propias muestras"
        if any(pattern.search(s) for s in bad):
            return "insuficiente", f"regla {rule['id']}: dispara con sus negativos"
        seen_new = seen_new or not all(_already_detected(s) for s in good)
    if rules and not seen_new and not (ips or hashes):
        return "insuficiente", "no aporta nada: lo que prueba ya se detectaba sin ella"
    if samples is None and (rules or hashes):
        samples = _host_samples()
    known = {sha for _, _, sha in samples or []}
    if known.intersection(hashes):
        return "hostil", "marca como malicioso un binario de este host"
    for rule in rules:
        pattern = re.compile(rule["regex"])
        for path, data, _ in samples or []:
            if pattern.search(data.decode("latin-1")):
                return "insuficiente", f"regla {rule['id']}: casa con {printable(path)} de este host"
    return "válida", "superó la validación local"


def _host_bucket(vid: str) -> int:
    try:
        with open("/etc/machine-id", encoding="ascii") as f:
            host = f.read().strip()
    except OSError:
        host = socket.gethostname()
    return int(hashlib.sha256(f"{host}|{vid}".encode()).hexdigest(), 16) % 100


# ── actualizar ───────────────────────────────────────────────────────────────
def _fetch(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"arx/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (la firma es lo que manda)
        data = r.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("paquete de vacunas demasiado grande")
    return data


def update(fetch=_fetch, pubkey: str | None = None, cfg: dict | None = None, now: datetime | None = None) -> dict:
    """Descarga, verifica y aplica lo que valide este host. Nunca lanza: fail-open."""
    cfg = cfg if cfg is not None else config.load_config()
    now = now or _now()
    key = ASL_PUBKEY if pubkey is None else pubkey
    if cfg.get("vaccines_enabled") is False:
        return {"ok": False, "reason": "desactivadas en la configuración (vaccines_enabled)"}
    if not key:
        return {"ok": False, "reason": "el canal aún no está abierto: falta la clave de ASL"}
    with config.locked("vaccines"):
        st = _load()
        st["last_check"] = _iso(now)
        _save(st)
    try:
        raw = fetch(cfg.get("vaccine_feed_url") or FEED_URL)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:
        return {"ok": False, "reason": f"sin canal ahora mismo ({type(e).__name__}); la defensa sigue igual"}
    feed = open_feed(raw, key)
    if feed is None:
        response.record({"kind": "vaccine_rejected", "sev": "high",
                         "detail": "paquete de vacunas con firma no válida: descartado sin abrir"})
        return {"ok": False, "reason": "firma no válida: descartado sin abrir"}
    with config.locked("vaccines"):
        st = _load()
        serial = feed.get("serial")
        if type(serial) is not int:
            return {"ok": False, "reason": "paquete sin serial válido"}
        if serial < st.get("serial", 0):
            response.record({"kind": "vaccine_rejected", "sev": "high",
                             "detail": f"paquete antiguo (serial {serial} < {st.get('serial')}): posible repetición"})
            return {"ok": False, "reason": "paquete más antiguo que el aplicado: posible ataque de repetición"}
        applied, disabled = st.setdefault("applied", {}), st.setdefault("disabled", {})
        rejected = st.setdefault("rejected", {})
        out = {"ok": True, "serial": serial, "applied": [], "rejected": [], "revoked": [], "waiting": []}
        for vid in feed.get("revoked") or []:
            if isinstance(vid, str) and applied.pop(vid, None) is not None:
                out["revoked"].append(vid)
                response.record({"kind": "vaccine_revoked", "detail": f"vacuna {printable(vid)} retirada por ASL"})
        samples = None
        vaccines = feed.get("vaccines") if isinstance(feed.get("vaccines"), list) else []
        for v in vaccines:
            vid = str(v.get("id", "")) if isinstance(v, dict) else ""
            known = applied.get(vid) or {}
            version = v.get("version") if isinstance(v, dict) and type(v.get("version")) is int else 0
            if vid in disabled or (known and known.get("version", 0) >= version):
                continue
            if isinstance(v, dict) and type(v.get("rollout", 100)) is int and _host_bucket(vid) >= v.get("rollout", 100):
                out["waiting"].append(vid)
                continue
            if len(out["applied"]) >= MAX_NEW_PER_UPDATE:
                out["waiting"].append(vid)
                continue
            if samples is None:
                samples = _host_samples()
            status, why = validate(v, samples)
            if status != "válida":
                rejected[printable(vid) or "?"] = {"status": status, "reason": why, "at": _iso(now)}
                out["rejected"].append({"id": printable(vid), "status": status, "reason": why})
                response.record({"kind": "vaccine_rejected", "sev": "high" if status == "hostil" else "low",
                                 "detail": f"vacuna {printable(vid)} {status} en este host", "result": why})
                continue
            applied[vid] = {"version": v["version"], "description": v["description"], "attack": v.get("attack") or [],
                            "iocs": v.get("iocs") or {}, "rules": v.get("rules") or [], "expires": v.get("expires"),
                            "applied_at": _iso(now)}
            rejected.pop(vid, None)
            out["applied"].append(vid)
            response.record({"kind": "vaccine_applied", "detail": f"vacuna {vid} v{v['version']} validada y aplicada"})
        st["serial"], st["issued"] = serial, feed.get("issued")
        _save(st)
    _reset_index()
    return out


def update_safely() -> None:
    """Para el hilo de guardia: nada de esto puede tumbar la defensa local."""
    try:
        update()
    except Exception as e:
        response.record({"kind": "vaccine_error", "detail": f"actualización de vacunas fallida ({type(e).__name__})"})


def due(now: datetime | None = None) -> bool:
    last = _parse(_load().get("last_check"))
    return last is None or ((now or _now()) - last).total_seconds() >= UPDATE_EVERY_S


# ── lo que aplica ────────────────────────────────────────────────────────────
_index: dict = {"mtime": None}


def _reset_index() -> None:
    _index["mtime"] = None


def _active() -> dict:
    """Vacunas vigentes, con sus indicadores listos para buscar. Se reconstruye si cambió el fichero."""
    try:
        mtime = os.stat(_path()).st_mtime_ns
    except OSError:
        return {"ips": {}, "nets": [], "sha": {}, "rules": []}
    if _index["mtime"] == mtime:
        return _index["data"]
    ips, nets, sha, rules = {}, [], {}, []
    now = _now()
    for vid, v in (_load().get("applied") or {}).items():
        exp = _parse(v.get("expires")) if v.get("expires") else None
        if exp and exp <= now:
            continue
        iocs = v.get("iocs") or {}
        for raw in iocs.get("ips") or []:
            net = ipaddress.ip_network(str(raw), strict=False)
            if net.num_addresses == 1:
                ips[str(net.network_address)] = vid
            else:
                nets.append((net, vid))
        for h in iocs.get("sha256") or []:
            sha[h] = vid
        for r in v.get("rules") or []:
            rules.append((re.compile(r["regex"]), r, vid))
    data = {"ips": ips, "nets": nets, "sha": sha, "rules": rules}
    _index.update(mtime=mtime, data=data)
    return data


def _vaccine_for_ip(ip: str, active: dict) -> str | None:
    if ip in active["ips"]:
        return active["ips"][ip]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((vid for net, vid in active["nets"] if addr.version == net.version and addr in net), None)


def static_hits(text: str, sha256: str) -> list[dict]:
    """Coincidencias para el análisis estático, con la misma forma que las reglas propias."""
    active = _active()
    hits = []
    if sha256 in active["sha"]:
        vid = active["sha"][sha256]
        hits.append({"rule": f"vacuna-{vid}", "sev": "malicioso", "vaccine": vid,
                     "why": f"su sha256 es el de una muestra conocida (vacuna {vid})"})
    for pattern, rule, vid in active["rules"]:
        if pattern.search(text):
            hits.append({"rule": f"vacuna-{vid}-{rule['id']}", "sev": rule["verdict"], "vaccine": vid,
                         "why": f"regla de la vacuna {vid}: {printable(rule['id'])}"})
    return hits


def findings(known=()) -> list[dict]:
    """IPs de las vacunas conectadas ahora mismo, o tocando puertos de este host."""
    active = _active()
    if not (active["ips"] or active["nets"]):
        return []
    seen = {c.get("remote_ip") for c in recon.collect_connections() if c.get("state") == "ESTABLISHED"}
    seen |= set(sensors._scan_from_nft() or {})
    own = recon.local_ips()
    out = []
    for ip in sorted(i for i in seen if i and i not in own and i not in known):
        vid = _vaccine_for_ip(ip, active)
        if vid:
            out.append({"sev": "high", "kind": "intel_ip", "detail": f"IP señalada por la vacuna {vid}: {ip}",
                        "why": "otro Arx la vio atacar y ASL lo revisó", "target": {"ip": ip},
                        "set": "intel_allow", "item": ip, "vaccine": vid, "fp_key": f"intel_ip|{ip}"})
    return out


def note_false_positive(vid: str | None) -> bool:
    """El operador desmintió algo de esta vacuna. A la tercera se retira sola (§12.4.5)."""
    if not vid:
        return False
    with config.locked("vaccines"):
        st = _load()
        applied = st.get("applied") or {}
        if vid not in applied:
            return False
        applied[vid]["false_positives"] = applied[vid].get("false_positives", 0) + 1
        gone = applied[vid]["false_positives"] >= FP_ROLLBACK
        if gone:
            st.setdefault("disabled", {})[vid] = {"at": _iso(_now()), "reason": f"desmentida {FP_ROLLBACK} veces"}
            del applied[vid]
        _save(st)
    _reset_index()
    if gone:
        response.record({"kind": "vaccine_rolled_back", "sev": "high",
                         "detail": f"vacuna {vid} retirada: el operador la desmintió {FP_ROLLBACK} veces"})
    return gone


def remove(vid: str) -> bool:
    with config.locked("vaccines"):
        st = _load()
        if vid not in (st.get("applied") or {}):
            return False
        del st["applied"][vid]
        st.setdefault("disabled", {})[vid] = {"at": _iso(_now()), "reason": "retirada por el operador"}
        _save(st)
    _reset_index()
    response.record({"kind": "vaccine_removed", "detail": f"vacuna {vid} retirada por el operador"})
    return True


# ── consola ──────────────────────────────────────────────────────────────────
def run(action: str = "list", vid: str | None = None) -> int:
    if action == "update":
        r = update()
        if not r.get("ok"):
            print(f"Sin cambios: {r.get('reason')}")
            return 0 if "falta la clave" in str(r.get("reason")) or "sin canal" in str(r.get("reason")) else 1
        print(f"✓ Paquete {r['serial']}: {len(r['applied'])} aplicadas · {len(r['rejected'])} rechazadas · "
              f"{len(r['revoked'])} retiradas · {len(r['waiting'])} en espera")
        for x in r["rejected"]:
            print(f"  ✗ {x['id']}: {x['status']} — {x['reason']}")
        return 0
    if action == "remove":
        if remove(str(vid)):
            print(f"✓ Vacuna {vid} retirada. No volverá a aplicarse sola.")
            return 0
        print(f"No hay ninguna vacuna aplicada con id '{printable(vid)}'.")
        return 1
    st = _load()
    applied = st.get("applied") or {}
    print("\n▸ Arx — vacunas")
    if not ASL_PUBKEY and not applied:
        print("  El canal aún no está abierto: falta la clave pública de ASL. La defensa local no depende de él.\n")
        return 0
    print(f"  paquete        {st.get('serial', '—')}  ·  emitido {str(st.get('issued') or '—')[:16]}"
          f"  ·  última comprobación {str(st.get('last_check') or '—')[:16]}")
    print(f"  aplicadas      {len(applied)}")
    for k, v in applied.items():
        iocs = v.get("iocs") or {}
        print(f"    {k} v{v.get('version')}: {len(iocs.get('ips') or [])} IPs · {len(iocs.get('sha256') or [])} hashes · "
              f"{len(v.get('rules') or [])} reglas · {printable(v.get('description', ''))[:60]}")
    for k, v in (st.get("rejected") or {}).items():
        print(f"  rechazada      {k}: {v.get('status')} — {v.get('reason')}")
    for k, v in (st.get("disabled") or {}).items():
        print(f"  retirada       {k}: {v.get('reason')}")
    print()
    return 0
