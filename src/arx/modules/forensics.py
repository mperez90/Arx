"""Arx · forensics — informe forense post-incidente (promesa Core, §12.1).

Tras repeler un ataque, Arx arma un informe DETALLADO de lo que pasó, reuniendo lo que ya
registró (nada se inventa) y sellándolo para detectar cambios posteriores:

  · cronología de incidents (incidents.jsonl): qué detectó, cuándo, qué hizo y su nivel;
  · contención activa (bloqueos Tier 1) y acciones Tier 2 pendientes;
  · evidencia preservada en cuarentena (vault): ficheros hostiles movidos, con su hash;
  · contexto del host (último recon) y un summary ejecutivo.

Sellado (stdlib puro, sin dependencias):
  · CADENA DE HASH sobre la cronología: detecta una corrupción o un cambio torpe. Sola no
    protege de nada, porque cualquiera que altere el informe puede recalcularla.
  · HMAC-SHA256 del informe con una clave local del host (secrets.json): esto es lo que
    detecta una alteración. La clave nace sola la primera vez y jamás se imprime.

Límites honestos: el sello protege el INFORME desde que se genera, no el registro del que
sale (quien edite incidents.jsonl antes de generarlo no deja rastro), y quien sea root en
este host puede leer la clave y volver a firmar. Para resistir eso hay que anclar el sello
fuera del host (consola de flota, F15). Antes de sellar se redactan los secretos conocidos.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from datetime import datetime, timezone

from arx import config
from arx.i18n import tr
from arx.modules import fleet, recon, response
from arx.redact import printable

# Campos estables que entran en la cronología (orden canónico lo da _canonical).
_TIMELINE_FIELDS = ("at", "kind", "sev", "detail", "tier", "status", "remediation",
                    "result", "reverted", "revert", "decided_by", "verdict", "closed", "survivors",
                    "finding_kind", "why")
_SEV_RANK = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}
# solo lo que señala a alguien de fuera; un login dice demasiado sobre este host
_SHAREABLE_KINDS = ("port_scan", "auth_bruteforce", "reverse_shell", "intel_ip")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8", "surrogatepass")


def _hmac_key(create: bool = True) -> tuple[bytes, str] | None:
    """Clave HMAC local del host. Nace sola la primera vez; key_id = sha256(clave)[:12]
    (identifica la clave sin exponerla, para que verify sepa si es la misma)."""
    sec = config.load_secrets()
    hexkey = sec.get("forensic_hmac_key")
    if not hexkey:
        if not create:
            return None
        hexkey = secrets.token_bytes(32).hex()
        sec["forensic_hmac_key"] = hexkey
        config.save_secrets(sec)
    key = bytes.fromhex(hexkey)
    return key, hashlib.sha256(key).hexdigest()[:12]


def _chain(timeline: list[dict]) -> str:
    """Cadena de hash sobre la cronología: h_i = sha256(h_{i-1} + entrada_i)."""
    h = b""
    for entry in timeline:
        h = hashlib.sha256(h + _canonical(entry)).digest()
    return h.hex()


# ── recolección (solo lo ya registrado) ───────────────────────────────────────
def _incidents(since: str | None) -> list[dict]:
    try:
        lines = response._incidents_path().read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if since and str(e.get("at", "")) < since:
            continue
        out.append({k: e[k] for k in _TIMELINE_FIELDS if k in e})
    return out


def _quarantined() -> list[dict]:
    manifest = config.read_json(response._vault_manifest_path(), {})
    out = []
    for meta in manifest.values():
        if meta.get("quarantined_from"):
            out.append({"origin": meta["quarantined_from"], "sha256": meta.get("sha256"),
                        "at": meta.get("at")})
    return sorted(out, key=lambda x: str(x.get("at")))


def _host() -> dict:
    try:
        from arx.modules import guard
        return guard._host_context()
    except Exception:
        return {}


def _summary(timeline: list[dict], blocks: list, quarantine: list) -> dict:
    by_sev: dict[str, int] = {}
    for e in timeline:
        s = e.get("sev")
        if s:
            by_sev[s] = by_sev.get(s, 0) + 1
    worst = min((s for s in by_sev), key=lambda s: _SEV_RANK.get(s, 9), default=None)
    # una acción es lo que se EJECUTÓ: un hallazgo Tier 1 en modo observar o un Tier 2
    # pendiente no han tocado nada, y un informe forense no puede decir lo contrario
    # lo decidido por el modelo no pasa por Tier 2: se cuenta aparte, sin duplicar lo del humano
    acciones = [e for e in timeline if e.get("revert") or e.get("kind") == "tier2_executed"
                or (e.get("kind") == "identity_contained" and e.get("verdict"))]
    return {
        "incidents": len(timeline),
        "by_severity": by_sev,
        "max_severity": worst,
        "actions_taken": len(acciones),
        "active_containment": len(blocks),
        "quarantined_evidence": len(quarantine),
        "window": {"since": timeline[0]["at"] if timeline else None,
                    "until": timeline[-1]["at"] if timeline else None},
    }


def indicators(since: str | None = None) -> dict:
    """Lo que puede salir de este host si el dueño quiere compartirlo (§12.3): IPs públicas de los
    atacantes, hashes de lo que quedó en cuarentena y tipos de ataque. Nada de rutas, cuentas ni
    nombres de host. Nada sale solo: esto se imprime y lo envía una persona, si quiere."""
    timeline = _incidents(since)
    ips, kinds = set(), set()
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")
    own = recon.local_ips()
    for e in timeline:
        if e.get("sev") not in ("high", "crit") or e.get("finding_kind") not in _SHAREABLE_KINDS:
            continue
        kinds.add(e["finding_kind"])
        for raw in ip_re.findall(str(e.get("detail") or "")):
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if addr.is_global and raw not in own:
                ips.add(raw)
    return {"arx_indicators": 1, "attack_kinds": sorted(kinds), "ips": sorted(ips),
            "sha256": sorted({q["sha256"] for q in _quarantined() if q.get("sha256")})}


def print_indicators(since: str | None = None) -> int:
    print(json.dumps(indicators(since), ensure_ascii=False, indent=1))
    return 0


# ── informe + sellado ──────────────────────────────────────────────────────────
def build_report(since: str | None = None) -> dict:
    timeline = _incidents(since)
    blocks = [{"detail": b.get("detail"), "expires": response._until(b)}
              for b in response._load_blocks()]
    pending = [{"id": p.get("id"), "detail": p.get("detail"),
                "remediation": p.get("remediation")} for p in response.list_pending()]
    quarantine = _quarantined()
    report = {
        "meta": {"arx_forensics": 2, "id": secrets.token_hex(6), "generated": _now(),
                 "since": since},
        "host": _host(),
        "timeline": timeline,
        "active_containment": blocks,
        "pending_tier2": pending,
        "quarantined_evidence": quarantine,
        "summary": _summary(timeline, blocks, quarantine),
    }
    report = fleet._scrub_deep(report)  # un informe se comparte: sin secretos conocidos
    timeline = report["timeline"]
    # sellado doble: cadena de hash de la cronología + HMAC del informe entero
    chain = _chain(timeline)
    key, key_id = _hmac_key()
    body = {k: v for k, v in report.items()} | {"chain": chain}
    mac = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    report["seal"] = {"algo": "sha256-chain + hmac-sha256", "key_id": key_id,
                       "chain": chain, "hmac": mac}
    return report


def verify(report: dict) -> tuple[bool, str]:
    """Recomputa cadena y HMAC: detecta cualquier alteración posterior del informe.

    Los informes de versiones anteriores llevan las claves en español y siguen verificándose. Se
    elige una sola forma: añadirle a un informe nuevo una clave vieja también rompe el HMAC."""
    seal_key, timeline_key = ("seal", "timeline") if "seal" in report else ("firma", "cronologia")
    seal, timeline = report.get(seal_key), report.get(timeline_key, [])
    if not (isinstance(seal, dict) and isinstance(timeline, list)
            and isinstance(seal.get("hmac"), str)):
        return False, tr("malformed report: the seal is missing or it lacks the expected structure")
    if _chain(timeline) != seal.get("chain"):
        return False, tr("the hash chain does not match: the timeline was altered")
    local = _hmac_key(create=False)  # verificar no debe crear una clave como efecto lateral
    if local is None:
        return False, tr("this host does not have the sealing key: it cannot be verified here")
    key, key_id = local
    if seal.get("key_id") != key_id:
        return False, tr("signed with another key (another host or a rotated key)")
    body = {k: v for k, v in report.items() if k != seal_key} | {"chain": seal["chain"]}
    expect = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect.encode(), seal["hmac"].encode("utf-8", "replace")):
        return False, tr("the HMAC does not match: the report was altered or re-signed without the key")
    return True, tr("chain intact and HMAC valid")


def save_report(report: dict) -> "object":
    d = config.state_dir() / "forensics"
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"forensic-{report['meta']['id']}.json"
    config.write_json(dest, report)
    return dest


# ── salida de consola ──────────────────────────────────────────────────────────
def render(report: dict) -> None:
    r = report["summary"]
    print(tr("\n══ Forensic report {id} · {generated} ══",
             id=report['meta']['id'], generated=report['meta']['generated']))
    host = report.get("host") or {}
    if host.get("host"):
        print(f"Host: {host.get('host')} · {host.get('distro') or ''}")
    print(tr("Incidents: {incidents} · max severity: {v} · actions: {actions_taken} · "
             "quarantine: {quarantined_evidence}",
             incidents=r['incidents'], v=r['max_severity'] or '—', actions_taken=r['actions_taken'],
             quarantined_evidence=r['quarantined_evidence']))
    if r["window"]["since"]:
        print(tr("Window: {since} → {until}",
                 since=r['window']['since'], until=r['window']['until']))
    print(tr("\n▸ Timeline"))
    for e in report["timeline"]:
        tier = f"T{e['tier']}" if e.get("tier") is not None else "  "
        print(f"  {e.get('at', '?')[11:19]} [{e.get('sev', '?'):>4}] {tier} "
              f"{printable(e.get('detail', ''))[:80]}")
        if e.get("status"):
            print(f"              → {printable(e['status'])[:88]}")
    if not report["timeline"]:
        print(tr("  (no incidents recorded in the window)"))
    if report["quarantined_evidence"]:
        print(tr("\n▸ Preserved evidence (quarantine)"))
        for q in report["quarantined_evidence"]:
            print(f"  {printable(q['origin'])}  sha256={str(q['sha256'])[:16]}…")
    if report["active_containment"]:
        print(tr("\n▸ Containment still active"))
        for b in report["active_containment"]:
            print(f"  {printable(b['detail'])}  ({b.get('expires', '?')})")
    ok, msg = verify(report)
    seal = report["seal"]
    print(tr("\n▸ Seal  chain={v}…  key_id={key_id}  → {msg}",
             v=seal['chain'][:16], key_id=seal['key_id'], msg=msg))
    print()


def run(verify_path: str | None = None, since: str | None = None) -> int:
    if verify_path:
        report = config.read_json(verify_path, None)
        if not isinstance(report, dict):
            print(tr("Could not read a report at {verify_path}", verify_path=verify_path))
            return 1
        ok, msg = verify(report)
        print(("✓ " if ok else "✗ ") + msg)
        return 0 if ok else 1
    report = build_report(since=since)
    render(report)
    dest = save_report(report)
    print(tr("▸ Report saved to: {dest}  (verify it with: arx forensics --verify {dest})\n",
             dest=dest))
    return 0
