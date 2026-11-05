"""Arx · forensics — informe forense post-incidente (promesa Core, §12.1).

Tras repeler un ataque, Arx arma un informe DETALLADO de lo que pasó, reuniendo lo que ya
registró (nada se inventa) y sellándolo para detectar cambios posteriores:

  · cronología de incidentes (incidents.jsonl): qué detectó, cuándo, qué hizo y su nivel;
  · contención activa (bloqueos Tier 1) y acciones Tier 2 pendientes;
  · evidencia preservada en cuarentena (vault): ficheros hostiles movidos, con su hash;
  · contexto del host (último recon) y un resumen ejecutivo.

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
import json
import secrets
from datetime import datetime, timezone

from arx import config
from arx.modules import fleet, response
from arx.redact import printable

# Campos estables que entran en la cronología (orden canónico lo da _canonical).
_TIMELINE_FIELDS = ("at", "kind", "sev", "detail", "tier", "status", "remediation",
                    "result", "reverted", "revert")
_SEV_RANK = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}


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
            out.append({"origen": meta["quarantined_from"], "sha256": meta.get("sha256"),
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
    acciones = [e for e in timeline if e.get("revert") or e.get("kind") == "tier2_executed"]
    return {
        "incidentes": len(timeline),
        "por_severidad": by_sev,
        "severidad_maxima": worst,
        "acciones_tomadas": len(acciones),
        "contencion_activa": len(blocks),
        "evidencia_en_cuarentena": len(quarantine),
        "ventana": {"desde": timeline[0]["at"] if timeline else None,
                    "hasta": timeline[-1]["at"] if timeline else None},
    }


# ── informe + sellado ──────────────────────────────────────────────────────────
def build_report(since: str | None = None) -> dict:
    timeline = _incidents(since)
    blocks = [{"detalle": b.get("detail"), "expira": b.get("expires_at")}
              for b in response._load_blocks()]
    pending = [{"id": p.get("id"), "detalle": p.get("detail"),
                "remediacion": p.get("remediation")} for p in response.list_pending()]
    quarantine = _quarantined()
    report = {
        "meta": {"arx_forensics": 1, "id": secrets.token_hex(6), "generado": _now(),
                 "desde": since},
        "host": _host(),
        "cronologia": timeline,
        "contencion_activa": blocks,
        "pendientes_tier2": pending,
        "evidencia_en_cuarentena": quarantine,
        "resumen": _summary(timeline, blocks, quarantine),
    }
    report = fleet._scrub_deep(report)  # un informe se comparte: sin secretos conocidos
    timeline = report["cronologia"]
    # sellado doble: cadena de hash de la cronología + HMAC del informe entero
    chain = _chain(timeline)
    key, key_id = _hmac_key()
    body = {k: v for k, v in report.items()} | {"chain": chain}
    mac = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    report["firma"] = {"algo": "sha256-chain + hmac-sha256", "key_id": key_id,
                       "chain": chain, "hmac": mac}
    return report


def verify(report: dict) -> tuple[bool, str]:
    """Recomputa cadena y HMAC: detecta cualquier alteración posterior del informe."""
    firma, timeline = report.get("firma"), report.get("cronologia", [])
    if not (isinstance(firma, dict) and isinstance(timeline, list)
            and isinstance(firma.get("hmac"), str)):
        return False, "informe mal formado: falta el sello o no tiene la estructura esperada"
    if _chain(timeline) != firma.get("chain"):
        return False, "la cadena de hash no cuadra: la cronología fue alterada"
    local = _hmac_key(create=False)  # verificar no debe crear una clave como efecto lateral
    if local is None:
        return False, "este host no tiene la clave de sellado: no se puede verificar aquí"
    key, key_id = local
    if firma.get("key_id") != key_id:
        return False, "firmado con otra clave (otro host o clave rotada)"
    body = {k: v for k, v in report.items() if k != "firma"} | {"chain": firma["chain"]}
    expect = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect.encode(), firma["hmac"].encode("utf-8", "replace")):
        return False, "el HMAC no cuadra: el informe fue alterado o re-firmado sin la clave"
    return True, "cadena íntegra y HMAC válido"


def save_report(report: dict) -> "object":
    d = config.state_dir() / "forensics"
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"forense-{report['meta']['id']}.json"
    config.write_json(dest, report)
    return dest


# ── salida de consola ──────────────────────────────────────────────────────────
def render(report: dict) -> None:
    r = report["resumen"]
    print(f"\n══ Informe forense {report['meta']['id']} · {report['meta']['generado']} ══")
    host = report.get("host") or {}
    if host.get("host"):
        print(f"Host: {host.get('host')} · {host.get('distro') or ''}")
    print(f"Incidentes: {r['incidentes']} · severidad máx: {r['severidad_maxima'] or '—'} · "
          f"acciones: {r['acciones_tomadas']} · cuarentena: {r['evidencia_en_cuarentena']}")
    if r["ventana"]["desde"]:
        print(f"Ventana: {r['ventana']['desde']} → {r['ventana']['hasta']}")
    print("\n▸ Cronología")
    for e in report["cronologia"]:
        tier = f"T{e['tier']}" if e.get("tier") is not None else "  "
        print(f"  {e.get('at', '?')[11:19]} [{e.get('sev', '?'):>4}] {tier} "
              f"{printable(e.get('detail', ''))[:80]}")
        if e.get("status"):
            print(f"              → {printable(e['status'])[:88]}")
    if not report["cronologia"]:
        print("  (sin incidentes registrados en la ventana)")
    if report["evidencia_en_cuarentena"]:
        print("\n▸ Evidencia preservada (cuarentena)")
        for q in report["evidencia_en_cuarentena"]:
            print(f"  {printable(q['origen'])}  sha256={str(q['sha256'])[:16]}…")
    if report["contencion_activa"]:
        print("\n▸ Contención aún activa")
        for b in report["contencion_activa"]:
            print(f"  {printable(b['detalle'])}  (expira {b.get('expira', '?')[11:16]} UTC)")
    ok, msg = verify(report)
    firma = report["firma"]
    print(f"\n▸ Sellado  cadena={firma['chain'][:16]}…  key_id={firma['key_id']}  → {msg}")
    print()


def run(verify_path: str | None = None, since: str | None = None) -> int:
    if verify_path:
        report = config.read_json(verify_path, None)
        if not isinstance(report, dict):
            print(f"No pude leer un informe en {verify_path}")
            return 1
        ok, msg = verify(report)
        print(("✓ " if ok else "✗ ") + msg)
        return 0 if ok else 1
    report = build_report(since=since)
    render(report)
    dest = save_report(report)
    print(f"▸ Informe guardado en: {dest}  (verifícalo con: arx forensics --verify {dest})\n")
    return 0
