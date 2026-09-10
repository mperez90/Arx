"""Arx · guard — modo operativo (comando `arx guard`).

Bucle: instantánea → detección → respuesta por niveles → análisis del motor.
Detección = anomalía contra la base sellada (baseline.compare) + deriva de
integridad de ficheros críticos. Respuesta = motor por niveles (response). El
motor LLM (engine) añade una lectura en lenguaje natural, async y degradable
(si no hay proveedor, sigue el análisis determinista).

`--chat` abre un canal de consola con Arx (usa engine). `--once` hace un solo
barrido (para cron/pruebas). `--enforce` habilita las remediaciones Tier 1 auto.
"""
from __future__ import annotations

import time

from arx import config, engine, redact
from arx import license as lic
from arx.modules import baseline, canaries, response, sensors

SYSTEM_PROMPT = (
    "Eres Arx, guardián defensivo de este servidor. Respondes breve y en español, "
    "orientado a la acción. Nunca inventes datos; si no sabes algo, dilo. Distingue "
    "acciones reversibles (puedes proponerlas) de irreversibles (requieren la palabra "
    "de autorización del operador humano)."
)

_SEV_RANK = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}


def _integrity_drift(base: dict) -> list[dict]:
    """Compara la huella actual de ficheros críticos contra la sellada en la base."""
    sealed = base.get("integrity") or {}
    now = baseline.integrity_fingerprint()
    findings = []
    for k, v in sealed.items():
        if k in now and now[k] != v:
            findings.append(
                {
                    "sev": "crit" if k in ("authorized_keys_root", "sudoers") else "high",
                    "kind": "integrity",
                    "detail": f"cambió {k} desde el sellado de la línea base",
                    "why": "fichero crítico alterado → posible manipulación o persistencia",
                    "target": {"file": k},
                }
            )
    return findings


def sweep(base: dict, enforce: bool = False) -> tuple[list[dict], list[dict]]:
    snap = baseline.snapshot()
    findings = (
        baseline.compare(base, snap)
        + _integrity_drift(base)
        + canaries.check()
        + sensors.collect_events()
    )
    findings.sort(key=lambda f: _SEV_RANK.get(f["sev"], 9))
    outcomes = [response.handle(f, enforce=enforce) for f in findings]
    return findings, outcomes


def _assess_with_engine(findings: list[dict]) -> str | None:
    try:
        eng = engine.Engine()
        if not eng.providers_in_order():
            return None
        summary = "\n".join(f"- [{f['sev']}] {f['detail']}" for f in findings) or "sin hallazgos"
        # redactor de secretos SIEMPRE antes de mandar nada al LLM
        content = redact.scrub(f"Hallazgos del barrido:\n{summary}\n\n¿Prioridad y siguiente paso?")
        ans, _ = eng.ask([{"role": "user", "content": content}], system=SYSTEM_PROMPT)
        return ans
    except engine.ProviderError:
        return None


def _print_sweep(findings: list[dict], outcomes: list[dict]) -> None:
    if not findings:
        print("  sin desvíos respecto a la línea base ✓")
        return
    for f, o in zip(findings, outcomes):
        print(f"  [{f['sev']:>4}] {f['detail']}")
        print(f"         → Tier {o['tier']}: {o['remediation']}  ({o['status']})")


def _chat(cfg: dict) -> int:
    eng = engine.Engine(cfg)
    if not eng.providers_in_order():
        print("El chat necesita un proveedor LLM. Ejecuta:  arx setup")
        return 1
    print("Arx · chat  (escribe 'salir' para terminar)")
    history: list[dict] = []
    while True:
        try:
            line = input("tú> ").strip()
        except EOFError:
            break
        if not line:
            continue
        if line.lower() in ("salir", "exit", "quit"):
            break
        history.append({"role": "user", "content": line})
        try:
            ans, prov = eng.ask(history, system=SYSTEM_PROMPT)
        except engine.ProviderError as e:
            print(f"arx> (sin respuesta de ningún proveedor: {e})")
            history.pop()
            continue
        history.append({"role": "assistant", "content": ans})
        print(f"arx> {ans}")
    return 0


def run(once: bool = False, interval: int = 30, chat: bool = False, enforce: bool = False) -> int:
    cfg = config.load_config()
    if not cfg:
        print("Arx no está configurado. Ejecuta:  arx setup")
        return 1
    if chat:
        return _chat(cfg)

    base = baseline.load()
    if not base or not base["meta"].get("sealed"):
        print("No hay línea base sellada. Ejecuta:  arx learn  y luego  arx learn --seal")
        return 1

    lic.validate()  # best-effort: refresca la caché; nunca bloquea el arranque (fallar-abierto)
    tier, why = lic.effective_tier()
    intel = "gestionada (Pro)" if lic.tier_allows("managed_intel", tier) else "comunitaria (Core)"
    sens = sensors.available()
    active = [k for k, v in sens.items() if v] or ["colectores base (/proc)"]
    print(f"▸ Arx en guardia  ·  tier {tier} ({why})  ·  intel {intel}")
    print(f"  sensores: {', '.join(active)}  ·  enforce={'ON' if enforce else 'OFF'}  ·  "
          f"{'un barrido' if once else f'cada {interval}s'}")
    while True:
        print(f"\n— barrido {baseline._now()} —")
        findings, outcomes = sweep(base, enforce=enforce)
        _print_sweep(findings, outcomes)
        pend = [o for o in outcomes if o["tier"] == 2 and "PENDIENTE" in o["status"]]
        if pend:
            print(f"\n  ⚠ {len(pend)} acción(es) Tier 2 esperan tu palabra de autorización.")
        assessment = _assess_with_engine(findings)
        if assessment:
            print("\n▸ Motor (LLM):\n  " + assessment.replace("\n", "\n  "))
        elif findings:
            print("\n  (motor LLM no configurado — análisis determinista únicamente)")
        if once:
            break
        time.sleep(interval)
    return 0
