"""Arx · metrics — cuánto ruido hace Arx en este host (comando `arx metrics`).

La métrica pública de la fase de pruebas es < 0,1 falsos positivos altos por host y día. Sale de
lo que ya está en incidents.jsonl: una alerta alta o crítica cuenta como falso positivo cuando el
operador dice que lo era, con `arx accept` o `arx unlock`. Lo que nadie ha revisado se cuenta
aparte: no se da por bueno ni por malo.

`--json` da solo cifras por tipo de hallazgo, sin rutas, nombres ni IPs, para poder compartirlo.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from arx import __version__, config
from arx.i18n import tr

TARGET_FP_PER_DAY = 0.1
_HIGH = ("high", "crit")


def _events() -> list[dict]:
    try:
        text = (config.state_dir() / "incidents.jsonl").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def _when(e: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(str(e.get("at")))
    except ValueError:
        return None


def compute(days: int = 7, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    every = [(e, t) for e in _events() if (t := _when(e)) is not None]
    window = [e for e, t in every if t >= since]
    first = min((t for _, t in every), default=None)
    covered = min(days, max(1.0, (now - first).total_seconds() / 86400)) if first else 0
    new = [e for e in window if e.get("kind") == "incident" and e.get("new")]
    high = [e for e in new if e.get("sev") in _HIGH]
    by_kind: dict[str, int] = {}
    for e in high:
        k = str(e.get("finding_kind") or "sin_tipo")
        by_kind[k] = by_kind.get(k, 0) + 1
    # lo aceptado se compara con lo alto de la ventana: aceptar algo leve no es un falso positivo alto
    accepted = {e.get("detail") for e in window if e.get("kind") == "accepted"}
    fp = sum(e.get("detail") in accepted for e in high)
    unlocked = sum(e.get("kind") == "identity_unlocked" for e in window)
    false_positives = fp + unlocked
    rate = false_positives / covered if covered else 0.0
    unreviewed = max(0, len(high) - fp)
    # con alertas sin revisar, el objetivo solo se cumple si se cumpliría aunque todas fueran falsas
    worst = (false_positives + unreviewed) / covered if covered else 0.0
    within = True if worst < TARGET_FP_PER_DAY else (False if rate >= TARGET_FP_PER_DAY else None)
    return {
        "version": __version__,
        "days_covered": round(covered, 2),
        "findings_new": len(new),
        "alerts_high": len(high),
        "alerts_high_per_day": round(len(high) / covered, 3) if covered else 0.0,
        "false_positives": false_positives,
        "false_positives_per_day": round(rate, 3),
        "unreviewed_high": unreviewed,
        "automatic_actions": sum(1 for e in new if e.get("revert")),
        "accounts_locked_by_model": sum(e.get("kind") == "identity_contained" and bool(e.get("verdict"))
                                        for e in window),
        "high_by_kind": dict(sorted(by_kind.items())),
        "target_fp_per_day": TARGET_FP_PER_DAY,
        "within_target": within,  # None: depende de las alertas que aún no ha revisado nadie
    }


def run(days: int = 7, as_json: bool = False) -> int:
    m = compute(days)
    if as_json:
        print(json.dumps(m, ensure_ascii=False, indent=1))
        return 0
    if not m["days_covered"]:
        print(tr("Nothing to measure yet: Arx has not recorded any event."))
        return 0
    print(tr("\n▸ Arx: noise on this host (last {days_covered} days)",
             days_covered=m['days_covered']))
    print(tr("  new findings          {findings_new}", findings_new=m['findings_new']))
    print(tr("  high or critical      {alerts_high}  ({alerts_high_per_day}/day)",
             alerts_high=m['alerts_high'], alerts_high_per_day=m['alerts_high_per_day']))
    print(tr("  false positives       {false_positives}  ({false_positives_per_day}/day · target < "
             "{TARGET_FP_PER_DAY}/day)",
             false_positives=m['false_positives'], false_positives_per_day=m['false_positives_per_day'],
             TARGET_FP_PER_DAY=TARGET_FP_PER_DAY))
    print(tr("  high, unreviewed      {unreviewed_high}", unreviewed_high=m['unreviewed_high']))
    verdict = {True: tr("yes"), False: "no", None: tr("cannot tell yet: review the alerts")}[m["within_target"]]
    print(tr("  within target         {verdict}", verdict=verdict))
    print(tr("  automatic actions     {automatic_actions}",
             automatic_actions=m['automatic_actions']))
    if m["accounts_locked_by_model"]:
        print(tr("  accounts locked by the model  {accounts_locked_by_model}",
                 accounts_locked_by_model=m['accounts_locked_by_model']))
    for kind, n in m["high_by_kind"].items():
        print(f"    {kind:<18} {n}")
    print(tr("\n  A false positive only counts if you mark it (arx accept, arx unlock): whatever "
             "you do not review"))
    print(tr("  shows as «unreviewed», not as a hit. To share only the numbers: arx metrics "
             "--json\n"))
    return 0
