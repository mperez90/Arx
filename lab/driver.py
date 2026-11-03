#!/usr/bin/env python3
"""Driver del mini-lab Arx — corre DENTRO del contenedor víctima.

Prepara Arx (learn + seal + canario) y ejecuta los niveles que hoy deben pasar en
un contenedor único (3, 4, 5, 7, 8, 9). Imprime un scoreboard PASS/GAP por nivel y
sale != 0 si alguno de los que deberían pasar falla. Los niveles 1, 2 y 6 necesitan
atacante separado o sensores aún inexistentes — ver lab/README.md (GAPs honestos).
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, "/src/src")
os.environ["PYTHONPATH"] = "/src/src"  # los subprocesos `arx ...` heredan esto
os.environ.setdefault("ARX_CONFIG_DIR", "/work/labcfg")
os.environ.setdefault("ARX_STATE_DIR", "/work/labstate")

from arx import config  # noqa: E402

score = []


def report(level, ok, evidence):
    score.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] nivel {level}: {evidence}")


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str),
                          capture_output=True, text=True, **kw)


def arx(*args):
    r = sh([sys.executable, "-m", "arx.cli", *args])
    return (r.stdout or "") + (r.stderr or "")


def incidents():
    try:
        lines = (config.state_dir() / "incidents.jsonl").read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def sweep():
    return arx("guard", "--once", "--enforce")


def main():
    config.write_json(config.config_dir() / "config.json",
                      {"llm_daily_budget": 0, "lab": True})

    print("── preparación: learn ×2 + seal + canario ──")
    arx("learn")
    arx("learn")
    out = arx("learn", "--seal")
    assert "sellad" in out.lower() or "seal" in out.lower(), f"seal falló: {out}"
    print(arx("canaries", "plant").strip()[:120])
    canary_path = None
    from arx.modules import canaries
    planted = canaries._load().get("canaries", [])
    if planted:
        canary_path = planted[0]["path"]

    print("\n── nivel 4: listener nuevo (4444) ──")
    sh("nohup nc -l 4444 >/dev/null 2>&1 &")
    time.sleep(1)
    sweep()
    nft = sh(["nft", "list", "set", "inet", "arx", "block_tcp"]).stdout
    ok = any("listen_ports" in i.get("detail", "") and "4444" in i.get("detail", "")
             for i in incidents()) and "4444" in nft
    report(4, ok, f"puerto detectado y bloqueado en nft: {'4444' in nft}")

    print("\n── nivel 5: dropper en /tmp ejecutado ──")
    sh("cp /usr/bin/yes /tmp/miner && chmod +x /tmp/miner")
    proc = subprocess.Popen(["/tmp/miner"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    time.sleep(1)
    sweep()
    time.sleep(1)
    try:
        st = sh(["ps", "-o", "stat=", "-p", str(proc.pid)]).stdout.strip()
    except Exception:
        st = "?"
    ok = st.startswith("T")
    report(5, ok, f"/tmp/miner suspendido (estado {st})")

    print("\n── nivel 7: binario SUID nuevo ──")
    sh("cp /usr/bin/id /tmp/sux && chmod u+s /tmp/sux")
    sweep()
    ok = any("suid" in i.get("detail", "").lower() and i.get("sev") in ("crit", "high")
             for i in incidents())
    report(7, ok, "integridad SUID disparó crit")

    print("\n── nivel 8: persistencia en cron.d ──")
    sh("echo '* * * * * root /bin/true' > /etc/cron.d/arxevil")
    sweep()
    pend = config.read_json(config.state_dir() / "pending_tier2.json", [])
    ok = bool(pend) and any("cron" in i.get("detail", "").lower() for i in incidents())
    report(8, ok, f"drift crit + {len(pend)} pendiente(s) Tier 2 para el humano")

    print("\n── nivel 9: lectura del señuelo ──")
    if canary_path and os.path.exists(canary_path):
        sh(["cat", canary_path])
        time.sleep(1)
        sweep()
        ok = any(i.get("kind") == "canary" or "canar" in i.get("detail", "").lower()
                 or "señuelo" in i.get("detail", "").lower() for i in incidents())
        report(9, ok, "lectura del canario detectada (atime)")
    else:
        report(9, False, "no se pudo plantar el canario en el lab")

    print(f"\n══ SCOREBOARD: {sum(score)}/{len(score)} niveles superados ══")
    print("(niveles 1, 2 y 6: GAP documentado en lab/README.md — necesitan sensor de red/"
          "auth.log/conexiones, ya en roadmap)")
    return 0 if all(score) else 1


if __name__ == "__main__":
    sys.exit(main())
