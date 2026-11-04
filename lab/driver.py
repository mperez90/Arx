#!/usr/bin/env python3
"""Driver del mini-lab Arx — corre DENTRO del contenedor víctima.

Modos (los orquesta lab/docker-lab.sh con un contenedor atacante separado):
  prep              learn ×2 + seal + canario + listeners señuelo 9001-9012
  net-scan <ip>     L1: verifica detección del escaneo y bloqueo nft de la IP
  release           libera los bloqueos Tier 1 (entre fases de red)
  net-brute <ip>    L2: verifica detección de fuerza bruta y bloqueo nft
  levels            L4, L5, L7, L8, L9 en la víctima + scoreboard
  all               prep + levels (modo clásico de contenedor único)

Cada modo imprime [PASS]/[FAIL] por nivel y sale != 0 si falla.
"""
import json
import os
import socket
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


def _nft_set(name):
    return sh(["nft", "list", "set", "inet", "arx", name]).stdout


def prep():
    config.write_json(config.config_dir() / "config.json",
                      {"llm_daily_budget": 0, "lab": True})
    print("── preparación: verificar listeners 9001-9012 + learn ×2 + seal + canario ──")
    # Los listeners se siembran en el entrypoint del contenedor (docker exec mata el
    # árbol de procesos al salir — B7). Aquí se VERIFICA, con honestidad si faltan.
    import socket
    dead = [p for p in range(9001, 9013)
            if socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex(("127.0.0.1", p)) != 0]
    if dead:
        print(f"listeners señuelo caídos: {dead} — deben nacer en el entrypoint")
        return 1
    arx("learn")
    arx("learn")
    out = arx("learn", "--seal")
    assert "sellad" in out.lower() or "seal" in out.lower(), f"seal falló: {out}"
    print(arx("canaries", "plant").strip()[:120])
    return 0


def net_scan(ip):
    sweep()
    found = any("escaneo desde" in i.get("detail", "") and ip in i.get("detail", "")
                for i in incidents())
    blocked = ip in _nft_set("block_ipv4")
    ok = found and blocked
    print(f"[{'PASS' if ok else 'FAIL'}] nivel 1: escaneo detectado={found} · "
          f"IP en block_ipv4={blocked}")
    return 0 if ok else 1


def release():
    """Libera los bloqueos Tier 1 activos (como si hubieran expirado) entre fases."""
    from datetime import datetime, timedelta, timezone
    from arx.modules import response
    later = datetime.now(timezone.utc) + timedelta(minutes=61)
    n = len(response.expire_blocks(now=later))
    print(f"── bloqueos Tier 1 liberados entre fases: {n} ──")
    return 0


def net_brute(ip):
    sweep()
    found = any("fallos de autenticación desde" in i.get("detail", "")
                and ip in i.get("detail", "") for i in incidents())
    blocked = ip in _nft_set("block_ipv4")
    ok = found and blocked
    print(f"[{'PASS' if ok else 'FAIL'}] nivel 2: fuerza bruta detectada={found} · "
          f"IP en block_ipv4={blocked}")
    return 0 if ok else 1


def levels():
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

    print("\n── nivel 8: persistencia en cron.d → autorización → restauración ──")
    sh("echo '* * * * * root /bin/true' > /etc/cron.d/arxevil")
    sweep()
    pend = config.read_json(config.state_dir() / "pending_tier2.json", [])
    # el barrido puede haber encolado otros pendientes antes (p. ej. suid_set del L7):
    # el humano autoriza el de cron, no el primero de la fila
    item_id = next((p["id"] for p in pend
                    if p.get("kind") == "integrity"
                    and (p.get("target") or {}).get("file") == "cron"), None)
    restored, quarantined = False, False
    if item_id:
        from arx.modules import response
        # el humano autoriza (en la CLI real pide la palabra; aquí es el lab)
        item = response.authorize_pending(item_id)
        restored = bool(item and "restaurado" in (item.get("executed") or ""))
        import pathlib
        quarantined = any(p.name.startswith("q-") for p in
                          pathlib.Path(config.state_dir() / "vault").glob("q-*"))
        gone = not os.path.exists("/etc/cron.d/arxevil")
        report(8, restored and quarantined and gone,
               f"restaurado={restored} · hostil en cuarentena={quarantined} · "
               f"fichero hostil fuera de /etc/cron.d={gone}")
    else:
        report(8, False, "no se creó el pendiente Tier 2 de cron")

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
    print("(nivel 6 — anomalía de conexión saliente: GAP documentado en lab/README.md)")
    return 0 if all(score) else 1


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode == "prep":
        return prep()
    if mode == "net-scan":
        return net_scan(sys.argv[2])
    if mode == "release":
        return release()
    if mode == "net-brute":
        return net_brute(sys.argv[2])
    if mode == "levels":
        return levels()
    prep()
    return levels()


if __name__ == "__main__":
    sys.exit(main())
