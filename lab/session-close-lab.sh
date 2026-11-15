#!/usr/bin/env bash
# B75: cerrar UNA sesión de ssh de verdad (sshd, /proc y señales reales; no simulados).
# Abre una sesión de ssh desde la propia VM a su loopback, localiza sus procesos con la misma función que usa Arx
# (`_ssh_session_pids`), la cierra con `_close_ssh_session` y comprueba que murió ESA sesión y nada más: el sshd que
# escucha, la sesión desde la que se ejecuta el lab y los procesos de root siguen vivos.
#   ARX_LIMA_VICTIM=arx-victim bash lab/session-close-lab.sh
#   ARX_LAB_ROOT=1 ...   además, la misma prueba con una sesión de ROOT y el camino completo del Tier 2
#                         (`_execute_tier2`: la IP de loopback es propia, así que no se bloquea y lo dice).
#                         Pone una llave temporal en /root/.ssh/authorized_keys (Arx lo avisará) y la quita al acabar.
# Requiere Arx instalado (`/usr/lib/arx/arx.pyz`) y sshd con acceso por llave. Crea y borra la cuenta `arxlab`.
set -uo pipefail
VM=${ARX_LIMA_VICTIM:-arx-victim}
ROOT_TOO=${ARX_LAB_ROOT:-0}
FAILED=0

v() { limactl shell "$VM" sudo "$@"; }

v test -f /usr/lib/arx/arx.pyz || { echo "Arx no está instalado en $VM" >&2; exit 2; }
echo "# cierre de una sesión de ssh en $VM · $(v sh -c '. /etc/os-release; echo "$PRETTY_NAME · $(sshd -V 2>&1 | head -1) · $(python3 --version)"')"
OUT=$(v env ARX_LAB_ROOT="$ROOT_TOO" python3 - <<'PY'
import os, pwd, signal, subprocess, sys, tempfile, time

sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import response  # noqa: E402

ORIGIN = "127.0.0.1"
results = []


def check(ok, text):
    results.append(("PASS " if ok else "FAIL ") + text)
    return ok


def sh(*argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def alive(pid):
    return os.path.isdir(f"/proc/{pid}") and not response._is_zombie(pid)


def sshd_pids():
    out = sh("pgrep", "-x", "sshd").stdout.split() + sh("pgrep", "-x", "sshd-session").stdout.split()
    return {int(p) for p in out}


def sleepers(uid):
    """Los `sleep 600` de esa cuenta: el comando que lanza la sesión de prueba (hijo de su shell o de su sshd)."""
    return [int(p) for p in sh("pgrep", "-u", str(uid), "-f", "^sleep 600$").stdout.split()]


def wait(cond, secs=10):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    return cond()


def open_session(user, key):
    return subprocess.Popen(["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                             "-o", "BatchMode=yes", "-tt", f"{user}@{ORIGIN}", "sleep 600"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_case(user, via_tier2):
    uid = pwd.getpwnam(user).pw_uid
    key = tempfile.mkdtemp() + "/key"
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
    home = pwd.getpwnam(user).pw_dir
    auth = os.path.join(home, ".ssh", "authorized_keys")
    os.makedirs(os.path.dirname(auth), exist_ok=True)
    before_auth = open(auth).read() if os.path.exists(auth) else None
    with open(auth, "a") as f:
        f.write(open(key + ".pub").read())
    os.chmod(auth, 0o600)
    if user != "root":
        sh("chown", "-R", f"{user}:{user}", os.path.dirname(auth))
    try:
        keep = sshd_pids()  # lo que ya había: el que escucha y la sesión desde la que se ejecuta este lab
        client = open_session(user, key)
        found = wait(lambda: bool(response._ssh_session_pids(user, uid, ORIGIN)))
        check(found, f"[{user}] Arx localiza la sesión de {user} desde {ORIGIN}")
        if not found:
            return
        check(wait(lambda: bool(sleepers(uid))), f"[{user}] la sesión está completa (su comando ya corre)")
        mine = response._ssh_session_pids(user, uid, ORIGIN)  # con la sesión completa: el monitor, el hijo y lo que lanzó
        check(not (mine & keep), f"[{user}] y no confunde las sesiones que ya había")
        if via_tier2:
            finding = {"kind": "login_users", "sev": "high", "detail": f"nuevo en login_users: {user}@{ORIGIN}",
                       "target": {"user": f"{user}@{ORIGIN}"}}
            check(bool(response._session_only_reason(user)), f"[{user}] el Tier 2 es «origen + esa sesión», no bloquear la cuenta")
            text = response._execute_tier2(finding)
            print("\n".join("    | " + line for line in text.splitlines()), file=sys.stderr)
            check(not response.locked_accounts(), f"[{user}] la cuenta no se bloqueó")
            check("no se bloquea" in text.lower() or "is not blocked" in text.lower(),
                  f"[{user}] el informe dice por qué no se bloqueó el origen (IP propia protegida)")
        else:
            closed, survivors = response._close_ssh_session(user, ORIGIN)
            check(bool(closed) and not survivors, f"[{user}] se cerró la sesión ({len(closed)} procesos), sin supervivientes")
        check(wait(lambda: client.poll() is not None), f"[{user}] el cliente de ssh perdió la conexión")
        check(wait(lambda: not (mine & sshd_pids())), f"[{user}] los procesos de esa sesión ya no están")
        check(wait(lambda: not sleepers(uid)), f"[{user}] el comando que lanzó esa sesión murió con ella")
        check(all(alive(p) for p in keep), f"[{user}] el sshd que escucha y la sesión del lab siguen vivos")
        check(os.path.isdir("/proc/1"), f"[{user}] systemd, cron y el resto de root no se tocaron")
        client.kill()
    finally:
        if user == "root":
            if before_auth is None:
                os.unlink(auth)
            else:
                with open(auth, "w") as f:
                    f.write(before_auth)
        sh("pkill", "-KILL", "-f", f"{key}")


sh("useradd", "-m", "-s", "/bin/bash", "arxlab")
try:
    run_case("arxlab", via_tier2=False)
    if os.environ.get("ARX_LAB_ROOT") == "1":
        run_case("root", via_tier2=True)
finally:
    sh("pkill", "-KILL", "-u", "arxlab")
    sh("userdel", "-r", "arxlab")
print("\n".join(results))
PY
)
echo "$OUT"
grep -q '^FAIL ' <<<"$OUT" && FAILED=1
[ -n "$OUT" ] || FAILED=1
[ "$FAILED" = 0 ] && echo "RESULT: ok" || echo "RESULT: FAIL"
exit "$FAILED"
