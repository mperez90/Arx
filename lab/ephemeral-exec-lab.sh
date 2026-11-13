#!/usr/bin/env bash
# B59: identidad de execs efímeros en un kernel real, sin ataques externos.
#   bash lab/ephemeral-exec-lab.sh
#   ARX_LIMA_VICTIM=arx-deb13 bash lab/ephemeral-exec-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."
VM=${ARX_LIMA_VICTIM:-arx-victim}
WORD=palabra-del-lab
FAILED=0
BASE=/tmp/arx-b59

step() { echo; echo "══ $1 ══"; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }
v() { limactl shell "$VM" sudo "$@"; }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
wait_for() { local n="$1"; shift; local i; for i in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q Running || limactl start "$VM" >/dev/null 2>&1

step "víctima limpia, paquete actual y servicio generador"
v bash -c 'systemctl disable --now arx arx-firewall arx-revive.timer arx-b59-runner 2>/dev/null; pkill -9 -f "[a]rx.pyz"
  apt-get -o DPkg::Lock::Timeout=300 purge -y -qq arx >/dev/null 2>&1
  rm -rf /etc/arx /var/lib/arx /tmp/arxsrc /tmp/arx-b59 /dev/shm/arx-b59-* \
    /etc/systemd/system/arx-b59-runner.service /etc/systemd/system/arx*.service \
    /etc/systemd/system/arx*.timer /etc/systemd/system/arx*.slice \
    /etc/systemd/system/*.service.d/9[01]-arx-*.conf
  grep -lsE "inet:arx:|inet arx confined" /etc/systemd/system.control/*.service.d/*.conf 2>/dev/null | xargs -r rm -f
  nft delete table inet arx 2>/dev/null; systemctl daemon-reload
  export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 install -y -qq nftables python3 auditd >/dev/null'
v bash -s -- "$PWD" <<'REMOTE'
set -e
root=$1
mkdir -p /tmp/arxsrc
cp -r "$root/src" "$root/packaging" /tmp/arxsrc/
cd /tmp/arxsrc
packaging/build-deb.sh >/dev/null
dpkg -i ./dist/arx_all.deb >/dev/null
REMOTE
check "Arx instalado desde este árbol" v arx --version

v python3 - <<'PY'
import os
from pathlib import Path
base = Path("/tmp/arx-b59")
(base / "queue").mkdir(parents=True, exist_ok=True)
(base / "runner.py").write_text(r"""import json, os, time
from pathlib import Path
base = Path("/tmp/arx-b59")
queue = base / "queue"
while True:
    for go in sorted(queue.glob("*.go")):
        try:
            spec = json.loads(go.read_text())
        except (OSError, ValueError):
            continue
        try:
            go.unlink()
        except OSError:
            continue
        pid = os.fork()
        if pid == 0:
            try:
                if spec.get("script"):
                    os.execv(spec["script"], [spec["script"]])
                os.execv(spec["path"], [spec["path"]])
            except OSError:
                os._exit(127)
        _, status = os.waitpid(pid, 0)
        for name in (spec.get("script"), spec["path"] if spec.get("delete") else None):
            if name:
                try:
                    os.unlink(name)
                except OSError:
                    pass
        record = {"pid": pid, "path": spec["path"], "status": status,
                  "script": bool(spec.get("script"))}
        with (base / "records.jsonl").open("a") as fh:
            fh.write(json.dumps(record) + "\n")
            fh.flush()
    time.sleep(0.002)
""")
Path("/etc/systemd/system/arx-b59-runner.service").write_text(
    "[Service]\nExecStart=/usr/bin/python3 /tmp/arx-b59/runner.py\n"
    "[Install]\nWantedBy=multi-user.target\n")
os.chmod(base / "runner.py", 0o755)
PY
v bash -c 'systemctl daemon-reload; systemctl enable --now arx-b59-runner >/dev/null 2>&1'
printf '%s\n' "en" "" "" "" "$WORD" "$WORD" "" "" "1" "" "core" "" "" "high" "block" | v arx setup >/dev/null 2>&1
v bash -c 'arx recon >/dev/null; arx learn >/dev/null; arx learn >/dev/null; arx learn --seal >/dev/null'
v python3 -c "import json; p = '/etc/arx/config.json'; c = json.load(open(p)); c.update(profile_observe_days=0.003, profile_jitter_days=0); json.dump(c, open(p, 'w'))"
v arx service install --enforce >/dev/null 2>&1
check "Arx activo" wait_for 30 v systemctl is-active -q arx
kernel_full() {
  v python3 -c 'import json, sys
w = json.load(open("/var/lib/arx/watch.json"))
c = w["process"]["capture"]
sys.exit(0 if w["process"]["mode"] == "netlink" and c["running"] and c["mode"] == "full" and not c["failed"] else 1)'
}
check "netlink y captura fanotify completa publicados" wait_for 30 kernel_full
watching() {
  v python3 -c 'import json, sys
s = json.load(open("/var/lib/arx/profiles.json"))["subjects"]
sys.exit(0 if s.get("system.slice/arx-b59-runner.service", {}).get("status") == "watching" else 1)'
}
check "el generador terminó su observación" wait_for 420 watching

step "observador netlink independiente y contadores basales"
v python3 - <<'PY'
from pathlib import Path
Path("/tmp/arx-b59/netlink-monitor.py").write_text(r"""import json, select, sys, time
from pathlib import Path
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import execwatch
base = Path("/tmp/arx-b59")
sock = execwatch._subscribe()
poll = select.poll()
poll.register(sock, select.POLLIN)
(base / "netlink.ready").write_text("ready")
try:
    with (base / "netlink.jsonl").open("a", buffering=1) as out:
        while not (base / "netlink.stop").exists():
            try:
                if not poll.poll(200):
                    continue
                for pid, ts in execwatch.parse_events(sock.recv(65536)):
                    out.write(json.dumps({"pid": pid, "ts": ts}) + "\n")
            except Exception as exc:
                out.write(json.dumps({"error": type(exc).__name__}) + "\n")
                time.sleep(0.05)
finally:
    sock.close()
    (base / "netlink.stopped").write_text("stopped")
""")
PY
v bash -c 'rm -f /tmp/arx-b59/netlink.jsonl /tmp/arx-b59/netlink.ready /tmp/arx-b59/netlink.stop \
  /tmp/arx-b59/netlink.stopped /tmp/arx-b59/netlink-monitor.log /tmp/arx-b59/records.jsonl
  setsid nohup python3 /tmp/arx-b59/netlink-monitor.py >/tmp/arx-b59/netlink-monitor.log 2>&1 < /dev/null &'
check "observador netlink suscrito antes del lote" wait_for 20 v test -s /tmp/arx-b59/netlink.ready
check "cobertura completa inmediatamente antes del lote" kernel_full
v python3 -c 'import json
w = json.load(open("/var/lib/arx/watch.json"))
json.dump(w, open("/tmp/arx-b59/watch-before.json", "w"), indent=2)'

step "100 execs únicos e inmediatos; correspondencia uno a uno"
v python3 - <<'PY'
import json, os, shutil
from pathlib import Path
base = Path("/tmp/arx-b59")
for n in range(100):
    directory = Path("/dev/shm") if n >= 80 else base
    path = directory / f"arx-b59-ephemeral-{n:03d}"
    shutil.copyfile("/usr/bin/true", path)
    path.chmod(0o755)
    go = base / "queue" / f"direct-{n:03d}.go"
    tmp = go.with_suffix(".tmp")
    tmp.write_text(json.dumps({"path": str(path), "delete": True}))
    os.replace(tmp, go)
PY
records_100() {
  v python3 -c 'import json, os, sys
r = [json.loads(x) for x in open("/tmp/arx-b59/records.jsonl")]
ok = (len(r) == 100 and len({x["pid"] for x in r}) == 100
      and all(os.WIFEXITED(x["status"]) and os.WEXITSTATUS(x["status"]) == 0 for x in r)
      and sum(x["path"].startswith("/dev/shm/arx-b59-") for x in r) == 20)
sys.exit(0 if ok else 1)'
}
check "100 registros exactos, PID únicos, salida 0 y 20 tmpfs" wait_for 90 records_100
confirmed_100() {
  v python3 -c 'import json, sys
records = [json.loads(x) for x in open("/tmp/arx-b59/records.jsonl")]
events = []
for line in open("/tmp/arx-b59/netlink.jsonl"):
    try:
        events.append(json.loads(line))
    except json.JSONDecodeError:
        pass
confirmed = []
for record in records:
    hits = [e for e in events if e.get("pid") == record["pid"]]
    if len(hits) == 1:
        confirmed.append({"pid": record["pid"], "path": record["path"], "ts": hits[0]["ts"]})
errors = [e for e in events if "error" in e]
json.dump({"requested": len(records), "confirmed": len(confirmed), "monitor_errors": errors,
           "events": confirmed}, open("/tmp/arx-b59/confirmation.json", "w"), indent=2)
sys.exit(0 if len(records) == len(confirmed) == 100 and not errors else 1)'
}
check "100/100 execs confirmados una vez por netlink independiente" wait_for 30 confirmed_100
attributed_100() {
  v python3 -c 'import json, sys
records = [json.loads(x) for x in open("/tmp/arx-b59/records.jsonl")]
incidents = [json.loads(x) for x in open("/var/lib/arx/incidents.jsonl")]
found = []
for record in records:
    hits = [i for i in incidents if i.get("finding_kind") == "unexpected_exec"
            and i.get("target", {}).get("pid") == record["pid"]
            and i.get("target", {}).get("exe") == record["path"]]
    if len(hits) != 1:
        continue
    incident = hits[0]
    target = incident["target"]
    partial = "fanotify preserved its exec identity" in str(incident.get("detail", ""))
    reason = str(target.get("alert_reason", ""))
    consistent = (target.get("alert_only") is True and "retroactive containment is unavailable" in reason) \
        if partial else "retroactive containment is unavailable" not in reason
    if consistent and isinstance(target.get("start"), int):
        found.append({"pid": record["pid"], "path": record["path"], "start": target["start"],
                      "partial": partial, "alert_only": bool(target.get("alert_only"))})
json.dump({"attributed": len(found), "partial": sum(x["partial"] for x in found), "events": found},
          open("/tmp/arx-b59/attribution.json", "w"), indent=2)
sys.exit(0 if len(records) == len(found) == 100 else 1)'
}
check "100/100 incidentes emparejados por target PID+exe" wait_for 120 attributed_100
no_capture_loss() {
  v python3 -c 'import json, sys
before = json.load(open("/tmp/arx-b59/watch-before.json"))
w = json.load(open("/var/lib/arx/watch.json"))
b, c = before["process"], w["process"]
bc, cc = b["capture"], c["capture"]
keys = ("overflow", "dropped", "errors", "late", "expired")
deltas = {"netlink_lost": c["lost"] - b["lost"]}
deltas.update({key: cc[key] - bc[key] for key in keys})
evidence = {"watch_before": before, "watch_after": w, "loss_deltas": deltas,
            "confirmation": json.load(open("/tmp/arx-b59/confirmation.json")),
            "attribution": json.load(open("/tmp/arx-b59/attribution.json"))}
json.dump(evidence, open("/tmp/arx-b59/evidence.json", "w"), indent=2)
fresh = w.get("at", "") > before.get("at", "")
ok = (fresh and c["mode"] == "netlink" and cc["running"] and cc["mode"] == "full" and not cc["failed"]
      and all(value == 0 for value in deltas.values()))
sys.exit(0 if ok else 1)'
}
check "cobertura sigue full; pérdidas/errores/late/expirados en delta cero" wait_for 45 no_capture_loss
check "al menos una recuperación parcial, todas sin contención retroactiva" \
  v python3 -c 'import json
d = json.load(open("/tmp/arx-b59/attribution.json"))
assert d["attributed"] == 100 and d["partial"] >= 1, d
assert all(x["alert_only"] for x in d["events"] if x["partial"]), d'
v bash -c 'cp /tmp/arx-b59/records.jsonl /tmp/arx-b59/records-direct.jsonl; rm -f /tmp/arx-b59/records.jsonl'

step "10 cadenas script → re-exec: dos EXEC y el incidente final por PID"
v python3 - <<'PY'
import json, os, shutil
from pathlib import Path
base = Path("/tmp/arx-b59")
for n in range(10):
    path = base / f"arx-b59-reexec-{n:02d}"
    script = base / f"arx-b59-script-{n:02d}"
    shutil.copyfile("/usr/bin/true", path)
    path.chmod(0o755)
    script.write_text(f"#!/bin/sh\nexec {path}\n")
    script.chmod(0o755)
    go = base / "queue" / f"reexec-{n:02d}.go"
    tmp = go.with_suffix(".tmp")
    tmp.write_text(json.dumps({"path": str(path), "script": str(script), "delete": True}))
    os.replace(tmp, go)
PY
records_10() {
  v python3 -c 'import json, os, sys
r = [json.loads(x) for x in open("/tmp/arx-b59/records.jsonl")]
sys.exit(0 if len(r) == 10 and len({x["pid"] for x in r}) == 10
           and all(os.WIFEXITED(x["status"]) and os.WEXITSTATUS(x["status"]) == 0 for x in r) else 1)'
}
check "diez cadenas exactas terminaron con salida 0" wait_for 60 records_10
reexec_attributed() {
  v python3 -c 'import json, sys
records = [json.loads(x) for x in open("/tmp/arx-b59/records.jsonl")]
direct = [json.loads(x) for x in open("/tmp/arx-b59/records-direct.jsonl")]
events = []
for line in open("/tmp/arx-b59/netlink.jsonl"):
    try:
        events.append(json.loads(line))
    except json.JSONDecodeError:
        pass
incidents = [json.loads(x) for x in open("/var/lib/arx/incidents.jsonl")]
if {r["pid"] for r in records} & {r["pid"] for r in direct}:
    raise SystemExit(1)
found = []
for record in records:
    execs = sorted((e for e in events if e.get("pid") == record["pid"]), key=lambda e: e["ts"])
    hits = [i for i in incidents if i.get("finding_kind") == "unexpected_exec"
            and i.get("target", {}).get("pid") == record["pid"]
            and i.get("target", {}).get("exe") == record["path"]]
    if len(execs) == 2 and len({e["ts"] for e in execs}) == 2 and len(hits) == 1:
        found.append({"pid": record["pid"], "path": record["path"], "netlink": execs,
                      "partial": "fanotify preserved its exec identity" in str(hits[0].get("detail", ""))})
errors = [e for e in events if "error" in e]
json.dump({"chains": len(found), "monitor_errors": errors, "events": found},
          open("/tmp/arx-b59/reexec.json", "w"), indent=2)
sys.exit(0 if len(records) == len(found) == 10 and not errors else 1)'
}
check "10/10 tienen dos timestamps EXEC y un incidente final PID+exe" wait_for 90 reexec_attributed
v touch /tmp/arx-b59/netlink.stop
check "observador netlink cerrado ordenadamente" wait_for 20 v test -s /tmp/arx-b59/netlink.stopped
check "JSONL netlink final completo y sin errores" v python3 -c 'import json
e = [json.loads(x) for x in open("/tmp/arx-b59/netlink.jsonl")]
assert not any("error" in x for x in e)'

step "subprocess propio: el exec no puede retener el GIL del listener"
v python3 - <<'PY'
from pathlib import Path
Path("/tmp/arx-b59/spawn-probe.py").write_text(r"""import faulthandler, json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import execfanwatch as watch
base = Path("/tmp/arx-b59")
before = subprocess._USE_POSIX_SPAWN
coverage = watch.start("")
after = subprocess._USE_POSIX_SPAWN
faulthandler.dump_traceback_later(8)
try:
    assert coverage == "full", coverage
    assert after is False, "CPython posix_spawn would hold the GIL until the intercepted exec"
    result = subprocess.run(["/usr/bin/true"], capture_output=True, timeout=10)
    status = watch.status()
    assert result.returncode == 0, result.returncode
    assert status["running"] and status["responses"] >= 1, status
    (base / "spawn-done.json").write_text(json.dumps({
        "coverage": coverage, "posix_spawn_before": before, "posix_spawn_after": after,
        "returncode": result.returncode, "responses": status["responses"],
        "watcher_mode": status["mode"], "watcher_running": status["running"]}))
finally:
    faulthandler.cancel_dump_traceback_later()
    watch.stop()
""")
PY
spawn_probe() {
  v timeout --signal=KILL --kill-after=2 20 python3 /tmp/arx-b59/spawn-probe.py && \
    v python3 -c 'import json; d = json.load(open("/tmp/arx-b59/spawn-done.json"))
assert d["returncode"] == 0 and d["posix_spawn_after"] is False and d["responses"] >= 1, d'
}
check "subprocess.run termina y el listener responde sin quedar retenido por el GIL" spawn_probe

step "lector bloqueado y vigilante matado: permisos realmente pendientes"
v python3 - <<'PY'
from pathlib import Path
base = Path("/tmp/arx-b59")
(base / "failopen-watcher.py").write_text(r"""import json, os, sys, time
from pathlib import Path
sys.path.insert(0, "/usr/lib/arx/arx.pyz")
from arx.modules import execfanwatch as watch
mode = sys.argv[1]
base = Path("/tmp/arx-b59")
def save(name, data):
    path = base / f"{mode}-{name}.json"
    tmp = base / f"{mode}-{name}.tmp"
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)
target_path = base / f"{mode}-target.pid"
original = watch._snapshot
def capturing(efd, pid, root):
    try:
        target = int(target_path.read_text())
    except (OSError, ValueError):
        target = -1
    if pid == target:
        save("blocked", {"watcher": os.getpid(), "pid": pid, "efd": efd,
                         "blocked_at": time.monotonic()})
        time.sleep(30)
        return None
    return original(efd, pid, root)
watch._snapshot = capturing
coverage = watch.start("")
if coverage != "full":
    save("ready", {"watcher": os.getpid(), "mode": coverage})
    watch.stop()
    raise SystemExit(2)
save("ready", {"watcher": os.getpid(), "mode": coverage,
               "start": watch._stat(os.getpid())[1]})
try:
    while not (base / f"{mode}-stop").exists():
        save("status", watch.status())
        time.sleep(0.05)
finally:
    watch.stop()
""")
(base / "failopen-controller.py").write_text(r"""import json, os, signal, subprocess, sys, time
from pathlib import Path
mode = sys.argv[1]
base = Path("/tmp/arx-b59")
for path in base.glob(f"{mode}-*"):
    if path.is_file():
        path.unlink()
def save(name, data):
    (base / f"{mode}-{name}.json").write_text(json.dumps(data))
def load(name):
    try:
        return json.loads((base / f"{mode}-{name}.json").read_text())
    except (OSError, ValueError):
        return None
def wait_for(name, predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = load(name)
        if data is not None and predicate(data):
            return data
        time.sleep(0.02)
    raise AssertionError(f"timeout waiting for {mode}-{name}")
watcher = subprocess.Popen([sys.executable, str(base / "failopen-watcher.py"), mode])
pidfd = os.pidfd_open(watcher.pid)
child = None
try:
    ready = wait_for("ready", lambda d: d.get("watcher") == watcher.pid)
    assert ready["mode"] == "full", ready
    assert watcher.poll() is None
    child = os.fork()
    if child == 0:
        try:
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execv("/usr/bin/true", ["/usr/bin/true"])
        finally:
            os._exit(127)
    _, stopped = os.waitpid(child, os.WUNTRACED)
    assert os.WIFSTOPPED(stopped)
    (base / f"{mode}-target.pid").write_text(str(child))
    started = time.monotonic()
    save("probe", {"watcher": watcher.pid, "watcher_start": ready["start"],
                   "child": child, "mode": ready["mode"]})
    os.kill(child, signal.SIGCONT)
    marker = wait_for("blocked", lambda d: d.get("pid") == child
                      and d.get("watcher") == watcher.pid and d.get("efd", -1) >= 0)
    assert watcher.poll() is None
    assert load("done") is None
    waited, status = os.waitpid(child, os.WNOHANG)
    assert (waited, status) == (0, 0), "child was not held by fanotify"
    current = wait_for("status", lambda d: d.get("running") is True and d.get("mode") == "full")
    assert current["failed"] == []
    if mode == "kill":
        assert time.monotonic() - marker["blocked_at"] < 3, "watchdog won the race"
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        watcher.wait(timeout=5)
        deadline = time.monotonic() + 15
        while True:
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited == child:
                break
            if time.monotonic() >= deadline:
                raise AssertionError("killed watcher did not release the exec")
            time.sleep(0.02)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
        elapsed = time.monotonic() - started
        save("done", {"mode": "killed", "returncode": os.WEXITSTATUS(status),
                      "elapsed": elapsed, "watcher_returncode": watcher.returncode,
                      "blocked_pid": child, "blocked_efd": marker["efd"]})
    else:
        deadline = time.monotonic() + 15
        while True:
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited == child:
                break
            if time.monotonic() >= deadline:
                raise AssertionError("watchdog did not release the exec")
            time.sleep(0.02)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
        elapsed = time.monotonic() - started
        assert elapsed < 15, elapsed
        degraded = wait_for("status", lambda d: d.get("running") is False
                            and d.get("mode") == "degraded")
        save("done", {"mode": degraded["mode"], "returncode": os.WEXITSTATUS(status),
                      "elapsed": elapsed, "blocked_pid": child, "blocked_efd": marker["efd"]})
finally:
    if child is not None:
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
            if waited == 0:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
        except ChildProcessError:
            pass
    if watcher.poll() is None:
        (base / f"{mode}-stop").write_text("stop")
        try:
            watcher.wait(timeout=3)
        except subprocess.TimeoutExpired:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            watcher.wait(timeout=5)
    os.close(pidfd)
""")
PY
watchdog_probe() {
  v python3 /tmp/arx-b59/failopen-controller.py watchdog && \
    v python3 -c 'import json; d = json.load(open("/tmp/arx-b59/watchdog-done.json")); assert d["returncode"] == 0 and d["elapsed"] < 15 and d["mode"] == "degraded", d'
}
check "watchdog libera el PID marcado como retenido en menos de 15 s" watchdog_probe
kill_probe() {
  v python3 /tmp/arx-b59/failopen-controller.py kill && \
    v python3 -c 'import json; d = json.load(open("/tmp/arx-b59/kill-done.json")); assert d["returncode"] == 0 and d["elapsed"] < 15 and d["mode"] == "killed" and d["watcher_returncode"] == -9, d'
}
check "pidfd + SIGKILL liberan ese mismo exec antes del watchdog" kill_probe

step "evidencia y limpieza"
check "evidencia consolidada y cobertura final preservada" v python3 - <<'PY'
import json
from pathlib import Path
base = Path("/tmp/arx-b59")
evidence = json.loads((base / "evidence.json").read_text())
evidence["reexec"] = json.loads((base / "reexec.json").read_text())
evidence["spawn"] = json.loads((base / "spawn-done.json").read_text())
evidence["failopen"] = {mode: json.loads((base / f"{mode}-done.json").read_text())
                        for mode in ("watchdog", "kill")}
evidence["netlink_closed"] = (base / "netlink.stopped").exists()
(base / "evidence.json").write_text(json.dumps(evidence, indent=2))
(base / "watch-final.json").write_bytes(Path("/var/lib/arx/watch.json").read_bytes())
(base / "incidents.jsonl").write_bytes(Path("/var/lib/arx/incidents.jsonl").read_bytes())
assert evidence["netlink_closed"]
PY
v bash -c 'systemctl disable --now arx-b59-runner >/dev/null 2>&1; rm -f /tmp/arx-b59/queue/*.go'
check "SHA-256 de la evidencia" v sh -c 'sha256sum /tmp/arx-b59/evidence.json /tmp/arx-b59/incidents.jsonl /tmp/arx-b59/netlink.jsonl /tmp/arx-b59/watch-final.json'
echo
[ "$FAILED" = 0 ] && echo "══ LAB B59 COMPLETO ══" || echo "══ LAB B59 CON FALLOS (ver [FAIL]) ══"
exit "$FAILED"
