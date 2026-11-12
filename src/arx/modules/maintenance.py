"""Arx · auxiliares de mantenimiento fuera del presupuesto de memoria del guardián.

Dentro de ``arx.service``, APT/dpkg nace directamente en un scope hermano de
``arx-maintenance.slice``. Crear el proceso dentro de Arx y moverlo después dejaría
una ventana de OOM y no resolvería el límite jerárquico de su memcg.

Si systemd no puede crear ese scope, la operación queda indisponible: nunca se
reintenta dentro de Arx. Las CLI independientes conservan la ejecución directa.
"""
from __future__ import annotations

import itertools
import os
import shutil
import subprocess
import threading
import time

SLICE = "arx-maintenance.slice"
CGROUP = "/proc/self/cgroup"
CGROUP_ROOT = "/sys/fs/cgroup"
LOCK_WAIT_S = 5
STOP_TIMEOUT_S = 5
CLEANUP_WAIT_S = 5
_HEAVY = {
    "apt", "apt-get", "apt-cache", "apt-helper", "dpkg", "dpkg-deb",
    "dpkg-query", "dpkg-split", "dpkg-trigger",
}
# No se vuelca os.environ en propiedades systemd: podría contener secretos. Estas
# variables bastan para conservar la resolución, el idioma analizado y el modo apt.
_ENV_KEYS = {
    "PATH", "LANG", "LANGUAGE", "LC_ALL", "DEBIAN_FRONTEND", "DEBIAN_PRIORITY",
    "APT_CONFIG", "DPKG_ADMINDIR", "DPKG_ROOT",
}
_heavy_lock = threading.Lock()
_counter = itertools.count()


class MaintenanceUnavailable(OSError):
    """El daemon no pudo crear el entorno aislado; el auxiliar no se ejecutó."""


def _in_arx_service() -> bool:
    """La unidad final del cgroup v2, no una coincidencia textual en otra jerarquía."""
    try:
        with open(CGROUP, encoding="utf-8") as fh:
            for line in fh:
                if not line.startswith("0::"):
                    continue
                parts = line.strip()[3:].strip("/").split("/")
                if parts and parts[-1] == "arx.service":
                    return True
    except OSError:
        pass
    return False


def _is_heavy(argv: list[str]) -> bool:
    return bool(argv) and os.path.basename(str(argv[0])) in _HEAVY


def _scope_launch(argv: list[str], cwd: str | None, env: dict | None) -> tuple[list[str], str]:
    runner = shutil.which("systemd-run")
    if not runner:
        raise MaintenanceUnavailable("systemd-run is unavailable inside arx.service")
    if cwd is None:
        try:
            cwd = os.getcwd()
        except OSError:
            cwd = "/"
    cwd = os.path.abspath(cwd)
    scope = f"arx-maint-{os.getpid()}-{time.monotonic_ns()}-{next(_counter)}.scope"
    launch = [
        runner, "--system", "--scope", "--quiet", "--collect",
        f"--unit={scope}", f"--slice={SLICE}", f"--working-directory={cwd}",
        "--property=BindsTo=arx.service", "--property=After=arx.service",
        "--property=TimeoutStopSec=15",
    ]
    source = os.environ if env is None else env
    for key, value in source.items():
        if (key in _ENV_KEYS or key.startswith("LC_")) and isinstance(value, str) \
                and "\0" not in value and "=" not in key:
            launch.append(f"--setenv={key}={value}")
    return [*launch, "--", *argv], scope


def _kill_cgroup(scope: str) -> bool:
    """Sin D-Bus todavía podemos matar el cgroup completo; matar solo systemd-run no basta."""
    try:
        with open(os.path.join(CGROUP_ROOT, SLICE, scope, "cgroup.kill"), "w", encoding="ascii") as fh:
            fh.write("1")
        return True
    except OSError:
        return False


class MaintenanceProcess:
    """Popen con identidad del scope y limpieza del árbol completo en salidas anómalas."""

    def __init__(self, raw, argv: list[str], scope: str | None = None,
                 serialized: bool = False):
        self._raw = raw
        self._argv = argv
        self._scope = scope
        self._serialized = serialized
        self._released = not serialized
        self._scope_stopped = False
        self._closed = False

    def __getattr__(self, name):
        return getattr(self._raw, name)

    @property
    def args(self):
        return self._argv

    @property
    def returncode(self):
        return self._raw.returncode

    def _release(self) -> None:
        if not self._released:
            self._released = True
            _heavy_lock.release()

    def _stop_scope(self) -> bool:
        if not self._scope:
            return True
        if self._scope_stopped:
            return True
        try:
            result = subprocess.run(
                ["systemctl", "stop", self._scope], capture_output=True,
                text=True, timeout=STOP_TIMEOUT_S, check=False)
            stopped = getattr(result, "returncode", 1) == 0
        except (OSError, subprocess.TimeoutExpired):
            stopped = False
        if not stopped:
            stopped = _kill_cgroup(self._scope)
        self._scope_stopped = stopped
        return stopped

    def poll(self):
        result = self._raw.poll()
        if result is not None:
            self._release()
        return result

    def wait(self, timeout: float | None = None):
        try:
            result = self._raw.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._stop_scope()
            raise
        except BaseException:
            self.close()
            raise
        self._release()
        return result

    def communicate(self, input=None, timeout: float | None = None):
        try:
            result = self._raw.communicate(input=input, timeout=timeout)
        except subprocess.TimeoutExpired:
            self._stop_scope()
            raise
        except BaseException:
            self.close()
            raise
        self._release()
        return result

    def terminate(self) -> None:
        self._stop_scope()
        self._raw.terminate()

    def kill(self) -> None:
        self._stop_scope()
        self._raw.kill()

    def close(self) -> None:
        """Cerrar un stream antes de EOF no puede dejar tar/dpkg vivo ni la cola bloqueada."""
        if self._closed:
            return
        self._closed = True
        try:
            if self._raw.poll() is None:
                self._stop_scope()
                try:
                    self._raw.kill()
                except OSError:
                    pass
            try:
                self._raw.wait(timeout=CLEANUP_WAIT_S)
            except subprocess.TimeoutExpired:
                self._stop_scope()
                try:
                    self._raw.kill()
                except OSError:
                    pass
                try:
                    self._raw.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        except OSError:
            self._stop_scope()
        finally:
            for stream in (self._raw.stdin, self._raw.stdout, self._raw.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass
            self._release()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.close()
            return False
        try:
            return self._raw.__exit__(exc_type, exc, tb)
        finally:
            self._release()


def Popen(argv: list[str], cwd: str | None = None, env: dict | None = None,
          **kwargs) -> MaintenanceProcess:
    """Popen sin shell; en el daemon, el argv pesado va detrás de systemd-run."""
    if kwargs.get("shell"):
        raise ValueError("maintenance helpers never use a shell")
    isolated = _in_arx_service() and _is_heavy(argv)
    launch, scope = _scope_launch(argv, cwd, env) if isolated else (list(argv), None)
    if isolated:
        if not _heavy_lock.acquire(timeout=LOCK_WAIT_S):
            raise MaintenanceUnavailable("another APT/dpkg helper still owns the maintenance slot")
    try:
        raw = subprocess.Popen(launch, cwd=None if isolated else cwd,
                               env=None if isolated else env, **kwargs)
    except BaseException as exc:
        if isolated:
            _heavy_lock.release()
            if isinstance(exc, OSError):
                raise MaintenanceUnavailable(f"could not create {scope}: {exc}") from exc
        raise
    return MaintenanceProcess(raw, list(argv), scope=scope, serialized=isolated)


def run(argv: list[str], input=None, capture_output: bool = False,
        timeout: float | None = None, check: bool = False,
        cwd: str | None = None, env: dict | None = None, **kwargs) -> subprocess.CompletedProcess:
    """CompletedProcess con el argv original y timeout que detiene también el scope."""
    if capture_output:
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    if input is not None:
        kwargs.setdefault("stdin", subprocess.PIPE)
    proc = Popen(argv, cwd=cwd, env=env, **kwargs)
    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            stdout, stderr = proc.communicate(timeout=CLEANUP_WAIT_S)
        except Exception:
            stdout, stderr = None, None
        finally:
            proc.close()
        raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr) from None
    except BaseException:
        proc.close()
        raise
    if check and proc.returncode:
        raise subprocess.CalledProcessError(proc.returncode, argv, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def stop_all() -> list[str]:
    """Detiene scopes internos que hubieran sobrevivido a una versión anterior o a un fallo."""
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=scope", "--all", "--plain", "--no-legend"],
            capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    names = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            fields = line.split()
            if fields and fields[0].startswith("arx-maint-") and fields[0].endswith(".scope"):
                names.append(fields[0])
    for name in names:
        try:
            subprocess.run(["systemctl", "stop", name], capture_output=True,
                           text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return names
