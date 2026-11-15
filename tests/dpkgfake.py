"""Un dpkg simulado detrás de `maintenance.run`, para medir cuántas consultas hace Arx (B78).

Cada `dpkg-query` o `apt-cache` abriría un scope de systemd en el host: `queries()` es ese número. El simulador
responde a `dpkg-query -W` (inventario y un paquete, con el formato `-f=` que pida quien llama), a
`dpkg-query -S` (con líneas de desvío) y a `systemctl show` (MainPID y FragmentPath), y deja que una prueba haga
que dpkg «cambie» (`touch()`), falle (`fail`) o cambie a mitad de una consulta (`hook`).
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import tempfile
from unittest import mock

from arx.modules import maintenance


class _R:
    def __init__(self, returncode, stdout):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


class FakeDpkg:
    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.status, self.updates = os.path.join(self.dir, "status"), os.path.join(self.dir, "updates")
        self.diversions = os.path.join(self.dir, "diversions")
        os.mkdir(self.updates)
        # (nombre, arquitectura) → (versión, source:Package, source:Version)
        self.packages: dict = {}
        self.files: dict = {}        # ruta → paquete dueño
        self.diverted: set = set()   # rutas que dpkg lista con líneas «diversion by»
        self.main_pid: dict = {}     # unit → MainPID
        self.fragment: dict = {}     # unit → FragmentPath
        self.calls: list = []
        self.fail: str | None = None  # "busy" | "timeout" | "exit2" | "oserror"
        self.hook = None              # se llama en cada dpkg-query antes de leer la base
        self.after = None             # ... y esto después de leerla, antes de devolver la respuesta
        self.version = 0
        self.touch()

    # ── lo que cambia dpkg ────────────────────────────────────────────────────
    def touch(self) -> None:
        """Una transacción de dpkg terminada: status nuevo (otro inodo), como hace dpkg con status-new."""
        self.version += 1
        tmp = self.status + ".new"
        with open(tmp, "w") as f:
            f.write(f"generation {self.version}\n")
        os.replace(tmp, self.status)

    def install(self, name, version, arch="amd64", source=None, source_version=None, owns=()):
        self.packages[(name, arch)] = (version, source or name, source_version or version)
        for path in owns:
            self.files[path] = name
        self.touch()

    # ── la vía de ejecución ───────────────────────────────────────────────────
    def run(self, argv, **kw):
        self.calls.append(list(argv))
        name = os.path.basename(argv[0])
        if name in ("dpkg-query", "apt-cache") and self.fail:
            if self.fail == "busy":
                raise maintenance.SlotBusy("slot busy")
            if self.fail == "timeout":
                raise subprocess.TimeoutExpired(argv, 1)
            if self.fail == "exit2":
                return _R(2, "")
            if self.fail == "oserror":
                raise PermissionError("cannot exec")
        if name == "dpkg-query":
            if self.hook:
                self.hook(argv)
            reply = self._dpkg_query(argv)
            if self.after:
                self.after(argv)
            return reply
        if name == "systemctl":
            return self._systemctl(argv)
        return _R(1, "")

    def _fields(self, name, arch):
        version, source, source_version = self.packages[(name, arch)]
        return {"Package": name, "Architecture": arch, "Version": version, "source:Package": source,
                "source:Version": source_version}

    def _dpkg_query(self, argv):
        if "-W" in argv:
            fmt = next(a[3:] for a in argv if a.startswith("-f="))
            wanted = [a for a in argv[2:] if not a.startswith("-")]
            rows = []
            for (name, arch) in sorted(self.packages):
                if wanted and not any(w in (name, f"{name}:{arch}") for w in wanted):
                    continue
                rows.append(re.sub(r"\$\{([^}]+)\}", lambda m: self._fields(name, arch)[m.group(1)], fmt))
            return _R(0 if rows else 1, "".join(rows))
        if "-S" in argv:
            out, found = [], 0
            for pattern in argv[argv.index("-S") + 1:]:
                # como dpkg: con comodines un patrón; sin «/» inicial, una subcadena; si no, la ruta exacta
                if any(c in pattern for c in "*?[\\"):
                    paths = [p for p in sorted(self.files) if fnmatch.fnmatchcase(p, pattern)]
                elif not pattern.startswith("/"):
                    paths = [p for p in sorted(self.files) if pattern in p]
                else:
                    paths = [pattern] if pattern in self.files else []
                if pattern in self.diverted:
                    out += [f"diversion by dash from: {pattern}", f"diversion by dash to: {pattern}.distrib"]
                for path in paths:
                    out.append(f"{self.files[path]}: {path}")
                    found += 1
            return _R(0 if found else 1, "".join(line + "\n" for line in out))
        return _R(1, "")

    def _systemctl(self, argv):
        unit = argv[-1]
        if "MainPID" in argv:
            return _R(0, f"{self.main_pid.get(unit, 0)}\n")
        if "FragmentPath" in argv:
            return _R(0, f"FragmentPath={self.fragment.get(unit, '')}\nDropInPaths=\n")
        return _R(1, "")

    # ── lo que se contó ───────────────────────────────────────────────────────
    def count(self, kind: str) -> int:
        """«inventory» (-W de todo), «single» (-W de un paquete) o «search» (-S)."""
        n = 0
        for argv in self.calls:
            if os.path.basename(argv[0]) != "dpkg-query":
                continue
            if "-S" in argv:
                n += kind == "search"
            elif "-W" in argv:
                is_inventory = not [a for a in argv[2:] if not a.startswith("-")]
                n += kind == ("inventory" if is_inventory else "single")
        return n

    def queries(self) -> int:
        """Cada dpkg-query o apt-cache abre un scope: este es el número del que depende el journal."""
        return sum(os.path.basename(a[0]) in ("dpkg-query", "apt-cache") for a in self.calls)


def fake_world(testcase) -> FakeDpkg:
    """Un dpkg simulado conectado a `maintenance.run` y a las rutas de `pkgdb`; se deshace solo al acabar."""
    from arx.modules import pkgdb, profile, provenance, trust
    fake = FakeDpkg()
    verdict = {"state": "done", "trusted": True, "score": 1.0, "reason": "ok", "checks": []}
    patchers = [mock.patch.object(maintenance, "run", fake.run),
                mock.patch.object(profile, "_investigate_later", lambda *a, **k: None),
                mock.patch.object(trust, "assess_async", lambda pkg, deep=True, urgent=False: dict(verdict))]
    for name, value in (("STATUS", fake.status), ("UPDATES", fake.updates), ("DIVERSIONS", fake.diversions)):
        patchers.append(mock.patch.object(pkgdb, name, value))
    for patcher in patchers:
        patcher.start()
        testcase.addCleanup(patcher.stop)
    pkgdb.clear()
    provenance.clear_cache()
    testcase.addCleanup(pkgdb.clear)
    testcase.addCleanup(provenance.clear_cache)
    return fake
