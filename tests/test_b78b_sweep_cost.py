"""B78-b · Parte 2: el barrido en reposo (perfil de CPU de la pista I, `pistas/i/cpu-reposo.md`). Cada propuesta, con la
prueba de que lo que veía, lo sigue viendo en el mismo barrido.

P4: el estado solo se escribe si cambió (cinco ficheros por barrido, con fsync, aunque nada hubiera cambiado).
Corre con: python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _isolate():
    d = tempfile.mkdtemp()
    os.environ["ARX_CONFIG_DIR"] = os.path.join(d, "cfg")
    os.environ["ARX_STATE_DIR"] = os.path.join(d, "state")
    os.environ["ARX_POLAR_ENV"] = "sandbox"
    return d


class WriteOnlyIfChangedTests(unittest.TestCase):
    """P4 · `config.write_json` no toca el disco si lo que va a escribir es lo que ya hay."""

    def setUp(self):
        self.d = _isolate()
        from arx import config
        self.c = config
        config._last_written.clear()
        self.path = Path(self.d) / "state" / "x.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def replaces(self):
        """Cuántas veces se renombró un temporal sobre el destino (= cuántas escrituras reales)."""
        return mock.patch.object(self.c.os, "replace", wraps=os.replace)

    def test_the_same_content_is_not_written_again(self):
        with self.replaces() as rep:
            self.c.write_json(self.path, {"a": 1})
            self.c.write_json(self.path, {"a": 1})
            self.c.write_json(self.path, {"a": 1})
        self.assertEqual(rep.call_count, 1)
        self.assertEqual(json.loads(self.path.read_text()), {"a": 1})

    def test_changed_content_is_written(self):
        with self.replaces() as rep:
            self.c.write_json(self.path, {"a": 1})
            self.c.write_json(self.path, {"a": 2})
            self.c.write_json(self.path, {"a": 2})
        self.assertEqual(rep.call_count, 2)
        self.assertEqual(json.loads(self.path.read_text()), {"a": 2})

    def test_a_file_changed_behind_our_back_is_rewritten(self):
        """Otro proceso (la CLI: `arx accept`) pudo cambiarlo: lo que hay en disco manda sobre lo que se recuerda."""
        self.c.write_json(self.path, {"a": 1})
        self.path.write_text('{"a": 99}')  # alguien lo cambia (mismo tamaño, distinta fecha)
        os.utime(self.path, ns=(1, 1))
        with self.replaces() as rep:
            self.c.write_json(self.path, {"a": 1})
        self.assertEqual(rep.call_count, 1)
        self.assertEqual(json.loads(self.path.read_text()), {"a": 1})

    def test_a_deleted_file_is_written_again(self):
        self.c.write_json(self.path, {"a": 1})
        self.path.unlink()
        with self.replaces() as rep:
            self.c.write_json(self.path, {"a": 1})
        self.assertEqual(rep.call_count, 1)
        self.assertTrue(self.path.exists())

    def test_a_replaced_file_with_the_same_text_is_rewritten_only_if_it_is_another_file(self):
        self.c.write_json(self.path, {"a": 1})
        text = self.path.read_text()
        self.path.unlink()
        self.path.write_text(text)  # otro inodo, mismo texto
        with self.replaces() as rep:
            self.c.write_json(self.path, {"a": 1})
        self.assertEqual(rep.call_count, 1)  # no se fía: lo que hay no es lo que escribimos nosotros

    def test_each_path_is_remembered_on_its_own(self):
        other = self.path.with_name("y.json")
        with self.replaces() as rep:
            self.c.write_json(self.path, {"a": 1})
            self.c.write_json(other, {"a": 1})
            self.c.write_json(self.path, {"a": 1})
            self.c.write_json(other, {"a": 1})
        self.assertEqual(rep.call_count, 2)

    def test_the_private_mode_and_atomic_write_are_kept(self):
        self.c.write_json(self.path, {"a": 1})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual([p for p in self.path.parent.iterdir() if p.name.endswith(".tmp")], [])

    def test_a_failed_write_is_not_remembered_as_done(self):
        with mock.patch.object(self.c.os, "fsync", side_effect=OSError("disco lleno")):
            with self.assertRaises(OSError):
                self.c.write_json(self.path, {"a": 1})
        self.assertFalse(self.path.exists())
        self.c.write_json(self.path, {"a": 1})  # el reintento escribe de verdad
        self.assertEqual(json.loads(self.path.read_text()), {"a": 1})

    def test_the_memory_of_written_files_is_bounded(self):
        for i in range(self.c.WRITE_MEMORY_MAX + 40):
            self.c.write_json(self.path.with_name(f"f{i}.json"), {"i": i})
        self.assertLessEqual(len(self.c._last_written), self.c.WRITE_MEMORY_MAX)

    def test_non_utf8_content_still_round_trips(self):
        data = {"p": "ruta-\udcff"}
        self.c.write_json(self.path, data)
        self.c.write_json(self.path, data)
        self.assertEqual(json.loads(self.path.read_text())["p"], "ruta-\udcff")


class SweepStateIsQuietTests(unittest.TestCase):
    """Lo que el barrido escribe cada vez: con el estado igual, ningún fichero se reescribe."""

    def test_the_mode_marker_is_not_rewritten_every_loop(self):
        d = _isolate()
        from arx import config
        config._last_written.clear()
        path = config.state_dir() / "guard_mode.json"
        with mock.patch.object(config.os, "replace", wraps=os.replace) as rep:
            for _ in range(5):
                config.write_json(path, {"enforce": True})
        self.assertEqual(rep.call_count, 1)
        self.assertTrue(d)


class SshdAllowedRefreshTests(unittest.TestCase):
    """P7 · `sshd -T` y la lectura de sus ficheros no se repiten cada minuto: cada 15 min por edad, y AL INSTANTE si cambia
    algo de lo que se leyó (el sello de cada fichero y de cada directorio incluido)."""

    def setUp(self):
        _isolate()
        import time
        from arx.modules import execwatch, profile
        self.x, self.p, self.time = execwatch, profile, time
        self.d = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.d, "sshd_config.d"))
        self.conf = os.path.join(self.d, "sshd_config")
        open(self.conf, "w").write("Include sshd_config.d/*.conf\n")
        self.now = [5000.0]
        self.runs = []

        class R:
            returncode, stdout = 0, "port 22\n"

        def run(argv, **kw):
            self.runs.append(list(argv))
            return R()
        for obj, name, value in ((execwatch, "SSHD_CONFIG", self.conf), (execwatch.subprocess, "run", run),
                                 (execwatch.time, "monotonic", lambda: self.now[0]),
                                 (profile, "load", lambda: {})):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(execwatch._allow.update, at=0.0, paths=set(), sure=False, stamps={})
        execwatch._allow.update(at=0.0, paths=set(), sure=False, stamps={})
        self.x.sshd_allowed(refresh=True)
        self.runs.clear()

    def test_the_default_is_fifteen_minutes_not_one(self):
        self.assertEqual(self.x.ALLOW_REFRESH_S, 900)

    def test_nothing_changed_nothing_is_read_for_fifteen_minutes(self):
        for minute in range(1, 15):
            self.now[0] = 5000.0 + 60 * minute
            self.x.sshd_allowed()
        self.assertEqual(self.runs, [])

    def test_after_fifteen_minutes_it_is_read_again(self):
        self.now[0] = 5000.0 + self.x.ALLOW_REFRESH_S + 1
        self.x.sshd_allowed()
        self.assertEqual(len(self.runs), 1)

    def test_a_command_the_admin_adds_is_seen_at_once_not_after_fifteen_minutes(self):
        inc = os.path.join(self.d, "sshd_config.d", "50-ldap.conf")
        open(inc, "w").write("Match Group staff\n  AuthorizedKeysCommand /usr/local/bin/akc %u\n")
        os.utime(inc, ns=(self.time.time_ns() + 10**9, self.time.time_ns() + 10**9))
        self.now[0] += 5  # cinco segundos después, no quince minutos
        self.assertIn("/usr/local/bin/akc", self.x.sshd_allowed())

    def test_a_new_file_in_the_included_directory_is_seen_at_once(self):
        d = os.path.join(self.d, "sshd_config.d")
        open(os.path.join(d, "60-new.conf"), "w").write("Match Group g\n  AuthorizedKeysCommand /usr/local/bin/new %u\n")
        os.utime(d, ns=(self.time.time_ns() + 10**9, self.time.time_ns() + 10**9))
        self.now[0] += 5
        self.assertIn("/usr/local/bin/new", self.x.sshd_allowed(hot=True))

    def test_the_hot_path_of_an_exec_never_waits_for_sshd_dash_T(self):
        self.now[0] += 3600
        self.x.sshd_allowed(hot=True)
        self.assertEqual(self.runs, [])  # el camino caliente solo relee si cambió algo, nunca por edad

    def test_a_forced_refresh_still_reads_at_once(self):
        self.x.sshd_allowed(refresh=True)
        self.assertEqual(len(self.runs), 1)


class ScanTrackCadenceTests(unittest.TestCase):
    """P3 (b) · la pista de escaneo del kernel dura 10 min: se lee cada 60 s, no cada 30."""

    def setUp(self):
        _isolate()
        from arx.modules import sensors
        self.s = sensors
        sensors._scan_read.update(at=None, nft=False)
        self.addCleanup(sensors._scan_read.update, at=None, nft=False)
        self.reads = []
        self.hits = {}
        patches = [mock.patch.object(sensors, "_scan_from_nft", self._read),
                   mock.patch.object(sensors.recon, "local_ips", lambda: set())]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(sensors._scan_read.update, at=None, nft=False)

    def _read(self):
        self.reads.append(1)
        return None if self.hits is None else {ip: set(ports) for ip, ports in self.hits.items()}

    def scan(self, ip="203.0.113.9", n=20):
        return {ip: range(1000, 1000 + n)}

    def test_it_is_read_every_sixty_seconds_not_every_sweep(self):
        for i in range(20):  # 10 min de barridos de 30 s
            self.s.detect_port_scan(now=1_000_000.0 + 30 * i)
        self.assertEqual(len(self.reads), 10)

    def test_a_scan_is_reported_in_the_sweep_that_reads_the_track(self):
        self.hits = self.scan()
        first = self.s.detect_port_scan(now=1_000_000.0)
        self.assertEqual([e["target"]["ip"] for e in first], ["203.0.113.9"])
        self.assertEqual(self.s.detect_port_scan(now=1_000_030.0), [])  # el barrido sin lectura no repite el aviso
        again = self.s.detect_port_scan(now=1_000_060.0)  # la lectura siguiente lo vuelve a ver (se deduplica aguas abajo)
        self.assertEqual(len(again), 1)

    def test_a_scan_that_starts_between_reads_is_seen_within_a_minute(self):
        self.s.detect_port_scan(now=1_000_000.0)
        self.hits = self.scan()
        self.assertEqual(self.s.detect_port_scan(now=1_000_030.0), [])
        self.assertEqual(len(self.s.detect_port_scan(now=1_000_060.0)), 1)

    def test_a_clock_that_goes_back_does_not_leave_the_track_unread(self):
        self.s.detect_port_scan(now=1_000_000.0)
        self.hits = self.scan()
        self.assertEqual(len(self.s.detect_port_scan(now=900_000.0)), 1)

    def test_without_the_kernel_track_the_fallback_still_runs_every_sweep(self):
        self.hits = None  # sin nft
        with mock.patch.object(self.s.recon, "collect_connections", lambda: []), \
                mock.patch.object(self.s.recon, "collect_ports", lambda: []):
            for i in range(6):
                self.s.detect_port_scan(now=1_000_000.0 + 30 * i)
        self.assertEqual(len(self.reads), 6)


class TablePresenceByNetlinkTests(unittest.TestCase):
    """P3 (a) · ¿existe `table inet arx`? Se le pregunta al kernel por netlink (NFT_MSG_GETTABLE), sin lanzar `nft list tables`
    (3,7 ms de CPU por barrido). Misma respuesta, en el mismo barrido; si el kernel no contesta como se espera, `nft` de
    respaldo."""

    NEWTABLE = (10 << 8) | 0
    ERROR = 2

    def setUp(self):
        _isolate()
        from arx.modules import response, sweepcache
        self.r, self.sc = response, sweepcache
        sweepcache.end_sweep()
        sweepcache._owner[0] = None
        self.sent, self.reply = [], b""
        self.listed = []
        outer = self

        class Sock:
            def __init__(self, *a, **k):
                pass
            def settimeout(self, t):
                pass
            def bind(self, addr):
                pass
            def send(self, data):
                outer.sent.append(bytes(data))
                return len(data)
            def recv(self, n):
                if isinstance(outer.reply, Exception):
                    raise outer.reply
                return outer.reply
            def close(self):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *a):
                self.close()

        class R:
            returncode, stdout, stderr = 0, "table inet arx\n", ""

        def run(argv, **kw):
            self.listed.append(list(argv))
            return R()
        for obj, name, value in ((response.socket, "socket", Sock), (response.subprocess, "run", run)):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(sweepcache.end_sweep)

    @staticmethod
    def msg(kind, payload=b""):
        import struct
        return struct.pack("=IHHII", 16 + len(payload), kind, 0, 1, 0) + payload

    def errno(self, e):
        import struct
        return self.msg(self.ERROR, struct.pack("=i", -e) + self.msg(0))

    def test_the_kernel_says_the_table_is_there(self):
        self.reply = self.msg(self.NEWTABLE, b"\x01\x00\x00\x00" + b"\x08\x00\x01\x00arx\x00")
        self.assertIs(self.r._arx_table_present(), True)
        self.assertEqual(self.listed, [])  # sin lanzar nft

    def test_the_kernel_says_there_is_no_such_table(self):
        import errno
        self.reply = self.errno(errno.ENOENT)
        self.assertIs(self.r._arx_table_present(), False)
        self.assertEqual(self.listed, [])

    def test_the_request_asks_for_table_arx_of_the_inet_family(self):
        import struct
        self.reply = self.msg(self.NEWTABLE)
        self.r._arx_table_present()
        (req,) = self.sent
        length, kind, flags, _, _ = struct.unpack("=IHHII", req[:16])
        self.assertEqual((length, kind, flags & 1), (len(req), (10 << 8) | 1, 1))  # NFT_MSG_GETTABLE, NLM_F_REQUEST
        self.assertEqual(req[16], 1)                                              # NFPROTO_INET
        self.assertIn(b"arx\x00", req[20:])
        self.assertNotIn(b"arx\x00x", req)

    def test_an_answer_that_is_not_understood_falls_back_to_nft(self):
        for reply in (b"", b"\x01\x02", self.msg(0x1234), self.errno(1)):  # vacío, corto, otro tipo, EPERM
            self.listed.clear()
            self.sc.end_sweep()
            self.reply = reply
            self.assertIs(self.r._arx_table_present(), True, reply)
            self.assertEqual(len(self.listed), 1, reply)

    def test_a_socket_error_falls_back_to_nft(self):
        self.reply = OSError("sin CAP_NET_ADMIN")
        self.assertIs(self.r._arx_table_present(), True)
        self.assertEqual(len(self.listed), 1)

    def test_a_socket_that_cannot_even_be_made_falls_back_to_nft(self):
        with mock.patch.object(self.r.socket, "socket", side_effect=OSError("sin netlink")):
            self.assertIs(self.r._arx_table_present(), True)
        self.assertEqual(len(self.listed), 1)

    def test_the_fallback_is_still_right_when_the_table_is_gone(self):
        class R:
            returncode, stdout, stderr = 0, "table ip other\n", ""
        self.reply = b""
        with mock.patch.object(self.r.subprocess, "run", lambda *a, **k: R()):
            self.assertIs(self.r._arx_table_present(), False)

    def test_inside_a_sweep_it_is_asked_once(self):
        import errno
        self.reply = self.errno(errno.ENOENT)
        self.sc.begin_sweep()
        self.r._arx_table_present()
        self.r._arx_table_present()
        self.r._arx_table_present()
        self.sc.end_sweep()
        self.assertEqual(len(self.sent), 1)

    def test_nothing_is_kept_between_sweeps(self):
        import errno
        self.reply = self.errno(errno.ENOENT)
        self.r._arx_table_present()
        self.r._arx_table_present()
        self.assertEqual(len(self.sent), 2)  # fuera de un barrido siempre se pregunta de nuevo


class IntactCacheTests(unittest.TestCase):
    """P6 · un hallazgo que se repite barrido tras barrido no repite la prueba de integridad del fichero (el md5 contra el
    `.md5sums` del paquete: 4,4 ms por hallazgo permanente y barrido). El resultado se guarda mientras ni el fichero ni el
    `.md5sums` cambien (inodo, tamaño, mtime y ctime), y 10 min como mucho."""

    def setUp(self):
        _isolate()
        import hashlib
        from arx.modules import provenance
        self.v = provenance
        self.d = tempfile.mkdtemp()
        self.exe = os.path.join(self.d, "usr", "bin", "tool")
        os.makedirs(os.path.dirname(self.exe))
        with open(self.exe, "wb") as f:
            f.write(b"#!/bin/sh\necho hi\n")
        self.md5 = os.path.join(self.d, "tool.md5sums")
        self._sums(hashlib.md5(open(self.exe, "rb").read()).hexdigest())
        self.now = [100.0]
        self.hashed = []
        real_md5 = provenance._md5_file

        def counting(path):
            self.hashed.append(path)
            return real_md5(path)
        for obj, name, value in ((provenance, "_md5sums_files", lambda pkg: [self.md5]),
                                 (provenance, "_variants", lambda path: [path]),
                                 (provenance, "_md5_file", counting),
                                 (provenance.time, "monotonic", lambda: self.now[0])):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        provenance._intact_cache.clear()
        self.addCleanup(provenance._intact_cache.clear)

    def _sums(self, digest):
        with open(self.md5, "w") as f:
            f.write(f"{digest}  {self.exe.lstrip('/')}\n")

    def test_the_same_unchanged_file_is_hashed_once(self):
        for _ in range(5):
            self.assertIs(self.v.intact(self.exe, "tool"), True)
        self.assertEqual(len(self.hashed), 1)

    def test_a_file_that_changes_is_checked_again_at_once(self):
        self.assertIs(self.v.intact(self.exe, "tool"), True)
        with open(self.exe, "ab") as f:
            f.write(b"# implante\n")
        self.assertIs(self.v.intact(self.exe, "tool"), False)
        self.assertEqual(len(self.hashed), 2)

    def test_a_change_that_keeps_size_and_mtime_is_still_noticed(self):
        """`touch -r` devuelve la fecha de modificación, no la de cambio de inodo (ctime)."""
        self.assertIs(self.v.intact(self.exe, "tool"), True)
        before = os.stat(self.exe)
        with open(self.exe, "r+b") as f:
            f.write(b"#!/bin/bash")
        os.utime(self.exe, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertIs(self.v.intact(self.exe, "tool"), False)

    def test_a_file_replaced_by_another_one_is_checked_again(self):
        self.assertIs(self.v.intact(self.exe, "tool"), True)
        data = open(self.exe, "rb").read()
        os.unlink(self.exe)
        with open(self.exe, "wb") as f:
            f.write(data)  # mismo contenido, otro inodo
        self.assertIs(self.v.intact(self.exe, "tool"), True)
        self.assertEqual(len(self.hashed), 2)

    def test_a_symlink_pointed_elsewhere_is_checked_again(self):
        link = os.path.join(self.d, "usr", "bin", "link")
        os.symlink(self.exe, link)
        with open(self.md5, "a") as f:
            f.write(f"{'0' * 32}  {link.lstrip('/')}\n")
        self.v.intact(link, "tool")
        os.unlink(link)
        os.symlink("/bin/sh", link)
        self.v.intact(link, "tool")
        self.assertEqual(len(self.hashed), 2)

    def test_two_links_to_one_file_are_two_different_files_to_check(self):
        """Dos rutas al mismo inodo tienen la misma firma de fichero: el destino del enlace las distingue."""
        a, b = os.path.join(self.d, "usr", "bin", "a"), os.path.join(self.d, "usr", "bin", "b")
        os.link(self.exe, a)
        os.link(self.exe, b)
        link = os.path.join(self.d, "usr", "bin", "link")
        with open(self.md5, "a") as f:
            f.write(f"{'0' * 32}  {link.lstrip('/')}\n")
        os.symlink(a, link)
        self.v.intact(link, "tool")
        os.unlink(link)
        os.symlink(b, link)  # mismo inodo, otra ruta
        self.v.intact(link, "tool")
        self.assertEqual(len(self.hashed), 2)

    def test_the_package_checksum_file_changing_makes_it_checked_again(self):
        self.assertIs(self.v.intact(self.exe, "tool"), True)
        self._sums("0" * 32)  # el paquete se actualizó: otro resumen
        self.assertIs(self.v.intact(self.exe, "tool"), False)

    def test_after_ten_minutes_it_is_checked_again(self):
        self.v.intact(self.exe, "tool")
        self.now[0] += self.v.INTACT_TTL_S + 1
        self.v.intact(self.exe, "tool")
        self.assertEqual(len(self.hashed), 2)

    def test_what_could_not_be_proved_is_never_kept(self):
        with open(self.md5, "w") as f:
            f.write("")  # dpkg no guardó el resumen de este fichero
        for _ in range(3):
            self.assertIsNone(self.v.intact(self.exe, "tool"))
        self.assertEqual(self.v._intact_cache, {})

    def test_a_file_that_vanished_is_not_kept(self):
        os.unlink(self.exe)
        self.assertIsNone(self.v.intact(self.exe, "tool"))
        self.assertEqual(self.v._intact_cache, {})

    def test_the_memory_is_bounded(self):
        for i in range(self.v.INTACT_MAX + 30):
            self.v._intact_remember((f"/x/{i}", "tool"), (i,), True)
        self.assertLessEqual(len(self.v._intact_cache), self.v.INTACT_MAX)


class SystemdPathsCacheTests(unittest.TestCase):
    """P5a · la lista de unidades de systemd (4 mil listados de directorio por barrido) se guarda mientras ningún directorio
    cambie: la firma son sus inodos y fechas (mtime y ctime). Una unidad, un drop-in o un enlace nuevos se ven en la
    llamada siguiente, no a los 5 min."""

    def setUp(self):
        _isolate()
        from arx.modules import integrity
        self.i = integrity
        self.d = tempfile.mkdtemp()
        self.sys = os.path.join(self.d, "system")
        self.gen = os.path.join(self.d, "generators")
        os.makedirs(self.sys)
        os.makedirs(self.gen)
        self.now = [100.0]
        for obj, name, value in ((integrity, "_SYSTEMD_DIRS", (self.sys,)), (integrity, "_GENERATOR_DIRS", (self.gen,)),
                                 (integrity.time, "monotonic", lambda: self.now[0])):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        integrity.clear_cache()
        self.addCleanup(integrity.clear_cache)
        self.globs = []
        real = integrity.glob.glob

        def counting(pattern, **kw):
            self.globs.append(pattern)
            return real(pattern, **kw)
        patch = mock.patch.object(integrity.glob, "glob", counting)
        patch.start()
        self.addCleanup(patch.stop)

    def touch(self, *parts):
        path = os.path.join(self.sys, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write("[Service]\n")
        return path

    def test_the_same_tree_is_listed_once(self):
        self.touch("a.service")
        first = self.i._systemd_paths()
        listed = len(self.globs)
        for _ in range(5):
            self.assertEqual(self.i._systemd_paths(), first)
        self.assertEqual(len(self.globs), listed)

    def test_a_new_unit_is_seen_at_once(self):
        self.touch("a.service")
        self.i._systemd_paths()
        new = self.touch("evil.service")
        self.assertIn(new, self.i._systemd_paths())

    def test_a_new_drop_in_in_an_existing_directory_is_seen_at_once(self):
        self.touch("a.service")
        self.touch("a.service.d", "10-x.conf")
        self.i._systemd_paths()
        new = self.touch("a.service.d", "99-evil.conf")
        self.assertIn(new, self.i._systemd_paths())

    def test_a_new_drop_in_directory_is_seen_at_once(self):
        self.touch("a.service")
        self.i._systemd_paths()
        new = self.touch("b.service.d", "99-evil.conf")
        self.assertIn(new, self.i._systemd_paths())

    def test_a_new_wants_link_is_seen_at_once(self):
        self.touch("a.service")
        os.makedirs(os.path.join(self.sys, "multi-user.target.wants"))
        self.i._systemd_paths()
        link = os.path.join(self.sys, "multi-user.target.wants", "a.service")
        os.symlink(os.path.join(self.sys, "a.service"), link)
        self.assertIn(link, self.i._systemd_paths())

    def test_a_new_generator_is_seen_at_once(self):
        self.i._systemd_paths()
        gen = os.path.join(self.gen, "evil-generator")
        open(gen, "w").write("#!/bin/sh\n")
        self.assertIn(gen, self.i._systemd_paths())

    def test_a_removed_unit_is_gone_at_once(self):
        gone = self.touch("a.service")
        self.i._systemd_paths()
        os.unlink(gone)
        self.assertNotIn(gone, self.i._systemd_paths())

    def test_a_directory_whose_mtime_was_put_back_is_still_noticed_by_its_ctime(self):
        self.touch("a.service")
        self.i._systemd_paths()
        before = os.stat(self.sys)
        new = self.touch("evil.service")
        os.utime(self.sys, ns=(before.st_atime_ns, before.st_mtime_ns))  # `touch -r`
        self.assertIn(new, self.i._systemd_paths())

    def test_it_is_listed_again_after_five_minutes_anyway(self):
        self.touch("a.service")
        self.i._systemd_paths()
        listed = len(self.globs)
        self.now[0] += self.i.SYSTEMD_LIST_TTL_S + 1
        self.i._systemd_paths()
        self.assertGreater(len(self.globs), listed)

    def test_another_set_of_directories_is_never_served_from_the_cache(self):
        self.touch("a.service")
        self.i._systemd_paths()
        other = tempfile.mkdtemp()
        with mock.patch.object(self.i, "_SYSTEMD_DIRS", (other,)):
            self.assertEqual(self.i._systemd_paths(), [])

    def test_the_caller_cannot_poison_the_cache(self):
        self.touch("a.service")
        self.i._systemd_paths().append("/etc/evil")       # lo que devuelve al reconstruir
        self.i._systemd_paths().append("/etc/evil2")      # lo que devuelve desde la caché
        paths = self.i._systemd_paths()
        self.assertNotIn("/etc/evil", paths)
        self.assertNotIn("/etc/evil2", paths)


class ServicesCacheTests(unittest.TestCase):
    """P5a · `systemctl list-units --state=running` (un proceso, y trabajo para PID 1) solo cuando cambia el conjunto de cgroups de
    servicios: la firma es cada `*.service` de la jerarquía con su `populated`. Mientras sea la misma, la salida de systemd de
    antes sigue valiendo (5 min como mucho), así que la paridad es la de systemd mismo: visto en un host real, los
    `sshd@<conexión>.service` de Debian 13 están en marcha para systemd con el cgroup vacío (el proceso pasó a la sesión)."""

    LIST = ("  ssh.service      loaded active running OpenBSD Secure Shell server\n"
            "  cron.service     loaded active running Regular background program processing daemon\n")

    def setUp(self):
        _isolate()
        from arx.modules import recon
        self.r = recon
        self.root = tempfile.mkdtemp()
        open(os.path.join(self.root, "cgroup.controllers"), "w").write("cpu memory\n")
        self.now = [1000.0]
        self.ran = []
        self.out = self.LIST

        def run(args, **k):
            self.ran.append(list(args))
            return self.out
        for obj, name, value in ((recon, "CGROUP_ROOT", self.root), (recon, "_run", run),
                                 (recon.time, "monotonic", lambda: self.now[0])):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        recon._services_cache.clear()
        self.addCleanup(recon._services_cache.clear)
        self.service("system.slice", "ssh.service")
        self.service("system.slice", "cron.service")

    def service(self, *parts, populated=True):
        path = os.path.join(self.root, *parts)
        os.makedirs(path, exist_ok=True)
        open(os.path.join(path, "cgroup.events"), "w").write(f"populated {int(populated)}\nfrozen 0\n")
        return path

    def test_the_answer_is_what_systemd_says(self):
        self.assertEqual(self.r.collect_services(), ["ssh.service", "cron.service"])
        self.assertEqual(self.ran[0][:2], ["systemctl", "list-units"])

    def test_nothing_changed_systemd_is_asked_once(self):
        for _ in range(10):
            self.r.collect_services()
        self.assertEqual(len(self.ran), 1)

    def test_a_new_service_cgroup_asks_again_at_once(self):
        self.r.collect_services()
        self.service("system.slice", "evil.service")
        self.out = self.LIST + "  evil.service loaded active running x\n"
        self.assertIn("evil.service", self.r.collect_services())
        self.assertEqual(len(self.ran), 2)

    def test_a_service_that_goes_away_asks_again_at_once(self):
        self.r.collect_services()
        os.unlink(os.path.join(self.root, "system.slice", "cron.service", "cgroup.events"))
        os.rmdir(os.path.join(self.root, "system.slice", "cron.service"))
        self.out = self.LIST.splitlines(True)[0]
        self.assertEqual(self.r.collect_services(), ["ssh.service"])

    def test_a_service_that_starts_or_stops_running_its_processes_asks_again(self):
        self.r.collect_services()
        self.service("system.slice", "cron.service", populated=False)
        self.r.collect_services()
        self.assertEqual(len(self.ran), 2)

    def test_services_in_their_own_slices_and_user_managers_are_part_of_the_signature(self):
        self.r.collect_services()
        self.service("system.slice", "system-sshd.slice", "sshd@1-a.service")
        self.r.collect_services()
        self.service("user.slice", "user-1000.slice", "user@1000.service")
        self.r.collect_services()
        self.assertEqual(len(self.ran), 3)

    def test_what_a_service_runs_inside_and_scopes_are_not_part_of_it(self):
        self.r.collect_services()
        self.service("system.slice", "ssh.service", "sub", "inner.service")
        self.service("system.slice", "docker-abc.scope")
        self.service("system.slice", "docker-abc.scope", "x.service")
        self.service("user.slice", "user-1000.slice", "session-3.scope")
        self.r.collect_services()
        self.assertEqual(len(self.ran), 1)

    def test_after_five_minutes_it_asks_again_anyway(self):
        self.r.collect_services()
        self.now[0] += self.r.SERVICES_REFRESH_S + 1
        self.r.collect_services()
        self.assertEqual(len(self.ran), 2)

    def test_without_cgroup_v2_it_always_asks_systemd(self):
        os.unlink(os.path.join(self.root, "cgroup.controllers"))
        for _ in range(3):
            self.r.collect_services()
        self.assertEqual(len(self.ran), 3)

    def test_an_unreadable_hierarchy_always_asks_systemd(self):
        with mock.patch.object(self.r, "CGROUP_ROOT", os.path.join(self.root, "nope")):
            self.r.collect_services()
            self.r.collect_services()
        self.assertEqual(len(self.ran), 2)

    def test_a_failure_of_systemd_is_never_kept(self):
        self.out = None
        self.assertIsNone(self.r.collect_services())
        self.out = self.LIST
        self.assertEqual(self.r.collect_services(), ["ssh.service", "cron.service"])

    def test_the_caller_cannot_poison_the_cache(self):
        self.r.collect_services().append("evil.service")
        self.r.collect_services().append("evil2.service")
        self.assertEqual(self.r.collect_services(), ["ssh.service", "cron.service"])


def _net_line(i, local, state, inode):
    return f"{i:4d}: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0 100 0 0 10 0"


class ListeningPortsCacheTests(unittest.TestCase):
    """P2 · `ss -tulpnH` solo cuando cambia lo que escucha: la firma sale de /proc/net/{tcp,tcp6,udp,udp6} (sockets en escucha
    con su inodo) y la salida de `ss` se guarda mientras no cambie, hasta 5 min y mientras sigan vivos los procesos que
    nombra. Así la paridad con `ss -p` es la de `ss` mismo."""

    HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    SS = ('tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n'
          'udp   UNCONN 0 0   127.0.0.54:53 0.0.0.0:* users:(("systemd-resolve",pid=901,fd=12))\n')

    def setUp(self):
        _isolate()
        from arx.modules import recon
        self.r = recon
        self.net = tempfile.mkdtemp()
        self.files = {k: os.path.join(self.net, k) for k in ("tcp", "tcp6", "udp", "udp6")}
        self.rows = {k: [] for k in self.files}
        self.now = [1000.0]
        self.ss_runs = []
        self.ss_out = self.SS
        self.alive = {900, 901}
        self.write()

        def run(args, **k):
            self.ss_runs.append(list(args))
            return self.ss_out
        for obj, name, value in ((recon, "_NET_FILES", dict(self.files)),
                                 (recon, "_run", run), (recon.time, "monotonic", lambda: self.now[0]),
                                 (recon, "_pid_alive", lambda pid: pid in self.alive)):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        recon._ports_cache.clear()
        self.addCleanup(recon._ports_cache.clear)

    def write(self):
        for k, path in self.files.items():
            with open(path, "w") as f:
                f.write(self.HEADER + "\n".join(self.rows[k]) + ("\n" if self.rows[k] else ""))

    def listen(self, kind, port, inode, state=None):
        state = state or ("0A" if kind.startswith("tcp") else "07")
        addr = "00000000" if not kind.endswith("6") else "0" * 32
        self.rows[kind].append(_net_line(len(self.rows[kind]), f"{addr}:{port:04X}", state, inode))
        self.write()

    def test_nothing_changed_ss_is_asked_once(self):
        self.listen("tcp", 22, 1111)
        self.listen("udp", 53, 2222)
        for _ in range(10):
            ports = self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 1)
        self.assertEqual([p["proto"] for p in ports], ["tcp", "udp"])
        self.assertIn("sshd", ports[0]["process"])

    def test_a_new_listening_socket_asks_again_at_once(self):
        self.listen("tcp", 22, 1111)
        self.r._collect_ports()
        self.listen("tcp", 4444, 3333)
        self.ss_out = self.SS + 'tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=902,fd=3))\n'
        self.alive.add(902)
        ports = self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 2)
        self.assertIn("nc", " ".join(p["process"] for p in ports))

    def test_a_new_udp_socket_asks_again_at_once(self):
        self.listen("udp", 53, 2222)
        self.r._collect_ports()
        self.listen("udp", 31337, 4444)
        self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 2)

    def test_a_new_ipv6_socket_asks_again_at_once(self):
        self.listen("tcp6", 22, 1111)
        self.r._collect_ports()
        self.listen("tcp6", 4444, 3333)
        self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 2)

    def test_a_socket_that_stops_listening_asks_again(self):
        self.listen("tcp", 22, 1111)
        self.listen("tcp", 8080, 1112)
        self.r._collect_ports()
        self.rows["tcp"].pop()
        self.write()
        self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 2)

    def test_the_same_port_taken_by_another_process_is_another_socket(self):
        self.listen("tcp", 22, 1111)
        self.r._collect_ports()
        self.rows["tcp"] = []
        self.listen("tcp", 22, 5555)  # otro proceso, otro inodo
        self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 2)

    def test_connections_and_other_states_do_not_count(self):
        self.listen("tcp", 22, 1111)
        self.r._collect_ports()
        self.listen("tcp", 40000, 7777, state="01")  # una conexión establecida
        self.listen("udp", 40001, 7778, state="01")  # un UDP conectado
        self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 1)

    def test_a_process_that_died_asks_again_even_if_the_socket_is_the_same(self):
        self.listen("tcp", 22, 1111)
        self.r._collect_ports()
        self.alive.discard(900)  # un worker que se reinicia
        self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 2)

    def test_after_five_minutes_it_asks_again_anyway(self):
        self.listen("tcp", 22, 1111)
        self.r._collect_ports()
        self.now[0] += self.r.PORTS_REFRESH_S + 1
        self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 2)

    def test_an_unreadable_procfs_never_uses_the_cache(self):
        self.listen("tcp", 22, 1111)
        self.r._collect_ports()
        os.unlink(self.files["tcp"])
        self.r._collect_ports()
        self.r._collect_ports()
        self.assertEqual(len(self.ss_runs), 3)

    def test_the_fallback_without_ss_is_not_kept(self):
        self.listen("tcp", 22, 1111)
        self.ss_out = None  # sin ss
        self.r._collect_ports()
        self.ss_out = self.SS
        ports = self.r._collect_ports()
        self.assertIn("sshd", ports[0]["process"])  # el respaldo (sin procesos) no se quedó guardado

    def test_the_caller_cannot_poison_the_cache(self):
        self.listen("tcp", 22, 1111)
        self.r._collect_ports()[0]["process"] = "evil"
        self.assertIn("sshd", self.r._collect_ports()[0]["process"])


class EstablishedCountTests(unittest.TestCase):
    """P2 · el número de conexiones establecidas (el indicador de la base) sale de /proc/net/tcp y tcp6, como `ss -tan state
    established`, sin lanzar `ss`."""

    def setUp(self):
        _isolate()
        from arx.modules import baseline, recon
        self.b, self.r = baseline, recon
        self.d = tempfile.mkdtemp()
        self.tcp, self.tcp6 = os.path.join(self.d, "tcp"), os.path.join(self.d, "tcp6")
        self.ran = []
        for obj, name, value in ((recon, "_NET_FILES", {"tcp": self.tcp, "tcp6": self.tcp6, "udp": "/nope", "udp6": "/nope"}),
                                 (recon, "_run", lambda args, **k: self.ran.append(list(args)) or "a\nb\nc\n")):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def put(self, path, states):
        header = "  sl  local_address rem_address   st\n"
        with open(path, "w") as f:
            f.write(header + "".join(_net_line(i, "0100007F:0016", st, 100 + i) + "\n" for i, st in enumerate(states)))

    def test_only_established_tcp_of_both_families_count(self):
        self.put(self.tcp, ["01", "0A", "01", "06", "01"])
        self.put(self.tcp6, ["01", "0A", "08"])
        self.assertEqual(self.r.count_established(), 4)
        self.assertEqual(self.ran, [])

    def test_the_gauge_uses_it_and_does_not_run_ss(self):
        self.put(self.tcp, ["01", "01"])
        self.put(self.tcp6, [])
        self.assertEqual(self.b._gauges()["conn_count"], 2.0)
        self.assertNotIn(["ss", "-tanH", "state", "established"], self.ran)

    def test_with_no_connections_it_is_zero_not_missing(self):
        self.put(self.tcp, ["0A"])
        self.put(self.tcp6, [])
        self.assertEqual(self.r.count_established(), 0)

    def test_without_procfs_it_asks_ss_as_before(self):
        self.assertIsNone(self.r.count_established())
        self.assertEqual(self.b._gauges()["conn_count"], 3.0)  # lo que dijo el `ss` de la prueba
        self.assertIn(["ss", "-tanH", "state", "established"], self.ran)


if __name__ == "__main__":
    unittest.main()
