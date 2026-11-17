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


if __name__ == "__main__":
    unittest.main()
