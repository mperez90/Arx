"""B78 · `pkgdb`: la identidad de la base de dpkg, el inventario por generación y los dueños por lotes.

Equivalencia con lo anterior (mismo inventario de versiones, mismos dueños, mismos hechos para `trust`) y las
reglas duras: una falta de respuesta nunca se lee como «nada cambió» ni se guarda; un dato viejo no se guarda
bajo una generación nueva. Corre con:  python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from arx.modules import maintenance  # noqa: E402
from dpkgfake import fake_world  # noqa: E402


class _PkgdbCase(unittest.TestCase):
    def setUp(self):
        from arx.modules import pkgdb
        self.db = pkgdb
        self.fake = fake_world(self)
        self.fake.install("coreutils", "9.4-3", owns=["/usr/bin/ls", "/bin/cat"])
        self.fake.install("nginx", "1.24.0-1", source="nginx", owns=["/usr/sbin/nginx"])
        self.fake.install("libc6", "2.39-0ubuntu8", arch="amd64", source="glibc", source_version="2.39-0ubuntu8",
                          owns=["/usr/lib/x86_64-linux-gnu/libc.so.6"])
        self.fake.install("libc6", "2.39-0ubuntu8", arch="i386", source="glibc", source_version="2.39-0ubuntu8")


class GenerationTests(_PkgdbCase):
    def test_it_is_stable_until_dpkg_changes(self):
        a = self.db.generation()
        self.assertIsNotNone(a)
        self.assertEqual(self.db.generation(), a)
        self.fake.touch()  # status nuevo (otro inodo)
        self.assertNotEqual(self.db.generation(), a)

    def test_a_status_rewritten_in_place_with_the_same_size_is_noticed(self):
        a = self.db.generation()
        st = os.stat(self.fake.status)
        os.utime(self.fake.status, ns=(st.st_atime_ns, st.st_mtime_ns + 1))  # solo mtime_ns
        self.assertNotEqual(self.db.generation(), a)

    def test_a_running_transaction_changes_it_and_its_end_changes_it_again(self):
        idle = self.db.generation()
        journal = os.path.join(self.fake.updates, "0000")
        with open(journal, "w") as f:
            f.write("unpack")
        running = self.db.generation()
        self.assertNotEqual(running, idle)
        with open(journal, "a") as f:
            f.write(" more")  # el diario crece sin cambiar de nombre
        self.assertNotEqual(self.db.generation(), running)
        os.unlink(journal)
        self.assertEqual(self.db.generation(), idle)  # sin diario, la misma base de antes

    def test_a_journal_entry_that_vanishes_while_listing_is_not_an_error(self):
        with mock.patch.object(self.db.os, "scandir") as scandir:
            entry = mock.Mock()
            entry.name = "0001"
            entry.stat.side_effect = FileNotFoundError()
            scandir.return_value.__enter__.return_value = [entry]
            self.assertIn("0001", self.db.generation())

    def test_diversions_change_it_without_touching_status(self):
        a = self.db.generation()
        with open(self.fake.diversions, "w") as f:
            f.write("/usr/bin/x\n/usr/bin/x.distrib\ndash\n")
        self.assertNotEqual(self.db.generation(), a)

    def test_without_status_or_with_an_unreadable_journal_there_is_no_generation(self):
        with mock.patch.object(self.db, "STATUS", os.path.join(self.fake.dir, "missing")):
            self.assertIsNone(self.db.generation())
        with mock.patch.object(self.db.os, "scandir", side_effect=PermissionError("no")):
            self.assertIsNone(self.db.generation())

    def test_a_missing_journal_directory_is_an_empty_journal(self):
        with mock.patch.object(self.db, "UPDATES", os.path.join(self.fake.dir, "no-such-dir")):
            self.assertIsNotNone(self.db.generation())


class InventoryTests(_PkgdbCase):
    def test_one_inventory_per_generation_shared_by_every_reader(self):
        for _ in range(20):
            self.db.versions()
            self.db.installed_versions()
            self.db.lookup("nginx")
            self.db.version_of("coreutils")
        self.assertEqual(self.fake.count("inventory"), 1)
        self.assertEqual(self.fake.count("single"), 0)
        self.fake.touch()
        self.db.versions()
        self.assertEqual(self.fake.count("inventory"), 2)

    def test_it_matches_the_old_inventory_of_versions(self):
        """Equivalencia: lo mismo que devolvía `dpkg-query -W` con «paquete:arq» y «paquete» de la versión."""
        legacy = {}
        out = self.fake.run(["dpkg-query", "-W", "-f=${Package}:${Architecture}\t${Version}\n"]).stdout
        for line in out.splitlines():
            name, _, version = line.partition("\t")
            if version:
                legacy[name] = version
                legacy.setdefault(name.partition(":")[0], version)
        self.assertEqual(dict(self.db.installed_versions()), legacy)
        self.assertIn("libc6:i386", legacy)
        self.assertEqual(len(self.db.versions()), 4)  # los cuatro paquetes instalados, ambas arquitecturas

    def test_packages_carry_architecture_and_source(self):
        libc = self.db.lookup("libc6:i386")
        self.assertEqual((libc.name, libc.arch, libc.version, libc.source, libc.source_version),
                         ("libc6", "i386", "2.39-0ubuntu8", "glibc", "2.39-0ubuntu8"))
        self.assertEqual(self.db.lookup("libc6").arch, "amd64")  # sin arquitectura: el primero que lista dpkg
        self.assertEqual(self.db.lookup("libc6:any").arch, "amd64")
        self.assertIsNone(self.db.lookup("nope"))
        self.assertIsNone(self.db.version_of("nope"))

    def test_the_inventory_cannot_be_changed_by_a_reader(self):
        inv = self.db.installed_versions()
        with self.assertRaises(TypeError):
            inv["nginx"] = "0"  # type: ignore[index]
        self.assertEqual(self.db.installed_versions()["nginx"], "1.24.0-1")

    def test_no_answer_is_an_error_and_is_never_kept(self):
        for failure in ("busy", "timeout", "exit2", "oserror"):
            self.fake.fail = failure
            with self.assertRaises(self.db.NoAnswer, msg=failure):
                self.db.versions()
        self.assertIsNone(self.db._inventory)
        self.fake.fail = None
        self.assertEqual(self.db.version_of("nginx"), "1.24.0-1")  # la siguiente pregunta sí llega a dpkg

    def test_a_host_without_dpkg_gets_an_empty_inventory_and_nothing_is_kept(self):
        with mock.patch.object(self.db, "STATUS", os.path.join(self.fake.dir, "missing")), \
                mock.patch.object(maintenance, "run", side_effect=FileNotFoundError("dpkg-query")):
            self.assertEqual(len(self.db.versions()), 0)
            self.assertEqual(dict(self.db.installed_versions()), {})
        self.assertIsNone(self.db._inventory)

    def test_without_a_generation_every_call_asks_again(self):
        with mock.patch.object(self.db, "STATUS", os.path.join(self.fake.dir, "missing")):
            self.db.versions()
            self.db.versions()
        self.assertEqual(self.fake.count("inventory"), 2)

    def test_concurrent_readers_share_one_query(self):
        gate = threading.Event()
        self.fake.hook = lambda argv: gate.wait(2)  # la consulta tarda: los demás esperan su resultado
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.db.version_of("nginx"))) for _ in range(8)]
        for t in threads:
            t.start()
        gate.set()
        for t in threads:
            t.join(5)
        self.assertEqual(results, ["1.24.0-1"] * 8)
        self.assertEqual(self.fake.count("inventory"), 1)

    def test_a_change_during_the_query_never_leaves_old_data_under_the_new_generation(self):
        self.fake.after = lambda argv: (setattr(self.fake, "after", None), self.fake.install("nginx", "1.24.0-2"))
        first = self.db.version_of("nginx")  # dpkg cambió justo después de leerlo: este dato nace viejo
        self.assertEqual(first, "1.24.0-1")
        self.assertEqual(self.db.version_of("nginx"), "1.24.0-2")  # la generación ya no coincide: se renueva
        self.assertEqual(self.fake.count("inventory"), 2)



class OwnersTests(_PkgdbCase):
    def test_every_path_is_resolved_in_one_call_and_then_kept(self):
        paths = ["/usr/bin/ls", "/usr/sbin/nginx", "/opt/loose/server"]
        got = self.db.owners(paths)
        self.assertEqual(got, {"/usr/bin/ls": "coreutils", "/usr/sbin/nginx": "nginx", "/opt/loose/server": None})
        self.assertEqual(self.fake.count("search"), 1)
        self.assertEqual(self.db.owners(paths), got)  # también lo negativo: dpkg contestó que no es de nadie
        self.assertEqual(self.db.owner("/usr/bin/ls"), "coreutils")
        self.assertEqual(self.fake.count("search"), 1)

    def test_a_dpkg_change_renews_what_was_asked_before_in_the_same_call(self):
        paths = [f"/usr/bin/tool{i}" for i in range(30)]
        for i, path in enumerate(paths):
            self.fake.files[path] = f"tool{i}"
        self.db.owners(paths)
        self.assertEqual(self.fake.count("search"), 1)
        self.fake.touch()
        self.assertEqual(self.db.owner("/usr/bin/tool0"), "tool0")  # una pregunta renueva las 30 en una sola llamada
        self.assertEqual(self.fake.count("search"), 2)
        self.assertEqual(self.db.owners(paths), {p: f"tool{i}" for i, p in enumerate(paths)})
        self.assertEqual(self.fake.count("search"), 2)

    def test_a_renewed_answer_reflects_what_dpkg_now_says(self):
        self.assertEqual(self.db.owner("/usr/sbin/nginx"), "nginx")
        del self.fake.files["/usr/sbin/nginx"]  # se desinstaló
        self.assertEqual(self.db.owner("/usr/sbin/nginx"), "nginx")  # la generación no cambió: sigue valiendo
        self.fake.touch()
        self.assertIsNone(self.db.owner("/usr/sbin/nginx"))

    def test_a_diversion_change_renews_the_owners_too(self):
        self.assertEqual(self.db.owner("/bin/cat"), "coreutils")
        self.fake.files["/bin/cat"] = "busybox"
        with open(self.fake.diversions, "w") as f:
            f.write("/bin/cat\n")
        self.assertEqual(self.db.owner("/bin/cat"), "busybox")

    def test_diversion_lines_name_no_owner_and_the_exact_path_is_required(self):
        self.fake.diverted.add("/usr/sbin/nginx")
        self.assertEqual(self.db.owner("/usr/sbin/nginx"), "nginx")
        self.fake.files["/usr/bin/socat1"] = "socat"
        self.assertIsNone(self.db.owner("/usr/bin/socat"))  # otro fichero que empieza igual

    def test_the_usr_merge_aliases_are_the_same_file(self):
        self.assertEqual(self.db.owner("/usr/bin/cat"), "coreutils")  # dpkg lo conoce como /bin/cat
        self.assertEqual(self.db.owner("/bin/ls"), "coreutils")      # y este como /usr/bin/ls
        self.assertEqual(self.fake.count("search"), 2)

    def test_a_path_with_wildcards_cannot_borrow_the_owner_of_another_file(self):
        # dpkg-query -S toma patrones: «/usr/bin/*» devuelve los ficheros de coreutils, y ninguno es esa ruta
        got = self.db.owners(["/usr/bin/*", "/usr/sbin/ngin[x]"])
        self.assertEqual(got, {"/usr/bin/*": None, "/usr/sbin/ngin[x]": None})
        self.assertEqual(self.db.owners(["/usr/bin/*", "/usr/bin/ls"]), {"/usr/bin/*": None, "/usr/bin/ls": "coreutils"})

    def test_paths_dpkg_would_read_as_options_or_patterns_are_never_asked(self):
        got = self.db.owners(["relative/ls", "-W", "/usr/bin/ls\n/etc/passwd", "/a\0b", "/" + "x" * 5000, 7])
        self.assertTrue(all(v is None for v in got.values()))
        self.assertEqual(self.fake.queries(), 0)

    def test_many_paths_go_in_a_few_bounded_calls(self):
        paths = [f"/usr/lib/lib{i}.so" for i in range(450)]
        with mock.patch.object(self.db, "BATCH_PATHS", 200):
            self.db.owners(paths)
        searches = [a for a in self.fake.calls if "-S" in a]
        # 450 rutas y sus variantes de la fusión de /usr (900 argumentos), no 450 consultas
        self.assertEqual(len(searches), 5)
        self.assertTrue(all(len(a) - 2 <= 200 for a in searches))

    def test_the_batch_is_also_bounded_by_the_size_of_its_arguments(self):
        paths = [f"/usr/lib/{'x' * 3000}{i}.so" for i in range(100)]
        self.db.owners(paths)
        for a in self.fake.calls:
            if "-S" in a:
                self.assertLessEqual(sum(len(x) + 1 for x in a[2:]), self.db.BATCH_BYTES + 3100)

    def test_no_answer_is_never_taken_for_no_package_and_is_never_kept(self):
        for failure in ("busy", "timeout", "exit2", "oserror"):
            self.fake.fail = failure
            with self.assertRaises(self.db.NoAnswer, msg=failure):
                self.db.owners(["/usr/bin/ls"])
            with self.assertRaises(self.db.NoAnswer, msg=failure):
                self.db.owner("/usr/sbin/nginx")
        self.assertEqual(dict(self.db._owner_cache), {})
        self.fake.fail = None
        self.assertEqual(self.db.owner("/usr/bin/ls"), "coreutils")

    def test_nothing_is_kept_when_one_of_the_batches_gets_no_answer(self):
        paths = [f"/usr/lib/lib{i}.so" for i in range(250)]
        for path in paths:
            self.fake.files[path] = "libs"
        calls = []

        def second_fails(argv):
            calls.append(argv)
            if len(calls) == 2:
                self.fake.fail = "busy"
        self.fake.hook = second_fails
        with mock.patch.object(self.db, "BATCH_PATHS", 100):
            with self.assertRaises(self.db.NoAnswer):
                self.db.owners(paths)
        self.assertEqual(dict(self.db._owner_cache), {})  # nada se guarda sin la respuesta de todos
        self.fake.fail, self.fake.hook = None, None
        self.assertEqual(set(self.db.owners(paths).values()), {"libs"})

    def test_a_change_during_the_query_leaves_no_old_answer_under_the_new_generation(self):
        self.fake.after = lambda argv: (setattr(self.fake, "after", None), self.fake.touch())
        self.assertEqual(self.db.owner("/usr/sbin/nginx"), "nginx")
        searches = self.fake.count("search")
        self.assertEqual(self.db.owner("/usr/sbin/nginx"), "nginx")
        self.assertEqual(self.fake.count("search"), searches + 1)  # cambió a mitad: se vuelve a preguntar

    def test_a_slow_answer_cannot_overwrite_a_newer_generation_that_another_thread_already_filled(self):
        def dpkg_changes_while_this_call_waits(argv):
            self.fake.after = None
            self.fake.files["/usr/sbin/nginx"] = "nginx-new"  # lo que dirá dpkg desde ahora
            self.fake.touch()
            self.assertEqual(self.db.owner("/usr/sbin/nginx"), "nginx-new")  # otro hilo, ya en la generación nueva
        self.fake.after = dpkg_changes_while_this_call_waits
        self.assertEqual(self.db.owner("/usr/sbin/nginx"), "nginx")  # esta llamada leyó lo de antes
        searches = self.fake.count("search")
        self.assertEqual(self.db.owner("/usr/sbin/nginx"), "nginx-new")  # lo viejo no pisó lo nuevo
        self.assertEqual(self.fake.count("search"), searches)

    def test_the_cache_is_bounded(self):
        with mock.patch.object(self.db, "CACHE_MAX", 10):
            self.db.owners([f"/usr/bin/t{i}" for i in range(25)])
        self.assertEqual(len(self.db._owner_cache), 10)

    def test_without_a_generation_nothing_is_kept(self):
        with mock.patch.object(self.db, "STATUS", os.path.join(self.fake.dir, "missing")):
            self.db.owner("/usr/bin/ls")
            self.db.owner("/usr/bin/ls")
        self.assertEqual(self.fake.count("search"), 2)
        self.assertEqual(dict(self.db._owner_cache), {})



if __name__ == "__main__":
    unittest.main()
