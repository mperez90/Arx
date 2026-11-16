"""B78/A#4 · Presupuesto de procesos de un barrido en reposo (lab de reposo: 17 por barrido, el 2,2 % de un núcleo).

`nft list set` de un set con elementos de cgroup cuesta ~2 ms de CPU por elemento; cada barrido leía 7 sets y 3 veces
la tabla entera, y por cada servicio fijado un `nft get element` más. Ahora: la tabla se comprueba con `nft list
tables`, lo aprendido (`seen`) se lee cada 300 s (o ya si hay un servicio nuevo), los cortes (`denied`) y la pista de
escaneo en cada barrido, y los servicios fijados con UNA lectura de `watched2` cada 300 s. Un `nft` simulado cuenta cada
orden y los barridos corren con reloj simulado. Corre con:  python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)
STEP = 30  # s entre barridos
SVC = ["app", "db", "web"]


def _isolate():
    d = tempfile.mkdtemp()
    os.environ["ARX_CONFIG_DIR"] = os.path.join(d, "cfg")
    os.environ["ARX_STATE_DIR"] = os.path.join(d, "state")
    os.environ["ARX_POLAR_ENV"] = "sandbox"
    return d


class _R:
    def __init__(self, returncode=0, stdout=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


class FakeNft:
    """`nft` y `ss` simulados: cuentan cada orden y guardan el estado que el kernel tendría."""

    def __init__(self):
        self.calls: list = []
        self.table = True
        self.sets = {n: [] for n in ("seen4", "seen6", "denied4", "denied6", "ok4", "ok6", "scan4", "scan6",
                                     "novel4", "novel6")}
        self.watched: set = set()
        self.watched_obs: set = set()      # servicios en vigilancia «observar» (sin corte)
        self.loaded: list = []             # texto de cada `nft -f`
        self.declared_sets: list = []      # lo que Arx ha ido creando: el listado de la tabla lo refleja
        self.chains: dict = {}
        self.fail_lists = False
        self.after_list: dict = {}         # set → elementos que el kernel anota justo después de listarlo
        self.fail_batch_delete = False

    @property
    def structure(self) -> str:
        out = ["table inet arx {"]
        out += [f"\tset {name} {{\n\t}}" for name in self.declared_sets]
        for name, rules in self.chains.items():
            out.append(f"\tchain {name} {{")
            out += [f"\t\t{rule}" for rule in rules]
            out.append("\t}")
        return "\n".join(out) + "\n}\n"

    # ── lo que se contó ───────────────────────────────────────────────────────
    def count(self, *prefix: str) -> int:
        return sum(1 for c in self.calls if tuple(c[:len(prefix)]) == prefix)

    def reads(self, name: str) -> int:
        return self.count("nft", "list", "set", "inet", "arx", name)

    def processes(self) -> int:
        return len(self.calls)

    # ── el nft de mentira ─────────────────────────────────────────────────────
    def run(self, argv, **kw):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        if argv[0] == "ss":
            return _R(0, "")
        if argv[0] != "nft":
            return _R(0, "")
        args = argv[1:]
        if args[:2] == ["list", "tables"]:
            return _R(0, "table inet arx\n" if self.table else "")
        if args[:2] in (["list", "table"], ["-t", "list"]):
            return _R(0, self.structure) if self.table else _R(1, "")
        if args[:2] == ["list", "set"]:
            if self.fail_lists or not self.table:
                return _R(1, "")
            name = args[4]
            def show(p):  # nft imprime el cgroup como ruta si existe y como número si ya no
                return p if p.isdigit() else f'"{p}"'
            elems = ([show(p) for p in sorted(self.watched)] if name == "watched2" else
                     [show(p) for p in sorted(self.watched_obs)] if name == "watched_obs" else self.sets.get(name, []))
            body = f"\t\telements = {{ {', '.join(elems)} }}\n" if elems else ""
            late = self.after_list.pop(name, [])  # la carrera: llega entre la lectura y lo siguiente
            self.sets.setdefault(name, []).extend(late)
            return _R(0, f"table inet arx {{\n\tset {name} {{\n{body}\t}}\n}}\n")
        if args[0] == "get":
            return _R(1, "")
        if args[0] == "add" and args[1] == "table":
            self.table = True
        elif args[0] == "add" and args[1] == "set":
            if args[4] not in self.declared_sets:
                self.declared_sets.append(args[4])
        elif args[0] == "add" and args[1] == "chain":
            self.chains.setdefault(args[4], [])
        elif args[0] == "add" and args[1] == "rule":
            self.chains.setdefault(args[4], []).append(" ".join(args[5:]))
        if args[0] == "-f":  # recarga de un servicio fijado, o la carga de los de «observar»
            try:
                text = open(args[1]).read()
            except OSError:
                text = ""
            self.loaded.append((os.path.basename(args[1]), text))
            if "watched_obs" in text:
                for line in text.splitlines():
                    if "watched_obs" in line:
                        self.watched_obs.add(line.split('"')[1])
            else:
                self.watched.add("system.slice/" + os.path.basename(args[1]).removesuffix(".nft"))
        if args[0] == "flush" and args[1] == "set":
            self.sets[args[4]] = []
        if args[0] == "delete" and args[1] == "element":
            name = args[4]
            targets = [t.strip() for t in " ".join(args[5:]).strip("{} ").split(", ")]
            if len(targets) > 1 and self.fail_batch_delete:
                return _R(1, "")
            for target in targets:
                self.sets[name] = [e for e in self.sets.get(name, [])
                                   if e.split(" timeout")[0] != target.split(" timeout")[0]]
                self.watched_obs.discard(target)
                self.watched.discard(target)
        return _R(0, "")


class _Sweeps(unittest.TestCase):
    """Un host con tres servicios y la clase base de los barridos con reloj simulado."""

    def setUp(self):
        _isolate()
        from arx.modules import profile, provenance, response, sweepcache
        self.p, self.r, self.sc = profile, response, sweepcache
        self.fake = FakeNft()
        self.now = [1000.0]
        self.enforce = False
        self.pinned: list = []
        self.files_dir = os.path.join(tempfile.mkdtemp(), "arx-files")
        self.cgroup_ids: dict = {}
        self.running = [f"system.slice/{n}.service" for n in SVC]
        profile._reset_cadence()
        response._tracking.update(ok_until=0.0, epoch=0)
        sweepcache.end_sweep()
        sweepcache._owner[0] = None
        for obj, name, value in [
                (response, "_is_linux_root", lambda: True), (response, "_nft_available", lambda: True),
                (profile, "_package_version", lambda unit: ("pkg", "1.0")),
                (profile, "running_services", lambda: list(self.running)),
                (profile, "_updates", lambda *a, **k: []), (profile, "_exec_events", lambda *a, **k: []),
                (profile, "_dns_events", lambda *a, **k: []), (profile, "_library_events", lambda *a, **k: []),
                (profile, "_read_events", lambda *a, **k: []), (profile, "_doc_review_later", lambda *a: None),
                (profile, "_cgroup_exists", lambda path: True),
                (profile, "_cgroup_id", lambda path: self.cgroup_ids.get(path)),
                (profile, "_pin", lambda path, s: self.pinned.append(path) or True),
                (profile, "_files_dir", lambda: __import__("pathlib").Path(self.files_dir)),
                (provenance, "system_root", lambda: ""),
                (profile.time, "monotonic", lambda: self.now[0]),
                (profile.subprocess, "run", self.fake.run)]:
            p = mock.patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(sweepcache.end_sweep)

    CFG = {"profile_observe_days": 10, "profile_jitter_days": 0}

    def sweep(self, t: float):
        """Un barrido de guard: empieza la caché, comprueba la tabla, perfil, y cierra la parte de lectura."""
        self.now[0] = 1000.0 + t
        self.sc.begin_sweep()
        self.r.ensure_nft_tracking()
        found = self.p.sweep(enforce=self.enforce, cfg=self.CFG, now=NOW + timedelta(seconds=t))
        self.sc.end_sweep()
        return found

    def subject(self, name="app"):
        return self.p.load()["subjects"][f"system.slice/{name}.service"]

    def elem(self, name, ip="104.20.23.154", port=443):
        return f'"system.slice/{name}.service" . tcp . {ip} . {port} timeout 1d expires 23h'


class IdleBudgetTests(_Sweeps):
    def test_an_idle_host_costs_a_couple_of_processes_per_sweep_not_seventeen(self):
        for i in range(40):  # 20 min
            self.sweep(i * STEP)
        per_sweep = self.fake.processes() / 40
        self.assertLessEqual(per_sweep, 3.0, self.fake.calls[:12])

    def test_the_table_is_checked_with_list_tables_and_listed_whole_only_now_and_then(self):
        for i in range(40):
            self.sweep(i * STEP)
        self.assertEqual(self.fake.count("nft", "list", "tables"), 40)  # una por barrido, compartida
        whole = self.fake.count("nft", "-t", "list", "table", "inet", "arx")
        self.assertLessEqual(whole, 2 * 5, whole)  # al empezar y cada 300 s (la estructura de Arx y la de la pista)

    def test_what_is_learned_is_read_every_five_minutes_and_the_sweep_still_sees_what_it_must_each_time(self):
        """Lo aprendido, cada SEEN_EVERY_S (15 min desde el piloto A); lo que vigila el kernel, cada barrido."""
        sweeps = 4 * self.p.SEEN_EVERY_S // STEP
        for i in range(sweeps):
            self.sweep(i * STEP)
        self.assertLessEqual(self.fake.reads("seen4"), 5)
        self.assertGreaterEqual(self.fake.reads("seen4"), 4)
        self.assertEqual(self.fake.reads("denied4"), 0)  # sin --enforce no hay cortes que leer

    def test_the_structure_is_never_listed_with_its_elements(self):
        """Piloto A: `nft list table` con los elementos costaba 2,3 s de CPU (nft resuelve cada cgroup recorriendo
        /sys/fs/cgroup); la estructura no los necesita: `-t`."""
        for i in range(40):
            self.sweep(i * STEP)
        self.assertEqual(self.fake.count("nft", "list", "table", "inet", "arx"), 0)
        self.assertGreater(self.fake.count("nft", "-t", "list", "table", "inet", "arx"), 0)

    def test_what_is_learned_is_removed_from_the_kernel_once_read(self):
        """Piloto A: `seen` guardaba un día entero (283 elementos, 2,7 s de CPU cada lectura). Lo leído se quita: la
        lectura siguiente solo trae lo de su ventana, y lo que vuelve a abrirse se cuenta otra vez."""
        self.sweep(0)
        self.fake.sets["seen4"].append(self.elem("app", "203.0.113.7", 8443))
        window = self.p.SEEN_EVERY_S // STEP + 2
        for i in range(1, window):
            self.sweep(i * STEP)
        self.assertEqual(self.fake.sets["seen4"], [])
        n1 = self.subject("app")["dest"]["tcp|203.0.113.0/24|8443"]["n"]
        self.assertEqual(n1, 1)  # leído una vez, no una vez por lectura durante un día
        self.fake.sets["seen4"].append(self.elem("app", "203.0.113.7", 8443))  # la vuelve a abrir
        for i in range(window, 2 * window):
            self.sweep(i * STEP)
        self.assertEqual(self.subject("app")["dest"]["tcp|203.0.113.0/24|8443"]["n"], 2)

    def test_what_a_restarted_service_opened_is_still_learned(self):
        """HZ#97c-1 de Q: un servicio reiniciado sale en `seen` como número; se atribuye por su historial de
        cgroups, como en `novel` y `denied`, antes de quitarlo del kernel."""
        self.sweep(0)
        st = self.p.load()
        st["subjects"]["system.slice/app.service"].setdefault("ids", []).append("4242")
        self.p._save(st)
        self.fake.sets["seen4"].append('4242 . tcp . 203.0.113.8 . 8443 timeout 1d expires 23h')
        for i in range(1, self.p.SEEN_EVERY_S // STEP + 2):
            self.sweep(i * STEP)
        self.assertIn("tcp|203.0.113.0/24|8443", self.subject("app")["dest"])
        self.assertEqual(self.fake.sets["seen4"], [])

    def test_a_new_destination_is_learned_within_five_minutes(self):
        self.sweep(0)
        self.fake.sets["seen4"].append(self.elem("app", "203.0.113.7", 8443))  # lo ve el kernel en el segundo 100
        learned_at = None
        for i in range(1, self.p.SEEN_EVERY_S // STEP + 3):
            self.sweep(i * STEP)
            if "tcp|203.0.113.0/24|8443" in self.subject("app")["dest"]:
                learned_at = i * STEP
                break
        self.assertIsNotNone(learned_at)
        self.assertLessEqual(learned_at, self.p.SEEN_EVERY_S + STEP)

    def test_a_new_service_is_read_at_once_not_after_five_minutes(self):
        self.sweep(0)
        self.sweep(STEP)
        before = self.fake.reads("seen4")
        self.running.append("system.slice/fresh.service")
        self.fake.sets["seen4"].append(self.elem("fresh", "198.51.100.5", 443))
        self.sweep(2 * STEP)
        self.assertEqual(self.fake.reads("seen4"), before + 1)
        self.assertIn("tcp|198.51.100.0/24|443", self.subject("fresh")["dest"])

    def test_the_scan_track_is_still_read_every_sweep(self):
        from arx.modules import sensors
        with mock.patch.object(sensors.subprocess, "run", self.fake.run), \
                mock.patch.object(sensors.shutil, "which", lambda c: "/usr/sbin/nft"):
            for i in range(10):
                self.sweep(i * STEP)
                self.sc.begin_sweep()
                sensors._scan_from_nft()
                self.sc.end_sweep()
        self.assertEqual(self.fake.reads("scan4"), 10)

    def test_dead_cgroups_are_cleaned_up_every_five_minutes_not_every_sweep(self):
        self.fake.sets["ok4"].append('12345 . tcp . 10.0.0.0/24 . 443')  # un cgroup que ya no existe
        for i in range(40):
            self.sweep(i * STEP)
        self.assertLessEqual(self.fake.reads("ok4"), 5)
        self.assertEqual(self.fake.sets["ok4"], [])  # y se limpió


class EnforceBudgetTests(_Sweeps):
    def setUp(self):
        super().setUp()
        self.enforce = True
        self.sweep(0)
        st = self.p.load()
        for name in SVC:  # tres servicios vigilados y fijados
            s = st["subjects"][f"system.slice/{name}.service"]
            s.update(status="watching", enforced=True, mode="fixed", dest={}, watching_since="2026-11-01T00:00:00+00:00")
        self.p._save(st)
        self.fake.watched = {f"system.slice/{n}.service" for n in SVC}
        self.fake.calls.clear()
        self.pinned.clear()

    def test_pinned_services_are_not_asked_about_one_by_one(self):
        for i in range(1, 41):
            self.sweep(i * STEP)
        self.assertEqual(self.fake.count("nft", "get"), 0)  # antes: un `get element` por servicio y barrido
        self.assertLessEqual(self.fake.reads("watched2"), 5)
        self.assertLessEqual(self.fake.processes() / 40, 4.0, self.fake.calls[:10])

    def test_a_cut_is_reported_in_the_very_sweep_where_the_kernel_has_it(self):
        self.sweep(STEP)
        self.fake.sets["denied4"].append(self.elem("app", "203.0.113.50", 4444))
        found = self.sweep(2 * STEP)
        self.assertTrue(any("203.0.113.50" in str(f.get("detail")) for f in found), found)
        self.assertEqual(self.fake.reads("denied4"), 2)  # cada barrido, sin esperar a ningún temporizador

    def test_after_a_cut_the_next_sweep_also_reads_what_is_learned(self):
        self.sweep(STEP)
        reads = self.fake.reads("seen4")
        self.fake.sets["denied4"].append(self.elem("app", "203.0.113.50", 4444))
        self.sweep(2 * STEP)
        self.sweep(3 * STEP)
        self.assertEqual(self.fake.reads("seen4"), reads + 1)

    def test_a_flush_of_the_table_is_noticed_at_once_and_every_pinned_service_is_loaded_again(self):
        self.sweep(STEP)
        self.fake.table = False  # nftables reiniciado: sin tabla
        self.fake.watched.clear()
        self.fake.declared_sets.clear()
        self.fake.chains.clear()
        self.sweep(2 * STEP)
        self.assertTrue(self.fake.table)  # se recreó en el mismo barrido
        self.assertEqual(sorted(os.path.basename(c[2]) for c in self.fake.calls if c[1:2] == ["-f"]
                                and c[2].endswith(".nft")), [f"{n}.service.nft" for n in SVC])
        self.assertEqual(self.fake.watched, {f"system.slice/{n}.service" for n in SVC})

    def test_one_service_missing_from_the_set_is_loaded_again_within_five_minutes(self):
        self.sweep(STEP)
        self.fake.watched.discard("system.slice/db.service")  # alguien lo borró a mano
        for i in range(2, 14):
            self.sweep(i * STEP)
        self.assertIn("system.slice/db.service", self.fake.watched)
        self.assertEqual(len([c for c in self.fake.calls if c[1:2] == ["-f"] and "db.service.nft" in c[2]]), 1)

    def test_an_unreadable_watched_set_reloads_nothing_blindly(self):
        self.sweep(STEP)
        self.fake.fail_lists = True
        self.p._cadence.pop("housekeeping", None)
        self.sweep(2 * STEP)
        self.assertEqual([c for c in self.fake.calls if c[1:2] == ["-f"]], [])


class ObserveNoveltyTests(_Sweeps):
    """P0 de arx-98: sin --enforce, un destino nuevo de un servicio vigilado no puede tardar 300 s (rc2: 30 s)."""

    def setUp(self):
        super().setUp()
        self.enforce = False
        self.sweep(0)
        st = self.p.load()
        for i, name in enumerate(SVC):  # tres servicios ya vigilados, con un destino permitido
            s = st["subjects"][f"system.slice/{name}.service"]
            s.update(status="watching", mode="fixed", watching_since="2026-11-01T00:00:00+00:00",
                     dest={"tcp|104.20.23.0/24|443": {"first": "2026-10-01T00:00:00+00:00", "n": 9}})
            self.cgroup_ids[f"system.slice/{name}.service"] = str(100 + i)
        self.p._save(st)
        self.fake.calls.clear()

    def test_the_kernel_is_told_what_is_normal_for_every_watched_service_in_one_process(self):
        self.sweep(STEP)
        self.assertEqual(self.fake.watched_obs, {f"system.slice/{n}.service" for n in SVC})
        loads = [name for name, text in self.fake.loaded if "watched_obs" in text]
        self.assertEqual(loads, ["observe.nft"])  # una sola carga para todos
        text = next(t for n, t in self.fake.loaded if n == "observe.nft")
        self.assertIn('add element inet arx ok4 { "system.slice/app.service" . tcp . 104.20.23.0/24 . 443 }', text)
        self.assertNotIn("watched2", text)  # nada de lo que corta

    def test_the_rule_that_notices_a_novel_destination_never_drops(self):
        self.sweep(STEP)
        rules = " ".join(self.fake.chains.get("output", []))
        self.assertIn("@watched_obs", rules)
        self.assertIn("add @novel4", rules)
        self.assertIn("add @novel6", rules)
        novel = [r for r in self.fake.chains["output"] if "@novel" in r]
        self.assertTrue(novel and all("drop" not in r for r in novel), novel)
        self.assertIn("set novel4 ", self.fake.structure)
        self.assertIn("set watched_obs ", self.fake.structure)

    def test_a_novel_destination_is_reported_in_the_next_sweep(self):
        self.sweep(STEP)
        self.fake.sets["novel4"].append(self.elem("app", "203.0.113.50", 4444))  # el kernel lo ve entre dos barridos
        found = self.sweep(2 * STEP)
        hits = [f for f in found if "203.0.113.50" in str(f.get("detail"))]
        self.assertEqual(len(hits), 1, found)
        self.assertEqual((hits[0]["sev"], hits[0]["kind"]), ("high", "egress_profile"))

    def test_it_does_not_wait_for_what_is_learned(self):
        self.sweep(STEP)
        reads = self.fake.reads("seen4")
        self.fake.sets["novel4"].append(self.elem("db", "203.0.113.51", 8080))
        found = self.sweep(2 * STEP)
        self.assertTrue(any("203.0.113.51" in str(f.get("detail")) for f in found))
        self.assertEqual(self.fake.reads("seen4"), reads)  # `seen` sigue su ritmo de 300 s

    def test_what_the_profile_already_allows_is_not_a_finding(self):
        """El kernel compara por intervalo; la comprobación del perfil de Arx es la que manda."""
        self.sweep(STEP)
        self.fake.sets["novel4"].append(self.elem("app", "104.20.23.200", 443))  # dentro de la red permitida
        found = self.sweep(2 * STEP)
        self.assertFalse([f for f in found if "104.20.23.200" in str(f.get("detail"))], found)

    def test_the_novel_set_is_emptied_after_each_read_so_it_never_grows(self):
        self.sweep(STEP)
        for i in range(50):
            self.fake.sets["novel4"].append(self.elem("app", f"203.0.113.{i}", 4444))
        self.sweep(2 * STEP)
        self.assertEqual(self.fake.sets["novel4"], [])
        self.assertEqual(self.fake.count("nft", "delete", "element", "inet", "arx", "novel4"), 1)  # una orden
        self.assertEqual(self.fake.count("nft", "flush", "set", "inet", "arx", "novel4"), 0)

    def test_what_the_kernel_notes_between_the_read_and_the_cleanup_is_not_lost(self):
        """HZ#1 de Q: vaciar el conjunto entero borraba sin leer lo anotado entre la lectura y el vaciado."""
        self.sweep(STEP)
        self.fake.sets["novel4"].append(self.elem("app", "203.0.113.60", 4444))
        self.fake.after_list["novel4"] = [self.elem("db", "198.51.100.7", 53)]  # una conexión de un disparo
        first = self.sweep(2 * STEP)
        self.assertTrue(any("203.0.113.60" in str(f.get("detail")) for f in first))
        self.assertEqual(self.fake.sets["novel4"], [self.elem("db", "198.51.100.7", 53)])
        second = self.sweep(3 * STEP)
        self.assertTrue(any("198.51.100.7" in str(f.get("detail")) for f in second), second)

    def test_if_the_one_order_cleanup_fails_each_read_element_is_removed_alone(self):
        self.sweep(STEP)
        self.fake.fail_batch_delete = True
        for i in range(3):
            self.fake.sets["novel4"].append(self.elem("app", f"203.0.113.{i}", 4444))
        self.sweep(2 * STEP)
        self.assertEqual(self.fake.sets["novel4"], [])

    def test_a_novel_set_close_to_full_is_itself_a_finding(self):
        """HZ#2 de Q: lleno, el kernel deja de anotar y en «observar» nada lo corta."""
        self.sweep(STEP)
        for i in range(self.p.NOVEL_ALARM):
            self.fake.sets["novel4"].append(self.elem("app", f"10.{i // 65536}.{i // 256 % 256}.{i % 256}", 4444))
        found = self.sweep(2 * STEP)
        over = [f for f in found if "novel_overflow" in f.get("fp_key", "")]
        self.assertEqual(len(over), 1)
        self.assertEqual(over[0]["sev"], "high")
        self.assertIn("app.service", over[0]["detail"])

    def test_a_handful_of_novel_destinations_is_not_an_overflow(self):
        self.sweep(STEP)
        for i in range(20):
            self.fake.sets["novel4"].append(self.elem("app", f"203.0.113.{i}", 4444))
        found = self.sweep(2 * STEP)
        self.assertFalse([f for f in found if "novel_overflow" in f.get("fp_key", "")])

    def test_a_service_still_being_learned_is_not_reported(self):
        self.running.append("system.slice/fresh.service")
        self.sweep(STEP)
        self.fake.sets["novel4"].append(self.elem("fresh", "198.51.100.9", 443))
        found = self.sweep(2 * STEP)
        self.assertFalse([f for f in found if "198.51.100.9" in str(f.get("detail"))])

    def test_a_restarted_service_is_loaded_again_at_once(self):
        self.sweep(STEP)
        self.fake.loaded.clear()
        self.cgroup_ids["system.slice/db.service"] = "999"  # systemd le dio otro cgroup
        self.sweep(2 * STEP)
        loads = [t for n, t in self.fake.loaded if n == "observe.nft"]
        self.assertEqual(len(loads), 1)
        self.assertIn("db.service", loads[0])
        self.assertNotIn("app.service", loads[0])  # solo el que cambió
        self.fake.loaded.clear()
        self.sweep(3 * STEP)
        self.assertEqual(self.fake.loaded, [])  # y no se repite

    def test_a_novel_destination_of_a_service_that_restarted_is_still_attributed_to_it(self):
        """Si el servicio se reinició antes del barrido, el kernel lo anota con su cgroup viejo, como número."""
        self.sweep(STEP)
        self.cgroup_ids["system.slice/app.service"] = "777"  # reinició: nuevo cgroup
        self.sweep(2 * STEP)
        self.fake.sets["novel4"].append('100 . tcp . 203.0.113.60 . 4444 timeout 10m expires 9m')  # el viejo, ya muerto
        found = self.sweep(3 * STEP)
        hits = [f for f in found if "203.0.113.60" in str(f.get("detail"))]
        self.assertEqual(len(hits), 1, found)
        self.assertIn("system.slice/app.service", hits[0]["item"])

    def test_a_flushed_table_gets_every_watched_service_loaded_again(self):
        self.sweep(STEP)
        self.fake.loaded.clear()
        self.fake.table = False
        self.fake.watched_obs.clear()
        self.fake.declared_sets.clear()
        self.fake.chains.clear()
        self.sweep(2 * STEP)
        self.assertEqual(self.fake.watched_obs, {f"system.slice/{n}.service" for n in SVC})

    def test_the_budget_of_processes_is_the_same_as_without_the_novelty_sets(self):
        self.sweep(STEP)
        self.fake.calls.clear()
        for i in range(2, 42):
            self.sweep(i * STEP)
        self.assertLessEqual(self.fake.processes() / 40, 4.0, self.fake.calls[:12])
        self.assertEqual(self.fake.reads("novel4"), 40)  # cada barrido: es el que da la latencia
        self.assertLessEqual(self.fake.reads("seen4"), 5)

    def test_with_enforce_the_services_are_cut_not_merely_noticed(self):
        """En enforce los servicios van a `watched2` (con corte); `watched_obs` ya no se carga ni se lee."""
        self.enforce = True
        st = self.p.load()
        for name in SVC:
            st["subjects"][f"system.slice/{name}.service"]["enforced"] = True
        self.p._save(st)
        self.fake.loaded.clear()
        self.fake.calls.clear()
        self.sweep(2 * STEP)
        self.assertEqual([n for n, t in self.fake.loaded if "watched_obs" in t], [])
        self.assertEqual(self.fake.reads("novel4"), 0)

    def test_dead_cgroups_are_also_cleaned_from_the_observe_set(self):
        self.sweep(STEP)
        self.fake.watched_obs.add("4242")  # un cgroup que ya no existe sale como número en el listado
        for i in range(2, 14):
            self.sweep(i * STEP)
        self.assertTrue(any(c[:5] == ["nft", "delete", "element", "inet", "arx"] and c[5] == "watched_obs"
                            for c in self.fake.calls), self.fake.calls[:5])

    def test_accepting_a_destination_loads_the_service_again_so_the_kernel_stops_noticing_it(self):
        self.sweep(STEP)
        self.fake.loaded.clear()
        self.p.accept("system.slice/app.service|tcp|203.0.113.50|4444")
        self.sweep(2 * STEP)
        text = next(t for n, t in self.fake.loaded if n == "observe.nft")
        self.assertIn("203.0.113.0/24", text)

    def test_a_destination_accepted_by_another_process_is_loaded_too(self):
        """HZ#12: `arx accept` corre en la CLI; el daemon solo ve el perfil en disco."""
        self.sweep(STEP)
        self.fake.loaded.clear()
        st = self.p.load()
        st["subjects"]["system.slice/app.service"]["dest"]["tcp|203.0.113.0/24|4444"] = {
            "first": "2026-11-15T00:00:00+00:00", "n": 0, "accepted": True}
        self.p._save(st)
        self.sweep(2 * STEP)
        text = next(t for n, t in self.fake.loaded if n == "observe.nft")
        self.assertIn("203.0.113.0/24", text)
        self.assertNotIn("system.slice/db.service", text)  # solo el servicio que cambió

    def test_nothing_changed_nothing_is_loaded_again(self):
        self.sweep(STEP)
        self.fake.loaded.clear()
        for i in range(2, 6):
            self.sweep(i * STEP)
        self.assertEqual([n for n, _ in self.fake.loaded if n == "observe.nft"], [])


class TheSweepEndsItsReadingBeforeTheResponses(unittest.TestCase):
    def test_actions_run_after_the_cache_ended_and_the_profile_inside_it(self):
        _isolate()
        from arx.modules import baseline, canaries, guard, profile, response, sensors, service, sweepcache, vaccines
        seen = {}
        finding = {"sev": "low", "kind": "x", "detail": "d"}
        patches = [(response, "restore_kernel_blocks", lambda: None), (response, "ensure_nft_tracking", lambda: True),
                   (baseline, "snapshot", lambda: {}), (baseline, "compare", lambda b, s: []),
                   (guard, "_integrity_drift", lambda b, i: []), (canaries, "check", lambda: []),
                   (sensors, "collect_events", lambda: []), (sensors, "detect_uid0_accounts", lambda known=(): []),
                   (vaccines, "findings", lambda known=(): []), (service, "self_check", lambda: []),
                   (profile, "sweep", lambda enforce=False, cfg=None: seen.setdefault(
                       "profile", sweepcache._owner[0] is not None) and [finding]),
                   (guard, "_prepare", lambda f, enrich=True: f), (guard, "_ready", lambda fs: fs),
                   (response, "handle", lambda f, enforce=False, cfg=None: seen.setdefault(
                       "handle", sweepcache._owner[0]) or {"new": False, "tier": 0, "sev": "low", "detail": "d",
                                                          "status": "x"})]
        for obj, name, value in patches:
            p = mock.patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)
        guard.sweep({"meta": {}, "sets": {}}, enforce=False, include_suid=False, cfg={})
        self.assertIs(seen["profile"], True)  # el perfil lee con la caché del barrido…
        self.assertIsNone(seen["handle"])     # …y las respuestas (bloquear, cerrar una sesión) preguntan de nuevo


class MemoTests(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx.modules import profile, sweepcache
        self.p, self.sc = profile, sweepcache
        self.fake = FakeNft()
        patch = mock.patch.object(profile.subprocess, "run", self.fake.run)
        patch.start()
        self.addCleanup(patch.stop)
        self.sc.end_sweep()
        self.addCleanup(self.sc.end_sweep)

    def test_within_a_sweep_a_set_is_read_once(self):
        self.sc.begin_sweep()
        for _ in range(5):
            self.p._nft_out("list", "set", "inet", "arx", "seen4")
        self.assertEqual(self.fake.reads("seen4"), 1)
        self.sc.begin_sweep()
        self.p._nft_out("list", "set", "inet", "arx", "seen4")
        self.assertEqual(self.fake.reads("seen4"), 2)

    def test_outside_a_sweep_nothing_is_kept(self):
        for _ in range(3):
            self.p._nft_out("list", "set", "inet", "arx", "seen4")
        self.assertEqual(self.fake.reads("seen4"), 3)

    def test_after_the_read_part_of_the_sweep_actions_ask_again(self):
        self.sc.begin_sweep()
        self.p._nft_out("list", "set", "inet", "arx", "seen4")
        self.sc.end_sweep()
        self.p._nft_out("list", "set", "inet", "arx", "seen4")
        self.assertEqual(self.fake.reads("seen4"), 2)

    def test_another_thread_never_sees_the_sweep_s_data(self):
        self.sc.begin_sweep()
        self.p._nft_out("list", "set", "inet", "arx", "seen4")
        out = []
        t = threading.Thread(target=lambda: out.append(self.p._nft_out("list", "set", "inet", "arx", "seen4")))
        t.start()
        t.join()
        self.assertEqual(self.fake.reads("seen4"), 2)

    def test_a_write_makes_the_next_read_fresh(self):
        self.sc.begin_sweep()
        self.p._nft_out("list", "set", "inet", "arx", "ok4")
        self.p._nft("delete", "element", "inet", "arx", "ok4", "{ 1 . tcp . 10.0.0.0/24 . 443 }")
        self.p._nft_out("list", "set", "inet", "arx", "ok4")
        self.assertEqual(self.fake.reads("ok4"), 2)
        self.p._nft_out("list", "set", "inet", "arx", "ok4")
        self.assertEqual(self.fake.reads("ok4"), 2)

    def test_a_failure_is_never_kept_as_an_empty_answer(self):
        self.sc.begin_sweep()
        self.fake.fail_lists = True
        self.assertEqual(self.p._nft_out("list", "set", "inet", "arx", "seen4"), "")
        self.fake.fail_lists = False
        self.fake.sets["seen4"].append('"system.slice/app.service" . tcp . 1.2.3.4 . 443')
        self.assertIn("1.2.3.4", self.p._nft_out("list", "set", "inet", "arx", "seen4"))

    def test_the_age_limit_protects_a_caller_that_never_ends_the_sweep(self):
        from arx.modules import sweepcache
        clock = [0.0]
        with mock.patch.object(sweepcache.time, "monotonic", lambda: clock[0]):
            self.sc.begin_sweep()
            self.p._nft_out("list", "set", "inet", "arx", "seen4")
            clock[0] = sweepcache.MAX_AGE_S + 1
            self.p._nft_out("list", "set", "inet", "arx", "seen4")
        self.assertEqual(self.fake.reads("seen4"), 2)

    def test_listening_ports_are_asked_to_ss_once_per_sweep_and_each_caller_gets_its_own_copy(self):
        from arx.modules import recon
        with mock.patch.object(recon, "_run", lambda argv, timeout=8: self.fake.run(argv) and
                               "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))"):
            self.sc.begin_sweep()
            first = recon.collect_ports()
            first[0]["proto"] = "mutado"
            second = recon.collect_ports()
            third = recon.collect_ports()
            self.assertEqual(self.fake.count("ss", "-tulpnH"), 1)
            self.assertEqual((second[0]["proto"], third[0]["proto"]), ("tcp", "tcp"))
            self.sc.end_sweep()
            recon.collect_ports()
            self.assertEqual(self.fake.count("ss", "-tulpnH"), 2)

    def test_a_clock_that_goes_back_does_not_stop_the_periodic_work(self):
        t0 = NOW
        self.assertTrue(self.p._due("x", 300, t0))
        self.assertFalse(self.p._due("x", 300, t0 + timedelta(seconds=100)))
        self.assertTrue(self.p._due("x", 300, t0 + timedelta(seconds=400)))
        self.assertTrue(self.p._due("x", 300, t0 - timedelta(days=1)))  # el reloj retrocedió


class TrackingTests(_Sweeps):
    def test_the_structure_is_checked_whole_every_five_minutes_and_at_once_if_the_table_is_gone(self):
        self.sweep(0)
        whole = self.fake.count("nft", "-t", "list", "table", "inet", "arx")
        for i in range(1, 9):  # hasta el segundo 240
            self.sweep(i * STEP)
        self.assertEqual(self.fake.count("nft", "-t", "list", "table", "inet", "arx"), whole)
        self.fake.table = False
        self.sweep(9 * STEP)
        self.assertGreater(self.fake.count("nft", "-t", "list", "table", "inet", "arx"), whole)
        self.assertEqual(self.r.tracking_epoch(), 1)
        self.assertTrue(self.fake.table)

    def test_the_whole_structure_is_looked_at_again_after_five_minutes(self):
        self.sweep(0)
        whole = self.fake.count("nft", "-t", "list", "table", "inet", "arx")
        for t, expect_more in ((120, False), (330, True)):  # solo `ensure_nft_tracking`: sin la pista del perfil
            self.now[0] = 1000.0 + t
            self.sc.begin_sweep()
            self.r.ensure_nft_tracking()
            self.sc.end_sweep()
            now_whole = self.fake.count("nft", "-t", "list", "table", "inet", "arx")
            self.assertEqual(now_whole > whole, expect_more, t)
            whole = now_whole

    def test_the_profile_structure_is_not_called_fine_when_the_table_is_gone(self):
        """setup() por sí solo (sin `ensure_nft_tracking` delante) tampoco da por buena una tabla que ya no está."""
        self.sweep(0)
        self.sc.begin_sweep()
        self.assertTrue(self.p.setup())
        self.fake.table = False
        self.fake.declared_sets.clear()
        self.fake.chains.clear()
        self.sc.begin_sweep()
        before = self.fake.count("nft", "add", "table")
        self.assertTrue(self.p.setup())
        self.sc.end_sweep()
        self.assertGreater(self.fake.count("nft", "add", "table"), before)  # volvió a montarla

    def test_an_action_path_never_takes_the_cheap_answer(self):
        """Bloquear una IP comprueba la estructura entera, como siempre: la ventana es solo del barrido."""
        self.sweep(0)
        before = self.fake.count("nft", "-t", "list", "table", "inet", "arx")
        self.r._nft_setup()
        self.assertEqual(self.fake.count("nft", "-t", "list", "table", "inet", "arx"), before + 1)

    def test_an_unreadable_table_is_not_taken_for_a_healthy_one(self):
        with mock.patch.object(self.r.subprocess, "run", side_effect=OSError("no nft")):
            self.sweep_cheap = self.r._arx_table_present()
        self.assertIsNone(self.sweep_cheap)


if __name__ == "__main__":
    unittest.main()
