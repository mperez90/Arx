"""B78-b · Parte 1: lo aprendido de un servicio muy variable, por PUERTOS (piloto A: tailscaled en aprendizaje, ~200 destinos
STUN por ventana llenan `seen` y cada lectura cuesta ~8 ms de CPU por elemento).

Un servicio cuyo perfil ya es por puertos (`len(redes) >= OPEN_DIVERSITY`, el criterio de `_mode`) entra en `seen_ports`:
la regla de `seen` lo deja fuera y otra apunta (cgroup, proto, puerto) en `seenp4/6`, que se lee con la misma cadencia y
el mismo «leer, procesar, quitar lo leído». La regla de `seen` que ya existe en toda instalación se SUSTITUYE por su handle:
primero la nueva, luego se borra la vieja, sin un instante sin regla de aprendizaje. Corre con: python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from test_nft_budget import STEP, FakeNft, _R, _Sweeps  # noqa: E402

OLD_SEEN = ('meta oifname != lo ct state new ct direction original meta l4proto {{ tcp, udp }} meta nfproto {nf} '
            'socket cgroupv2 level 1 "system.slice" add @seen{fam} {{ socket cgroupv2 level 2 . meta l4proto . {addr} daddr . '
            'th dport }}')


class PortsFakeNft(FakeNft):
    """El nft simulado, con handles en las reglas, `insert rule`/`delete rule` por handle y los conjuntos nuevos."""

    def __init__(self):
        super().__init__()
        for n in ("seenp4", "seenp6"):
            self.sets[n] = []
        self.seen_ports: set = set()
        self.handles: list = []
        self.next_handle = 10
        self.min_seen_rules = {"4": None, "6": None}   # el menor número de reglas de `seen` que hubo tras cada orden
        self.log: list = []

    # ── reglas con handle ─────────────────────────────────────────────────────
    def seed_old_rules(self):
        """Una instalación de antes: sets y reglas como los dejaba la versión anterior (sin `seen_ports`)."""
        old_sets = ["block_tcp", "block_udp", "block_ipv4", "block_ipv6", "scan4", "scan6", "c2_out4", "c2_out6",
                    "seen4", "seen6", "denied4", "denied6", "ok4", "ok6", "watched2", "watched_obs", "novel4", "novel6"]
        self.declared_sets = list(old_sets)
        self.chains["input"], self.chains["output"] = [], []
        for fam, addr, nf in (("4", "ip", "ipv4"), ("6", "ip6", "ipv6")):
            self.add_rule(OLD_SEEN.format(fam=fam, addr=addr, nf=nf))
            self.add_rule(f"socket cgroupv2 level 2 @watched2 ... != @ok{fam} add @denied{fam} {{ x }} drop")
            self.add_rule(f"socket cgroupv2 level 2 @watched_obs ... != @ok{fam} add @novel{fam} {{ x }}")
        self.min_seen_rules = {"4": None, "6": None}  # lo que se mide es lo que pasa DESPUÉS de la instalación de antes
        self._watch_seen_rules()

    def add_rule(self, text, before=None):
        out = self.chains.setdefault("output", [])
        h = self.next_handle
        self.next_handle += 1
        if before is None:
            out.append(text)
            self.handles.append(h)
        else:
            i = self.handles.index(before)
            out.insert(i, text)
            self.handles.insert(i, h)
        self._watch_seen_rules()

    def _watch_seen_rules(self):
        for fam in ("4", "6"):
            n = sum(1 for r in self.chains.get("output", []) if re.search(rf"add @seen{fam}\b", r))
            cur = self.min_seen_rules[fam]
            self.min_seen_rules[fam] = n if cur is None else min(cur, n)

    def seen_rules(self, fam):
        return [r for r in self.chains.get("output", []) if re.search(rf"add @seen{fam}\b", r)]

    def ports_rules(self, fam):
        return [r for r in self.chains.get("output", []) if f"add @seenp{fam}" in r]

    def run(self, argv, **kw):
        argv = [str(a) for a in argv]
        args = argv[1:] if argv[0] == "nft" else []
        if args[:4] == ["-a", "list", "chain", "inet"]:
            self.calls.append(argv)
            body = "".join(f"\t\t{r} # handle {h}\n" for r, h in zip(self.chains.get("output", []), self.handles))
            return _R(0, f"table inet arx {{\n\tchain output {{\n{body}\t}}\n}}\n")
        if args[:3] == ["insert", "rule", "inet"] and "position" in args:
            self.calls.append(argv)
            i = args.index("position")
            self.add_rule(" ".join(args[i + 2:]), before=int(args[i + 1]))
            self.log.append(("insert", int(args[i + 1])))
            return _R(0, "")
        if args[:3] == ["delete", "rule", "inet"] and "handle" in args:
            self.calls.append(argv)
            h = int(args[args.index("handle") + 1])
            if h not in self.handles:
                return _R(1, "")
            i = self.handles.index(h)
            del self.chains["output"][i], self.handles[i]
            self.log.append(("delete", h))
            self._watch_seen_rules()
            return _R(0, "")
        if args[:3] == ["add", "rule", "inet"] and args[4] == "output":
            self.calls.append(argv)
            self.add_rule(" ".join(args[5:]))
            self.log.append(("add", None))
            return _R(0, "")
        if args[:3] == ["add", "element", "inet"] and args[4] == "seen_ports":
            self.calls.append(argv)
            self.seen_ports |= set(re.findall(r'"([^"]+)"', " ".join(args[5:])))
            return _R(0, "")
        if args[:3] == ["delete", "element", "inet"] and args[4] == "seen_ports":
            self.calls.append(argv)
            for m in re.findall(r'"([^"]+)"|(\d+)', " ".join(args[5:])):
                self.seen_ports.discard(m[0] or m[1])
            return _R(0, "")
        if args[:2] == ["list", "set"] and args[4] == "seen_ports":
            self.calls.append(argv)
            elems = [p if p.isdigit() else f'"{p}"' for p in sorted(self.seen_ports)]
            body = f"\t\telements = {{ {', '.join(elems)} }}\n" if elems else ""
            return _R(0, f"table inet arx {{\n\tset seen_ports {{\n{body}\t}}\n}}\n")
        return super().run(argv, **kw)


class _Ports(_Sweeps):
    def setUp(self):
        super().setUp()
        self.fake = PortsFakeNft()
        # el parche de `subprocess.run` del `_Sweeps.setUp` apunta al nft anterior: se cambia por el nuevo
        import unittest.mock as mock
        p = mock.patch.object(self.p.subprocess, "run", self.fake.run)
        p.start()
        self.addCleanup(p.stop)
        self.cgroup_ids.update({f"system.slice/{n}.service": str(100 + i) for i, n in enumerate(["app", "db", "web", "fresh"])})

    def diverse(self, name="app", nets=None):
        """El servicio con `nets` redes distintas aprendidas (lo que tailscaled acaba teniendo)."""
        self.sweep(0) if not self.p.load().get("subjects") else None
        st = self.p.load()
        s = st["subjects"][f"system.slice/{name}.service"]
        n = self.p.OPEN_DIVERSITY if nets is None else nets
        s["dest"] = {f"udp|10.{i // 250}.{i % 250}.0/24|3478": {"first": "2026-11-14T00:00:00+00:00", "n": 1} for i in range(n)}
        self.p._save(st)

    def portelem(self, name, proto="udp", port=3478, cg=None):
        who = cg or f'"system.slice/{name}.service"'
        return f"{who} . {proto} . {port} timeout 1d expires 23h"


class StructureTests(_Ports):

    def test_a_fresh_host_gets_the_ports_sets_and_rules_and_no_rule_without_the_exclusion(self):
        self.sweep(0)
        for name in ("seen_ports", "seenp4", "seenp6"):
            self.assertIn(name, self.fake.declared_sets)
        for fam in ("4", "6"):
            seen, ports = self.fake.seen_rules(fam), self.fake.ports_rules(fam)
            self.assertEqual(len(seen), 1, seen)
            self.assertIn("@seen_ports", seen[0])
            self.assertIn("!=", seen[0].split("@seen_ports")[0].split("level 2")[-1])  # la deja FUERA
            self.assertEqual(len(ports), 1, ports)
            self.assertIn("@seen_ports", ports[0])
            self.assertNotIn("!=", ports[0].split("@seen_ports")[0].split("level 2")[-1])  # la de puertos, solo ESOS

    def test_the_ports_set_has_the_same_shape_as_seen_without_the_address(self):
        self.sweep(0)
        text = " ".join(" ".join(c) for c in self.fake.calls if c[:5] == ["nft", "add", "set", "inet", "arx"])
        self.assertRegex(text, r"seenp4 \{ typeof socket cgroupv2 level 2 \. meta l4proto \. th dport ; flags dynamic,timeout; "
                               r"timeout 1d; size 65535; \}")
        self.assertRegex(text, r"seen_ports \{ typeof socket cgroupv2 level 2; \}")

    def test_the_rule_for_ports_never_drops(self):
        self.sweep(0)
        for fam in ("4", "6"):
            self.assertNotIn("drop", self.fake.ports_rules(fam)[0])

    def test_nothing_else_about_ok_denied_novel_watched_changes(self):
        self.sweep(0)
        out = " ".join(self.fake.chains["output"])
        for needle in ("@ok4", "@denied4", "@novel4", "@watched2", "@watched_obs"):
            self.assertIn(needle, out)


class OldRuleReplacementTests(_Ports):
    """La regla de `seen` sin exclusión existe en TODAS las instalaciones: hay que sustituirla, una vez, sin hueco."""

    def setUp(self):
        super().setUp()
        self.fake.seed_old_rules()

    def test_the_old_rule_is_replaced_once_by_handle_and_the_new_one_goes_first(self):
        self.sweep(0)
        for fam in ("4", "6"):
            seen = self.fake.seen_rules(fam)
            self.assertEqual(len(seen), 1, seen)
            self.assertIn("@seen_ports", seen[0])
            self.assertEqual(len(self.fake.ports_rules(fam)), 1)
        inserts = [e for e in self.fake.log if e[0] == "insert"]
        deletes = [e for e in self.fake.log if e[0] == "delete"]
        self.assertEqual(len(deletes), 2, self.fake.log)       # la de cada familia, y solo esas
        first_delete = self.fake.log.index(deletes[0])
        self.assertTrue(any(i < first_delete for i, e in enumerate(self.fake.log) if e[0] == "insert"), self.fake.log)
        self.assertGreaterEqual(len(inserts), 2)

    def test_there_is_never_an_instant_without_a_rule_that_learns(self):
        self.sweep(0)
        self.assertEqual(self.fake.min_seen_rules, {"4": 1, "6": 1})  # tras cada orden, ≥ 1; nunca 0

    def test_the_new_rules_keep_the_old_ones_place_before_the_drop(self):
        self.sweep(0)
        out = self.fake.chains["output"]
        for fam in ("4", "6"):
            deny = next(i for i, r in enumerate(out) if f"@denied{fam}" in r)
            for r in self.fake.seen_rules(fam) + self.fake.ports_rules(fam):
                self.assertLess(out.index(r), deny)  # antes del corte de su familia, como la regla de antes

    def test_only_arx_s_own_rule_is_deleted(self):
        self.fake.add_rule("tcp dport 9999 accept # una regla ajena en la misma cadena")
        self.sweep(0)
        self.assertIn("tcp dport 9999 accept # una regla ajena en la misma cadena", self.fake.chains["output"])
        self.assertEqual(sum(1 for r in self.fake.chains["output"] if "@denied" in r), 2)  # las de corte siguen

    def test_it_is_idempotent_nothing_more_happens_in_later_sweeps(self):
        self.sweep(0)
        n_log, rules = len(self.fake.log), list(self.fake.chains["output"])
        for i in range(1, 40):  # 20 min: varias comprobaciones de la estructura
            self.sweep(i * STEP)
        self.assertEqual(len(self.fake.log), n_log)
        self.assertEqual(self.fake.chains["output"], rules)

    def test_a_flushed_table_gets_the_new_style_rules_directly(self):
        self.sweep(0)
        self.fake.table = False  # nftables reiniciado: sin tabla, sin sets, sin reglas
        self.fake.chains, self.fake.declared_sets, self.fake.handles = {}, [], []
        self.fake.log.clear()
        self.fake.seen_ports.clear()
        for i in range(1, 4):
            self.sweep(i * STEP)
        for fam in ("4", "6"):
            self.assertEqual(len(self.fake.seen_rules(fam)), 1)
            self.assertIn("@seen_ports", self.fake.seen_rules(fam)[0])
        self.assertEqual([e for e in self.fake.log if e[0] == "delete"], [])  # nada viejo que borrar

    def test_if_the_old_rule_survives_a_failed_delete_the_next_check_removes_it_without_duplicating(self):
        real = self.fake.run
        state = {"fail_once": True}

        def flaky(argv, **kw):
            if list(argv)[1:4] == ["delete", "rule", "inet"] and state["fail_once"]:
                state["fail_once"] = False
                return _R(1, "")
            return real(argv, **kw)
        import unittest.mock as mock
        with mock.patch.object(self.p.subprocess, "run", flaky):
            self.sweep(0)
            for i in range(1, 25):
                self.sweep(i * STEP)
        for fam in ("4", "6"):
            self.assertEqual(len(self.fake.seen_rules(fam)), 1, self.fake.seen_rules(fam))
            self.assertEqual(len(self.fake.ports_rules(fam)), 1)

    def test_the_old_rule_is_never_deleted_if_the_new_one_could_not_be_inserted(self):
        real = self.fake.run

        def no_insert(argv, **kw):
            if list(argv)[1:3] == ["insert", "rule"]:
                return _R(1, "")
            return real(argv, **kw)
        import unittest.mock as mock
        with mock.patch.object(self.p.subprocess, "run", no_insert):
            self.sweep(0)
        for fam in ("4", "6"):
            self.assertEqual(len(self.fake.seen_rules(fam)), 1)
            self.assertNotIn("@seen_ports", self.fake.seen_rules(fam)[0])  # sigue la de antes: aprender no se detiene
        self.assertEqual([e for e in self.fake.log if e[0] == "delete"], [])

    def test_an_unreadable_chain_does_not_break_the_rest(self):
        real = self.fake.run

        def no_handles(argv, **kw):
            if list(argv)[1:3] == ["-a", "list"]:
                return _R(1, "")
            return real(argv, **kw)
        import unittest.mock as mock
        with mock.patch.object(self.p.subprocess, "run", no_handles):
            self.sweep(0)
        for fam in ("4", "6"):
            self.assertGreaterEqual(len(self.fake.seen_rules(fam)), 1)  # la vieja sigue ahí: aprender no se detiene


class SeenPortsMembershipTests(_Ports):

    def test_a_service_that_reaches_open_diversity_goes_to_seen_ports(self):
        self.sweep(0)
        self.diverse("app")  # exactamente OPEN_DIVERSITY: el mismo criterio que `_mode`
        self.sweep(STEP)
        self.assertEqual(self.fake.seen_ports, {"system.slice/app.service"})

    def test_one_net_below_the_threshold_it_stays_out(self):
        self.sweep(0)
        self.diverse("app", self.p.OPEN_DIVERSITY - 1)
        self.sweep(STEP)
        self.assertEqual(self.fake.seen_ports, set())

    def test_the_threshold_is_the_one_of_mode_and_nothing_else(self):
        self.sweep(0)
        self.diverse("app")
        s = self.subject("app")
        self.assertEqual(self.p._mode(s), "ports")
        self.sweep(STEP)
        self.assertIn("system.slice/app.service", self.fake.seen_ports)

    def test_a_service_with_no_profile_yet_is_not_in_it(self):
        self.sweep(0)
        self.sweep(STEP)
        self.assertEqual(self.fake.seen_ports, set())

    def test_it_is_loaded_once_not_every_sweep(self):
        self.sweep(0)
        self.diverse("app")
        for i in range(1, 12):
            self.sweep(i * STEP)
        self.assertEqual(self.fake.count("nft", "add", "element", "inet", "arx", "seen_ports"), 1)

    def test_a_service_restarted_with_another_cgroup_is_loaded_again_at_once(self):
        self.cgroup_ids["system.slice/app.service"] = "100"
        self.sweep(0)
        self.diverse("app")
        self.sweep(STEP)
        self.assertEqual(self.fake.count("nft", "add", "element", "inet", "arx", "seen_ports"), 1)
        self.cgroup_ids["system.slice/app.service"] = "101"  # reinició: otro cgroup
        self.sweep(2 * STEP)
        self.assertEqual(self.fake.count("nft", "add", "element", "inet", "arx", "seen_ports"), 2)
        self.sweep(3 * STEP)
        self.assertEqual(self.fake.count("nft", "add", "element", "inet", "arx", "seen_ports"), 2)

    def test_several_services_are_loaded_in_one_process(self):
        self.sweep(0)
        self.diverse("app")
        self.diverse("db")
        self.sweep(STEP)
        self.assertEqual(self.fake.count("nft", "add", "element", "inet", "arx", "seen_ports"), 1)
        self.assertEqual(self.fake.seen_ports, {"system.slice/app.service", "system.slice/db.service"})

    def test_a_flushed_table_loads_them_again(self):
        self.sweep(0)
        self.diverse("app")
        self.sweep(STEP)
        self.fake.seen_ports.clear()
        self.fake.table = False  # nftables reiniciado
        self.fake.chains, self.fake.declared_sets, self.fake.handles = {}, [], []
        self.sweep(2 * STEP)
        self.sweep(3 * STEP)
        self.assertEqual(self.fake.seen_ports, {"system.slice/app.service"})

    def test_a_service_already_watching_by_ports_stays_in_it(self):
        """Al pasar a vigilar sigue en puertos: lo que `seen` vería de él (IPs) no sirve de nada y es lo que cuesta."""
        self.sweep(0)
        st = self.p.load()
        s = st["subjects"]["system.slice/app.service"]
        s.update(status="watching", mode="ports", dest={"udp|0.0.0.0/0|3478": {"first": "2026-11-14T00:00:00+00:00", "n": 1}})
        self.p._save(st)
        self.sweep(STEP)
        self.assertIn("system.slice/app.service", self.fake.seen_ports)

    def test_a_service_watching_by_fixed_destinations_is_not_in_it(self):
        self.sweep(0)
        st = self.p.load()
        st["subjects"]["system.slice/app.service"].update(status="watching", mode="fixed")
        self.p._save(st)
        self.sweep(STEP)
        self.assertEqual(self.fake.seen_ports, set())

    def test_dead_cgroups_are_cleaned_from_seen_ports(self):
        self.fake.seen_ports.add("12345")
        for i in range(40):
            self.sweep(i * STEP)
        self.assertNotIn("12345", self.fake.seen_ports)


class LearningByPortsTests(_Ports):

    def setUp(self):
        super().setUp()
        self.sweep(0)
        self.diverse("app")
        self.sweep(STEP)

    def window(self, start=2):
        for i in range(start, start + self.p.SEEN_EVERY_S // STEP + 2):
            self.sweep(i * STEP)

    def test_the_ports_it_opened_are_learned_as_any_address_on_that_port(self):
        self.fake.sets["seenp4"].append(self.portelem("app", "udp", 41641))
        self.fake.sets["seenp6"].append(self.portelem("app", "udp", 3479))
        self.window()
        dest = self.subject("app")["dest"]
        self.assertIn("udp|0.0.0.0/0|41641", dest)
        self.assertIn("udp|::/0|3479", dest)

    def test_what_is_learned_is_what_allowed_already_produces_in_ports_mode(self):
        self.fake.sets["seenp4"].append(self.portelem("app", "udp", 41641))
        self.window()
        s = self.subject("app")
        s["mode"] = self.p._mode(s)
        self.assertEqual(s["mode"], "ports")
        self.assertIn(("udp", "0.0.0.0/0", 41641), self.p._allowed(s))

    def test_what_was_read_is_removed_from_the_kernel_after_processing(self):
        self.fake.sets["seenp4"].append(self.portelem("app", "udp", 41641))
        self.window()
        self.assertEqual(self.fake.sets["seenp4"], [])

    def test_it_is_read_with_the_same_cadence_as_seen(self):
        for i in range(2, 2 + 4 * (self.p.SEEN_EVERY_S // STEP)):
            self.sweep(i * STEP)
        self.assertEqual(self.fake.reads("seenp4"), self.fake.reads("seen4"))
        self.assertEqual(self.fake.reads("seenp6"), self.fake.reads("seen6"))
        self.assertLessEqual(self.fake.reads("seenp4"), 6)

    def test_a_new_service_makes_it_read_at_once_like_seen(self):
        before = self.fake.reads("seenp4")
        self.running.append("system.slice/fresh.service")
        self.sweep(2 * STEP)
        self.assertEqual(self.fake.reads("seenp4"), before + 1)

    def test_a_restarted_service_that_shows_as_a_number_is_still_learned(self):
        st = self.p.load()
        st["subjects"]["system.slice/app.service"].setdefault("ids", []).append("4242")
        self.p._save(st)
        self.fake.sets["seenp4"].append(self.portelem("app", "udp", 3480, cg="4242"))
        self.window()
        self.assertIn("udp|0.0.0.0/0|3480", self.subject("app")["dest"])
        self.assertEqual(self.fake.sets["seenp4"], [])

    def test_an_unknown_cgroup_is_ignored_but_still_cleaned(self):
        self.fake.sets["seenp4"].append(self.portelem("ghost", "tcp", 1234))
        self.window()
        self.assertNotIn("tcp|0.0.0.0/0|1234", str(self.p.load()))
        self.assertEqual(self.fake.sets["seenp4"], [])

    def test_a_port_counts_each_time_it_is_read_like_a_destination(self):
        self.fake.sets["seenp4"].append(self.portelem("app", "udp", 41641))
        self.window()
        self.fake.sets["seenp4"].append(self.portelem("app", "udp", 41641))
        self.window(2 + self.p.SEEN_EVERY_S // STEP + 2)
        self.assertEqual(self.subject("app")["dest"]["udp|0.0.0.0/0|41641"]["n"], 2)

    def test_a_service_watching_produces_no_finding_from_its_ports(self):
        """En vigilancia el corte y el aviso los hacen `denied` y `novel`; lo aprendido solo es el respaldo y de un servicio
        por puertos no tiene IP que mostrar."""
        st = self.p.load()
        st["subjects"]["system.slice/app.service"].update(status="watching", mode="ports")
        self.p._save(st)
        self.fake.sets["seenp4"].append(self.portelem("app", "udp", 55555))
        found = []
        for i in range(2, 2 + self.p.SEEN_EVERY_S // STEP + 2):
            found += self.sweep(i * STEP)
        self.assertEqual([f for f in found if f.get("kind") == "egress_profile"], [])
        self.assertEqual(self.fake.sets["seenp4"], [])
        self.assertNotIn("udp|0.0.0.0/0|55555", self.subject("app")["dest"])  # y lo aprendido de un vigilado no se toca

    def test_the_plain_seen_set_still_works_for_services_that_are_not_by_ports(self):
        self.fake.sets["seen4"].append(self.elem("db", "203.0.113.7", 8443))
        self.window()
        self.assertIn("tcp|203.0.113.0/24|8443", self.subject("db")["dest"])


class ListingCostTests(_Ports):

    def test_a_service_by_ports_no_longer_adds_destinations_to_seen_so_the_cost_is_flat(self):
        """El kernel decide qué entra en `seen`: con el servicio en `seen_ports`, la regla lo deja fuera. Lo que se prueba
        aquí es que lo declarado en nft es lo que lo consigue (la prueba con nft real está en el lab)."""
        self.sweep(0)
        out = " ".join(self.fake.chains["output"])
        self.assertIn("!= @seen_ports", out)
        self.assertIn("@seen_ports add @seenp4", out.replace("  ", " "))


if __name__ == "__main__":
    unittest.main()
