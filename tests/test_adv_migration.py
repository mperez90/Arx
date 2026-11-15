"""Pista Q · R4 — las bases selladas reales migran al formato por fichero sin falsas alarmas.

Usa como fixtures PRIVADOS las bases selladas archivadas de los VPS antes de reinstalarlos
(DevelopDocs/pruebas-reales/…, fuera del repo público). Cada tarball trae `baseline.json` (formato legacy por
grupo), la bóveda con las copias buenas y su manifiesto.

Propiedad R4: para cada grupo cuya bóveda reproduce EXACTAMENTE el hash sellado (la copia buena == lo sellado),
`integrity.migrate` debe adoptar sus ficheros fichero a fichero y NO marcar el grupo como cambiado; y un `drift`
sobre lo adoptado no debe inventar hallazgos (contenido == sellado). Un grupo cuya bóveda NO reproduce el hash
(copia incompleta) queda legítimamente pendiente — no se exige aquí.

Se salta si los fixtures privados no están (p. ej. en CI pública).

Ejecutar:  python3 -m pytest tests/test_adv_migration.py -q
"""
import glob
import hashlib
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

FIXTURE_DIR = "/Users/mpz/Desktop/Arx/DevelopDocs/pruebas-reales/vps-final-pre-reinstalacion-2026-11-14"
TARBALLS = sorted(glob.glob(os.path.join(FIXTURE_DIR, "*.tar.gz")))


def _new_group(path: str, legacy_key: str) -> str:
    """Grupo nuevo de una ruta a partir de su grupo legacy (apt_sources se re-separa, systemd_units→systemd)."""
    if path.startswith("/etc/apt/apt.conf"):
        return "apt_conf"
    if legacy_key == "systemd_units":
        return "systemd"
    return legacy_key


@unittest.skipUnless(TARBALLS, "fixtures privados de DevelopDocs no disponibles")
class SealedBasesMigrateWithoutFalseAlarms(unittest.TestCase):

    def _load(self, tarball, work):
        import json
        with tarfile.open(tarball) as t:
            t.extractall(work, filter="data")
        state = glob.glob(f"{work}/**/var/lib/arx", recursive=True)[0]
        os.environ["ARX_STATE_DIR"] = state
        import importlib
        from arx import config as _cfg
        importlib.reload(_cfg)  # relee ARX_STATE_DIR
        from arx.modules import integrity, baseline, response
        importlib.reload(integrity); importlib.reload(baseline); importlib.reload(response)
        sealed = json.load(open(f"{state}/baseline.json"))["integrity"]
        manifest = json.load(open(f"{state}/vault/manifest.json"))
        vault = response.vault_entries()
        by_group = {}
        for path, meta in manifest.items():
            if "quarantined_from" in meta or path not in vault:
                continue
            by_group.setdefault(meta["key"], []).append(path)
        return integrity, baseline, sealed, vault, by_group

    def test_each_base_migrates_cleanly(self):
        for tarball in TARBALLS:
            with self.subTest(base=os.path.basename(tarball)), tempfile.TemporaryDirectory() as work:
                integrity, baseline, sealed, vault, by_group = self._load(tarball, work)

                # grupos cuya bóveda reproduce el hash sellado (copia fiel de lo sellado)
                faithful = {g: paths for g, paths in by_group.items()
                            if g != "suid_set"
                            and baseline.legacy_group_hash(g, {p: vault[p][0] for p in paths}) == sealed.get(g)}
                self.assertTrue(faithful, f"{tarball}: ningún grupo reproduce el hash sellado")

                now_files = {}
                for g, paths in by_group.items():
                    for p in paths:
                        data, meta = vault[p]
                        now_files[p] = integrity.state_from(p, _new_group(p, g), data,
                                                            {"mode": meta.get("mode"), "uid": 0, "gid": 0})
                legacy_now = {g: baseline.legacy_group_hash(g, {p: vault[p][0] for p in paths})
                              for g, paths in by_group.items()}

                integrity.legacy_groups = lambda: {g: list(ps) for g, ps in by_group.items()}
                integrity.groups = lambda: {g: [p for p in now_files if now_files[p]["g"] == g]
                                            for g in {s["g"] for s in now_files.values()}}

                adopted, changed, newly = integrity.migrate(
                    sealed, now_files, legacy_now, vault=vault, legacy_hash=baseline.legacy_group_hash)

                # ningún grupo FIEL puede salir como cambiado (eso sería una falsa alarma)
                for g in faithful:
                    self.assertNotIn(g, changed, f"{tarball}: grupo fiel {g} marcado como cambiado (falsa alarma)")

                # los ficheros de los grupos fieles se adoptan
                for g, paths in faithful.items():
                    for p in paths:
                        self.assertIn(p, adopted, f"{tarball}: {p} ({g}) no adoptado")

                # drift sobre lo adoptado, con el mismo contenido, no inventa hallazgos
                found, _ = integrity.drift(adopted, {p: now_files[p] for p in adopted})
                noisy = [f for f in found if f["sev"] in ("crit", "high", "med")]
                self.assertEqual(noisy, [], f"{tarball}: drift tras migrar inventó {[f['detail'][:50] for f in noisy]}")


if __name__ == "__main__":
    unittest.main()
