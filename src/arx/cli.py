#!/usr/bin/env python3
"""Arx — punto de entrada de consola (v0.01, sin UI).

Ciclo de arranque:  install → setup → recon → learn → guard

    arx setup    Wizard (lado usuario): proveedores LLM + orden de fallback
                 (OpenAI→Anthropic→KIMI), palabra de autorización (solo hash),
                 alcance / fuera-de-límites, licencia, ventana de baseline.
    arx recon    Reconocimiento inicial profundo: hardware, SO, paquetes,
                 servicios/puertos, usuarios/sudo/SUID/cron, contenedores, red y
                 alcance. Produce inventario + superficie + plan de defensa a medida.
    arx learn    Ventana de baseline: aprende "lo normal" de TODO (software,
                 hardware, red, usuarios, horarios). Conservador (aprender > bloquear)
                 y con chequeo de integridad de arranque (no aprender a un atacante
                 como normal).
    arx guard    Operativo 24/7: sensores + canarios + respuesta por niveles
                 (Tier 0/1 auto reversible · Tier 2 humano). Detección = firmas
                 (ATT&CK/CVE) + anomalía sobre la base. Chat por consola.

Motor de razonamiento: núcleo hermes-agent (MIT · Nous Research) — ver NOTICE.
"""
from __future__ import annotations

import argparse

from arx import __version__


def cmd_setup(args: argparse.Namespace) -> int:
    from arx.modules import setup
    return setup.run(show_only=args.show)


def cmd_recon(args: argparse.Namespace) -> int:
    from arx.modules import recon  # import perezoso: no cargar colectores en otros comandos
    return recon.run(json_path=args.json_path, save=not args.no_save)


def cmd_learn(args: argparse.Namespace) -> int:
    from arx.modules import baseline
    return baseline.run(samples=args.samples, interval=args.interval,
                        seal=args.seal, status=args.status)


def cmd_guard(args: argparse.Namespace) -> int:
    from arx.modules import guard
    return guard.run(once=args.once, interval=args.interval, chat=args.chat, enforce=args.enforce)


def cmd_canaries(args: argparse.Namespace) -> int:
    from arx.modules import canaries
    return canaries.run(args.caction, locations=getattr(args, "in_dirs", None))


def cmd_service(args: argparse.Namespace) -> int:
    from arx.modules import service
    return service.run(args.saction, exec_start=getattr(args, "exec_path", None))


def cmd_status(args: argparse.Namespace) -> int:
    import json
    import subprocess

    from arx import config
    from arx import license as lic
    from arx.modules import baseline, canaries, response, service

    cfg = config.load_config()
    print("\n▸ Arx — estado")
    print(f"  configurado    {'sí' if cfg else 'no  (arx setup)'}")
    if cfg:
        print(f"  proveedores    {', '.join(cfg.get('providers', {})) or 'ninguno'}")
        print(f"  palabra auth   {'configurada' if cfg.get('auth_word') else 'NO'}")
    base = baseline.load()
    if not base:
        print("  baseline       no existe  (arx learn)")
    else:
        m = base["meta"]
        estado = "sellada" if m.get("sealed") else "aprendiendo"
        print(f"  baseline       {estado} ({m.get('samples', 0)} muestras)")
    tier, why = lic.effective_tier()
    print(f"  licencia       {tier}  ({why})")
    if service._systemd_available():
        r = subprocess.run(["systemctl", "is-active", "arx"], capture_output=True, text=True)
        print(f"  servicio       {r.stdout.strip() or 'inactivo'}")
    else:
        print("  servicio       (systemd no disponible aquí)")
    cs = canaries._load().get("canaries", [])
    print(f"  canarios       {len(cs)} activos, {len(canaries.check())} disparados")
    print(f"  bloqueos T1    {len(response._load_blocks())} activos")
    pend = response.list_pending()
    print(f"  Tier 2 pend.   {len(pend)}" + ("   ⚠ usa: arx authorize" if pend else ""))
    inc = config.state_dir() / "incidents.jsonl"
    try:
        lines = inc.read_text().splitlines()[-5:]
    except OSError:
        lines = []
    if lines:
        print("  incidentes recientes:")
        for line in lines:
            try:
                e = json.loads(line)
                print(f"    {e.get('at', '')[:19]}  {e.get('detail') or e.get('kind')}")
            except ValueError:
                pass
    print()
    return 0


def cmd_authorize(args: argparse.Namespace) -> int:
    import getpass

    from arx import config
    from arx.modules import response

    pend = response.list_pending()
    if args.pending_id is None:
        if not pend:
            print("No hay acciones Tier 2 pendientes.")
            return 0
        print("Acciones Tier 2 pendientes (requieren tu palabra de autorización):")
        for p in pend:
            print(f"  {p['id']}  [{p['sev']}] {p['detail']}")
            print(f"          → {p['remediation']}")
        print("\nAutoriza una con:  arx authorize <id>")
        return 0
    item = next((p for p in pend if p["id"] == args.pending_id), None)
    if item is None:
        print(f"No hay ninguna acción pendiente con id '{args.pending_id}'.")
        return 1
    cfg = config.load_config()
    if not cfg.get("auth_word"):
        print("No hay palabra de autorización configurada. Ejecuta:  arx setup")
        return 1
    word = getpass.getpass("Palabra de autorización: ").strip()
    if not config.verify_word(word, cfg.get("auth_word", {})):
        print("Palabra incorrecta. Acción NO autorizada.")
        return 1
    response.authorize_pending(args.pending_id)
    print(f"✓ Autorizada: {item['detail']}")
    print(f"  Remediación: {item['remediation']}")
    print("  Arx aplica lo reversible; lo irreversible confírmalo tú en el host.")
    return 0


def cmd_license(args: argparse.Namespace) -> int:
    import platform
    import socket

    from arx import config
    from arx import license as lic

    if args.laction == "activate":
        res = lic.activate(args.key, socket.gethostname(), platform.platform(), __version__)
        if not res.get("ok"):
            print("No se pudo activar:", res.get("reason", "error desconocido"))
            return 1
        lic.validate()  # primera validación → puebla la caché y el tier
        tier, why = lic.effective_tier()
        print(f"✓ Licencia activada en este servidor. Tier: {tier} ({why})")
        return 0

    if args.laction == "deactivate":
        lic.deactivate()
        print("Activación local liberada. Puedes reinstalar este servidor y reactivar con la misma llave.")
        return 0

    # status
    st = lic.load()
    if not st.get("key"):
        print("Sin licencia — Arx opera en Core (gratis). Actívala con:  arx license activate <LLAVE>")
        return 0
    tier, why = lic.effective_tier()
    cache = st.get("cache", {})
    print("\n▸ Licencia de Arx")
    print(f"  llave           {config.redact(st['key'])}")
    print(f"  activada        {'sí' if st.get('activation_id') else 'no'}")
    print(f"  tier efectivo   {tier}  ({why})")
    if cache.get("expires_at"):
        print(f"  expira          {cache['expires_at']}")
    if cache.get("last_validated_at"):
        print(f"  últ. validación {cache['last_validated_at']}")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="arx", description="Arx — defensa activa y reactiva")
    p.add_argument("--version", action="version", version=f"Arx {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    p_setup = sub.add_parser("setup", help="wizard de configuración (lado usuario)")
    p_setup.add_argument("--show", action="store_true",
                         help="mostrar la configuración actual (secretos redactados)")
    p_recon = sub.add_parser("recon", help="reconocimiento inicial profundo del sistema")
    p_recon.add_argument("--json", dest="json_path", metavar="RUTA",
                         help="ruta del inventario JSON (por defecto: dir de estado de Arx)")
    p_recon.add_argument("--no-save", action="store_true",
                         help="solo mostrar en consola, no escribir el JSON")
    p_learn = sub.add_parser("learn", help="ventana de aprendizaje de la línea base")
    p_learn.add_argument("--samples", type=int, default=1, help="nº de instantáneas a integrar en esta corrida")
    p_learn.add_argument("--interval", type=int, default=0, help="segundos entre instantáneas")
    p_learn.add_argument("--seal", action="store_true", help="sellar la base (fin del aprendizaje)")
    p_learn.add_argument("--status", action="store_true", help="mostrar el estado de la base aprendida")
    p_guard = sub.add_parser("guard", help="modo operativo: vigila, detecta, responde")
    p_guard.add_argument("--once", action="store_true", help="un solo barrido y salir (cron/pruebas)")
    p_guard.add_argument("--interval", type=int, default=30, help="segundos entre barridos")
    p_guard.add_argument("--chat", action="store_true", help="abrir canal de consola con Arx")
    p_guard.add_argument("--enforce", action="store_true", help="aplicar remediaciones Tier 1 (auto, reversibles)")
    sub.add_parser("status", help="estado general de Arx (un vistazo)")
    p_auth = sub.add_parser("authorize", help="ver/aprobar acciones Tier 2 pendientes")
    p_auth.add_argument("pending_id", nargs="?", help="id a autorizar (sin id: lista los pendientes)")
    p_can = sub.add_parser("canaries", help="señuelos / honeytokens")
    csub = p_can.add_subparsers(dest="caction", required=True)
    p_cp = csub.add_parser("plant", help="plantar señuelos (por defecto: homes + /root)")
    p_cp.add_argument("--in", dest="in_dirs", action="append", metavar="DIR",
                      help="dónde plantar (repetible)")
    csub.add_parser("list", help="listar señuelos activos")
    csub.add_parser("check", help="verificar integridad de los señuelos")
    p_svc = sub.add_parser("service", help="instalar/retirar Arx como servicio systemd (24/7)")
    ssub = p_svc.add_subparsers(dest="saction", required=True)
    p_si = ssub.add_parser("install", help="instalar y arrancar el servicio")
    p_si.add_argument("--exec", dest="exec_path", metavar="RUTA",
                      help="ExecStart (por defecto: cómo se invoca arx ahora)")
    ssub.add_parser("uninstall", help="retirar el servicio")
    ssub.add_parser("status", help="estado del servicio")
    p_lic = sub.add_parser("license", help="activar / ver / liberar la licencia")
    lsub = p_lic.add_subparsers(dest="laction", required=True)
    p_la = lsub.add_parser("activate", help="activar una licencia Pro/Business en este servidor")
    p_la.add_argument("key", help="la llave que compraste (Polar)")
    lsub.add_parser("status", help="ver estado y tier efectivo")
    lsub.add_parser("deactivate", help="liberar la activación local (al reinstalar el servidor)")
    args = p.parse_args(argv)
    handlers = {"setup": cmd_setup, "recon": cmd_recon, "learn": cmd_learn,
                "guard": cmd_guard, "status": cmd_status, "authorize": cmd_authorize,
                "canaries": cmd_canaries, "service": cmd_service, "license": cmd_license}
    return handlers[args.cmd](args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
