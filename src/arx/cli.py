#!/usr/bin/env python3
"""Arx — punto de entrada de consola (sin UI).

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
                 (Tier 0/1 auto reversible · Tier 2 humano). Detección = anomalía
                 sobre la base + integridad + señuelos + sensores. El motor LLM solo
                 se consulta ante hallazgos nuevos. Chat por consola.
    arx accept   Incorporar a la base un cambio legítimo que Arx marcó como anómalo.
"""
from __future__ import annotations

import argparse

from arx import __version__
from arx.i18n import tr


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
    return guard.run(once=args.once, interval=args.interval, chat=args.chat, enforce=args.enforce,
                     verbose=args.verbose)


def cmd_canaries(args: argparse.Namespace) -> int:
    from arx.modules import canaries
    return canaries.run(args.caction, locations=getattr(args, "in_dirs", None))


def cmd_scan(args: argparse.Namespace) -> int:
    from arx.modules import sandbox  # análisis estático: nunca ejecuta el fichero
    return sandbox.run(args.path)


def cmd_forensics(args: argparse.Namespace) -> int:
    from arx.modules import forensics
    if args.indicators:
        return forensics.print_indicators(since=args.since)
    return forensics.run(verify_path=args.verify, since=args.since)


def cmd_service(args: argparse.Namespace) -> int:
    from arx.modules import service
    return service.run(args.saction, exec_start=getattr(args, "exec_path", None),
                       enforce=getattr(args, "enforce", False))


def cmd_accept(args: argparse.Namespace) -> int:
    from arx.modules import response

    st = response.load_findings()
    if args.fp is None:
        open_ = [(fp, e) for fp, e in st.items() if e.get("set")]
        if not open_:
            print(tr("No baseline findings waiting to be accepted."))
            return 0
        print(tr("Findings you can accept as normal (they are added to the baseline):"))
        for fp, e in sorted(open_, key=lambda x: x[1].get("last_seen", ""), reverse=True)[:30]:
            print(tr("  {fp}  {detail}   (seen {seen}×, last {v})",
                     fp=fp, detail=e.get('detail'), seen=e.get('seen'), v=e.get('last_seen', '')[:16]))
        print(tr("\nAccept one with:  arx accept <id>"))
        return 0
    msg = response.accept(args.fp)
    if msg is None:
        print(tr("No acceptable finding with id '{fp}'. List them:  arx accept", fp=args.fp))
        return 1
    print(msg)
    return 0 if msg.startswith("✓") else 1


def cmd_notify(args: argparse.Namespace) -> int:
    from arx import notify

    chans = notify.channels()
    if not chans:
        print(tr("No alert channels configured. Run:  arx setup  (step 6)"))
        return 1
    res = notify.send(tr("Alert test: if you can read this, Arx can reach you. ✓"))
    for ch, r in res.items():
        print(f"  {ch:<9} {r}")
    return 0 if all(r == "ok" for r in res.values()) else 1


def _status_data() -> dict:
    """Lo mismo que `arx status`, para quien quiera construir algo encima (sin UI propia)."""
    import subprocess

    from arx import config, notify
    from arx import license as lic
    from arx.modules import baseline, canaries, guard, proposals, response, service, vaccines

    cfg = config.load_config()
    base = baseline.load()
    tier, why = lic.effective_tier()
    svc = None
    if service._systemd_available():
        svc = subprocess.run(["systemctl", "is-active", "arx"], capture_output=True, text=True).stdout.strip()
    return {"version": __version__, "configured": bool(cfg), "license": {"tier": tier, "why": why},
            "baseline": {"sealed": bool(base and base["meta"].get("sealed")),
                         "samples": base["meta"].get("samples", 0) if base else 0},
            "service": svc, "alerts": notify.channels(cfg),
            "canaries": {"active": len(canaries._load().get("canaries", [])), "fired": len(canaries.check())},
            "blocks": len(response._load_blocks()), "breaker_tripped": response.breaker_tripped(),
            "findings": len(response.load_findings()), "enforce": guard.mode_seen(),
            "vaccines": len(vaccines._load().get("applied") or {}), "proposals": len(proposals.all_proposals()),
            "pending": [{"id": p["id"], "sev": p.get("sev"), "detail": p.get("detail")}
                        for p in response.list_pending()],
            "locked_accounts": response.locked_accounts(), "quarantine": len(response.list_quarantine())}


def cmd_status(args: argparse.Namespace) -> int:
    import json
    import subprocess

    from arx import config
    from arx import license as lic
    from arx.modules import baseline, canaries, response, service

    if getattr(args, "json", False):
        print(json.dumps(_status_data(), ensure_ascii=False, indent=1))
        return 0
    cfg = config.load_config()
    print(tr("\n▸ Arx: status"))
    print(tr("  configured     {v}", v=tr("yes") if cfg else tr("no  (arx setup)")))
    if cfg:
        print(tr("  providers      {v}", v=', '.join(cfg.get('providers', {})) or tr("none")))
        print(tr("  auth word      {v}", v=tr("configured") if cfg.get('auth_word') else 'NO'))
    base = baseline.load()
    if not base:
        print(tr("  baseline       missing  (arx learn)"))
    else:
        m = base["meta"]
        estado = tr("sealed") if m.get("sealed") else tr("learning")
        print(tr("  baseline       {estado} ({samples} samples)",
                 estado=estado, samples=m.get('samples', 0)))
    tier, why = lic.effective_tier()
    print(tr("  license        {tier}  ({why})", tier=tier, why=why))
    if service._systemd_available():
        r = subprocess.run(["systemctl", "is-active", "arx"], capture_output=True, text=True)
        print(tr("  service        {v}", v=r.stdout.strip() or tr("inactive")))
    else:
        print(tr("  service        (systemd not available here)"))
    cs = canaries._load().get("canaries", [])
    print(tr("  canaries       {n} active, {n2} triggered", n=len(cs), n2=len(canaries.check())))
    print(tr("  T1 blocks      {n} active", n=len(response._load_blocks()))
          + (tr("   ⚠ SAFETY BRAKE active") if response.breaker_tripped() else ""))
    from arx import notify
    from arx.modules import guard, proposals, vaccines
    seen = guard.mode_seen()
    print(tr("  mode           {v}",
             v=tr("has not run yet") if seen is None else tr("protect (--enforce)") if seen else tr("observe")))
    print(tr("  alerts         {v}", v=', '.join(notify.channels(cfg)) or tr("none  (arx setup)")))
    print(tr("  vaccines       {n} applied", n=len(vaccines._load().get('applied') or {})))
    props = proposals.all_proposals()
    if props:
        print(tr("  proposals      {n}   ·  review them: arx proposals", n=len(props)))
    print(tr("  findings       {n} known  ·  accept legitimate changes: arx accept",
             n=len(response.load_findings())))
    pend = response.list_pending()
    print(tr("  Tier 2 pending {n}", n=len(pend)) + (tr("   ⚠ use: arx authorize") if pend else ""))
    locked = response.locked_accounts()
    if locked:
        print(tr("  locked accts   {v}   ⚠ your call: arx unlock",
                 v=', '.join(a['user'] for a in locked)))
    inc = config.state_dir() / "incidents.jsonl"
    try:
        lines = inc.read_text().splitlines()[-5:]
    except OSError:
        lines = []
    if lines:
        print(tr("  recent incidents:"))
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
            print(tr("No pending Tier 2 actions."))
            return 0
        print(tr("Pending Tier 2 actions (they need your authorization word):"))
        for p in pend:
            print(f"  {p['id']}  [{p['sev']}] {p['detail']}")
            print(f"          → {p['remediation']}")
        print(tr("\nAuthorize one with:  arx authorize <id>"))
        return 0
    item = next((p for p in pend if p["id"] == args.pending_id), None)
    if item is None:
        print(tr("No pending action with id '{pending_id}'.", pending_id=args.pending_id))
        return 1
    cfg = config.load_config()
    if not cfg.get("auth_word"):
        print(tr("No authorization word configured. Run:  arx setup"))
        return 1
    word = getpass.getpass(tr("Authorization word: ")).strip()
    if not config.verify_word(word, cfg.get("auth_word", {})):
        print(tr("Wrong word. Action NOT authorized."))
        return 1
    item = response.authorize_pending(args.pending_id)
    print(tr("✓ Authorized: {detail}", detail=item['detail']))
    print(tr("  Remediation: {remediation}", remediation=item['remediation']))
    print(tr("  Executed:    {executed}", executed=item.get('executed', '—')))
    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    import getpass

    from arx import config
    from arx.modules import response

    locked = response.locked_accounts()
    if args.user is None:
        if not locked:
            print(tr("No accounts locked by Arx."))
            return 0
        print(tr("Accounts locked by Arx (they do not unlock on their own):"))
        for a in locked:
            print(tr("  {user}  since {v} UTC  ·  {detail}",
                     user=a['user'], v=str(a['since'])[:16], detail=a['detail']))
        print(tr("\nUnlock one with:  arx unlock <account>"))
        return 0
    if not any(a["user"] == args.user for a in locked):
        print(tr("Arx has not locked account '{user}'.", user=args.user))
        return 1
    cfg = config.load_config()
    if not cfg.get("auth_word"):
        print(tr("No authorization word configured. Run:  arx setup"))
        return 1
    word = getpass.getpass(tr("Authorization word: ")).strip()
    if not config.verify_word(word, cfg.get("auth_word", {})):
        print(tr("Wrong word. The account stays locked."))
        return 1
    done = response.unlock_account(args.user)
    if response.revert_failed(done):
        print(tr("⚠ {done}. The account stays locked.", done=done))
        return 1
    print(tr("✓ Account '{user}' unlocked: {done}", user=args.user, done=done))
    print(tr("  If this was legitimate access, to stop further alerts:  arx accept"))
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    import getpass

    from arx import config
    from arx.modules import response
    from arx.redact import printable

    items = response.list_quarantine()
    if args.qid is None:
        if not items:
            print(tr("The quarantine is empty."))
            return 0
        print(tr("Quarantined files (evidence preserved, 0600, root only):"))
        for q in items:
            print(tr("  {v}\n      from {v2}  ·  {v3} UTC  ·  sha256 {v4}…",
                     v=printable(q['id']), v2=printable(q['origin']), v3=str(q['at'])[:16],
                     v4=str(q['sha256'])[:16]))
        print(tr("\nPut one back with:  arx restore <id>"))
        return 0
    if not any(q["id"] == args.qid for q in items):
        print(tr("Nothing in quarantine with id '{v}'.", v=printable(args.qid)))
        return 1
    cfg = config.load_config()
    if not cfg.get("auth_word"):
        print(tr("No authorization word configured. Run:  arx setup"))
        return 1
    word = getpass.getpass(tr("Authorization word: ")).strip()
    if not config.verify_word(word, cfg.get("auth_word", {})):
        print(tr("Wrong word. It stays in quarantine."))
        return 1
    done = response.restore_quarantined(args.qid)
    print(("✓ " if done and done.startswith(tr("restored")) else "⚠ ") + str(done))
    return 0 if done and done.startswith(tr("restored")) else 1


def cmd_vaccines(args: argparse.Namespace) -> int:
    from arx.modules import vaccines
    return vaccines.run(args.vaction or "list", getattr(args, "vid", None))


def cmd_proposals(args: argparse.Namespace) -> int:
    from arx.modules import proposals
    return proposals.run(args.paction or "list", getattr(args, "pid", None))


def cmd_metrics(args: argparse.Namespace) -> int:
    from arx.modules import metrics
    return metrics.run(days=args.days, as_json=args.json)


def cmd_fleet(args: argparse.Namespace) -> int:
    from arx.modules import fleet

    if args.faction == "enroll":
        r = fleet.enroll(args.console, args.token)
        if r.get("ok"):
            print(tr("✓ Host enrolled in the console. agent_id: {agent_id}", agent_id=r['agent_id']))
            return 0
        print(tr("Could not enroll: {reason}", reason=r.get('reason')))
        return 1
    if args.faction == "sync":
        r = fleet.sync()
        if r.get("ok"):
            print(tr("✓ Synced with the console ({events} incidents sent).",
                     events=r.get('events', 0)))
            return 0
        print(tr("Could not sync: {reason}", reason=r.get('reason')))
        return 1
    # status
    st = fleet._load()
    print(tr("\n▸ Arx: fleet"))
    print(tr("  available      {v}",
             v=tr("yes (Business)") if fleet.enabled() else tr("no (requires a Business license)")))
    print(tr("  enrolled       {v}", v=tr("yes") if st.get('agent_id') else 'no'))
    if st.get("agent_id"):
        print(tr("  console        {console_url}", console_url=st.get('console_url')))
        print(f"  agent_id       {st.get('agent_id')}")
    print()
    return 0


def cmd_license(args: argparse.Namespace) -> int:
    import platform
    import socket

    from arx import config
    from arx import license as lic

    if args.laction == "activate":
        res = lic.activate(args.key, socket.gethostname(), platform.platform(), __version__)
        if not res.get("ok"):
            print(tr("Could not activate:"), res.get("reason", tr("unknown error")))
            return 1
        lic.validate()  # primera validación → puebla la caché y el tier
        tier, why = lic.effective_tier()
        print(tr("✓ License activated on this server. Tier: {tier} ({why})", tier=tier, why=why))
        return 0

    if args.laction == "deactivate":
        r = lic.deactivate()
        if r.get("ok"):
            print(tr("✓ Activation released (in Polar and locally). Reinstall and reactivate with "
                     "the same key."))
            return 0
        print(f"⚠ {r.get('reason')}")
        return 1

    # status
    st = lic.load()
    if not st.get("key"):
        print(tr("No license: Arx runs as Core (free). Activate with:  arx license activate <KEY>"))
        return 0
    tier, why = lic.effective_tier()
    cache = st.get("cache", {})
    print(tr("\n▸ Arx license"))
    print(tr("  key             {v}", v=config.redact(st['key'])))
    print(tr("  activated       {v}", v=tr("yes") if st.get('activation_id') else 'no'))
    print(tr("  effective tier  {tier}  ({why})", tier=tier, why=why))
    if cache.get("expires_at"):
        print(tr("  expires         {expires_at}", expires_at=cache['expires_at']))
    if cache.get("last_validated_at"):
        print(tr("  last validated {last_validated_at}",
                 last_validated_at=cache['last_validated_at']))
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="arx", description=tr("Arx: active and reactive defense"))
    p.add_argument("--version", action="version", version=f"Arx {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    p_setup = sub.add_parser("setup", help=tr("configuration wizard (user side)"))
    p_setup.add_argument("--show", action="store_true",
                         help=tr("show the current configuration (secrets redacted)"))
    p_recon = sub.add_parser("recon", help=tr("deep initial reconnaissance of the system"))
    p_recon.add_argument("--json", dest="json_path", metavar=tr("PATH"),
                         help=tr("path of the JSON inventory (default: Arx state dir)"))
    p_recon.add_argument("--no-save", action="store_true",
                         help=tr("only print to the console, do not write the JSON"))
    p_learn = sub.add_parser("learn", help=tr("baseline learning window"))
    p_learn.add_argument("--samples", type=int, default=1, help=tr("number of snapshots to take in this "
                                                                   "run"))
    p_learn.add_argument("--interval", type=int, default=0, help=tr("seconds between snapshots"))
    p_learn.add_argument("--seal", action="store_true", help=tr("seal the baseline (end of learning)"))
    p_learn.add_argument("--status", action="store_true", help=tr("show the state of the learned baseline"))
    p_guard = sub.add_parser("guard", help=tr("operating mode: watch, detect, respond"))
    p_guard.add_argument("--once", action="store_true", help=tr("a single sweep and exit (cron/tests)"))
    p_guard.add_argument("--interval", type=int, default=30, help=tr("seconds between sweeps"))
    p_guard.add_argument("--chat", action="store_true", help=tr("open a console channel with Arx"))
    p_guard.add_argument("--enforce", action="store_true", help=tr("apply Tier 1 remediations (automatic, "
                                                                   "reversible)"))
    p_guard.add_argument("--verbose", action="store_true", help=tr("show every finding on each sweep"))
    p_scan = sub.add_parser("scan", help=tr("static analysis of a file (is it malicious?)"))
    p_scan.add_argument("path", help=tr("path of the file to analyze (it is not executed)"))
    p_for = sub.add_parser("forensics", help=tr("post-incident forensic report (sealed)"))
    p_for.add_argument("--since", help=tr("only incidents since this ISO timestamp (UTC)"))
    p_for.add_argument("--verify", help=tr("verify the seal of a saved report"))
    p_for.add_argument("--indicators", action="store_true",
                       help=tr("only public IPs, hashes and attack types, nothing about this host: "
                               "safe to share"))
    p_st = sub.add_parser("status", help=tr("overall Arx status (at a glance)"))
    p_st.add_argument("--json", action="store_true", help=tr("as JSON, for scripts"))
    p_auth = sub.add_parser("authorize", help=tr("view/approve pending Tier 2 actions"))
    p_auth.add_argument("pending_id", nargs="?", help=tr("id to authorize (no id: list pending)"))
    p_unl = sub.add_parser("unlock", help=tr("view/unlock accounts locked by Arx"))
    p_unl.add_argument("user", nargs="?", help=tr("account to unlock (no account: list locked)"))
    p_res = sub.add_parser("restore", help=tr("view/put back quarantined files"))
    p_res.add_argument("qid", nargs="?", help=tr("file id (no id: list the quarantine)"))
    p_vac = sub.add_parser("vaccines", help=tr("signed vaccines: what other Arx hosts learned"))
    vsub = p_vac.add_subparsers(dest="vaction")
    vsub.add_parser("list", help=tr("show applied and rejected vaccines"))
    vsub.add_parser("update", help=tr("check for new vaccines now"))
    p_vr = vsub.add_parser("remove", help=tr("remove a vaccine from this host"))
    p_vr.add_argument("vid", help=tr("vaccine id"))
    p_pro = sub.add_parser("proposals", help=tr("what Arx proposes you change (nothing applies on "
                                                "its own)"))
    psub = p_pro.add_subparsers(dest="paction")
    psub.add_parser("list", help=tr("show the proposals"))
    p_pa = psub.add_parser("apply", help=tr("apply a proposal (asks for your word)"))
    p_pa.add_argument("pid", help=tr("proposal id"))
    p_pr = psub.add_parser("revert", help=tr("undo an applied proposal (asks for your word)"))
    p_pr.add_argument("pid", help=tr("proposal id"))
    p_met = sub.add_parser("metrics", help=tr("how much noise Arx makes on this host (false "
                                              "positives)"))
    p_met.add_argument("--days", type=int, default=7, help=tr("days to count (default 7)"))
    p_met.add_argument("--json", action="store_true", help=tr("numbers only, no paths or names: safe "
                                                              "to share"))
    p_can = sub.add_parser("canaries", help=tr("canaries / honeytokens"))
    csub = p_can.add_subparsers(dest="caction", required=True)
    p_cp = csub.add_parser("plant", help=tr("plant canaries (default: homes + /root)"))
    p_cp.add_argument("--in", dest="in_dirs", action="append", metavar="DIR",
                      help=tr("where to plant (repeatable)"))
    csub.add_parser("list", help=tr("list active canaries"))
    csub.add_parser("check", help=tr("check canary integrity"))
    p_svc = sub.add_parser("service", help=tr("install/remove Arx as a systemd service (24/7)"))
    ssub = p_svc.add_subparsers(dest="saction", required=True)
    p_si = ssub.add_parser("install", help=tr("install and start the service"))
    p_si.add_argument("--exec", dest="exec_path", metavar=tr("PATH"),
                      help=tr("ExecStart (default: how arx is being invoked now)"))
    p_si.add_argument("--enforce", action="store_true",
                      help=tr("apply automatic Tier 1 actions (default: observe only)"))
    ssub.add_parser("uninstall", help=tr("remove the service"))
    ssub.add_parser("status", help=tr("service status"))
    ssub.add_parser("restore", help=tr("put Arx's containment back in the kernel (runs at boot)"))
    p_acc = sub.add_parser("accept", help=tr("accept a legitimate change as normal (adds it to the "
                                             "baseline)"))
    p_acc.add_argument("fp", nargs="?", help=tr("finding id (no id: list acceptable findings)"))
    p_not = sub.add_parser("notify", help=tr("outgoing alerts (Telegram / webhook)"))
    nsub = p_not.add_subparsers(dest="naction", required=True)
    nsub.add_parser("test", help=tr("send a test message through the configured channels"))
    p_fleet = sub.add_parser("fleet", help=tr("fleet / central console (Business)"))
    fsub = p_fleet.add_subparsers(dest="faction", required=True)
    p_fe = fsub.add_parser("enroll", help=tr("enroll this host in the central console"))
    p_fe.add_argument("--console", required=True, metavar="URL", help=tr("URL of the fleet console"))
    p_fe.add_argument("--token", required=True, metavar="TOKEN", help=tr("enrollment token"))
    fsub.add_parser("status", help=tr("enrollment status"))
    fsub.add_parser("sync", help=tr("send heartbeat + incidents to the console"))
    p_lic = sub.add_parser("license", help=tr("activate / view / release the license"))
    lsub = p_lic.add_subparsers(dest="laction", required=True)
    p_la = lsub.add_parser("activate", help=tr("activate a Pro/Business license on this server"))
    p_la.add_argument("key", help=tr("the key you bought (Polar)"))
    lsub.add_parser("status", help=tr("show status and effective tier"))
    lsub.add_parser("deactivate", help=tr("release the local activation (when reinstalling the "
                                          "server)"))
    # Puerta 5 de D2: el arsenal vive en un paquete privado fuera del repo Core.
    # Este gancho solo lo DESCUBRE si está instalado; no contiene nada suyo.
    try:
        from arx_arsenal import cli as _arsenal_cli
    except ImportError:
        _arsenal_cli = None
    if _arsenal_cli is not None:
        _arsenal_cli.register(sub)
    args = p.parse_args(argv)
    handlers = {"setup": cmd_setup, "recon": cmd_recon, "learn": cmd_learn,
                "guard": cmd_guard, "status": cmd_status, "authorize": cmd_authorize, "unlock": cmd_unlock,
                "restore": cmd_restore, "metrics": cmd_metrics, "vaccines": cmd_vaccines,
                "proposals": cmd_proposals,
                "canaries": cmd_canaries, "scan": cmd_scan, "forensics": cmd_forensics,
                "service": cmd_service, "fleet": cmd_fleet, "license": cmd_license,
                "accept": cmd_accept, "notify": cmd_notify}
    if args.cmd not in handlers:
        # Puerta 5 de D2: el arsenal vive en un paquete privado fuera del repo Core.
        # Este gancho solo lo DESCUBRE si está instalado; no contiene nada suyo.
        try:
            from arx_arsenal import cli as _arsenal_cli
        except ImportError:
            _arsenal_cli = None
        if _arsenal_cli is not None and _arsenal_cli.handles(args.cmd):
            return _arsenal_cli.run(args) or 0
        p.print_help()
        return 1
    return handlers[args.cmd](args) or 0


def entry() -> None:
    """Punto de entrada del zipapp: su __main__ ignora lo que devuelve la función llamada, y
    `arx` terminaría siempre en 0 (un informe alterado "pasaría" para cualquier script)."""
    raise SystemExit(main())


if __name__ == "__main__":
    entry()
