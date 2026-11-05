"""Arx · sandbox — análisis estático de ficheros sospechosos (¿es malicioso?).

ESTÁTICO (promesa Core, SIEMPRE): nunca ejecuta el fichero. Lee bytes y decide por
  · tipo (magic bytes / shebang), sha256, tamaño, entropía de Shannon,
  · strings imprimibles (acotadas),
  · reglas propias versionadas (estilo YARA, formato stdlib): substring / regex /
    umbral de entropía / tipo de fichero → severidad.
Veredicto: limpio | sospechoso | malicioso, con las razones (qué reglas casaron).

El análisis DINÁMICO (detonación en un entorno aislado con namespaces/seccomp, sin
docker.sock) es una promesa Pro y vivirá aparte. Aquí no se ejecuta nada JAMÁS.

Corre sobre ficheros que controla el atacante, DENTRO del bucle de guardia: nunca puede
colgarse ni tumbar a Arx. Por eso solo abre ficheros regulares (un FIFO bloquearía la
lectura para siempre), todas las regex tienen cuantificadores acotados y hay un presupuesto
de tiempo real. Lo que no se puede analizar se dice ("unknown"), nunca es "clean".
"""
from __future__ import annotations

import collections
import contextlib
import hashlib
import math
import os
import re
import signal
import stat
import threading

from arx.i18n import tr
from arx.redact import printable

MAX_READ = 5 * 1024 * 1024   # primeros 5 MiB: tipo, entropía, strings y reglas
TAIL_READ = 1024 * 1024      # último MiB: un payload tras un relleno también se ve
SCAN_BUDGET_S = 60.0         # `arx scan`: el operador está mirando
ENRICH_BUDGET_S = 2.0        # dentro del bucle de guardia: la capa rápida no espera
_SHELL = r"(?:/(?:usr/)?bin/)?(?:ba|z|da)?sh\b"
_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")

# ── reglas propias versionadas (estilo YARA, formato stdlib) ──────────────────
# Cada regla: name · sev (malicioso|sospechoso) · why · un matcher:
#   substr  (needle: bytes)              · regex (pattern sobre el texto latin-1)
#   entropy (min_entropy + only_types)   · filetype (types)
# NOTA EICAR: se casa solo la FIRMA, no la cadena funcional completa, y partida en dos para
# que este propio fichero no se marque a sí mismo.
RULES_VERSION = "2"
RULES: list[dict] = [
    {"name": "eicar-test", "sev": "malicious", "type": "substr",
     "needle": b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE",  # partida: este fichero no se autodelata
     "why": tr("EICAR test file (antivirus standard)")},
    {"name": "revshell-devtcp", "sev": "malicious", "type": "regex",
     "pattern": r"/dev/(?:tcp|udp)/[\w.${}\-]{1,64}/[\w${}\-]{1,16}",
     "why": tr("reverse shell via bash /dev/tcp")},
    {"name": "revshell-nc-exec", "sev": "malicious", "type": "regex",
     "pattern": r"\bn(?:et)?c(?:at)?\b[^\n]{0,80}?\s(?:-\w{0,8}[ec]\w{0,8}|--(?:sh-)?exec)\b"
                r"[^\n]{0,40}?(?:/bin/|\b(?:ba)?sh\b)",
     "why": tr("netcat that runs a shell on connect")},
    {"name": "revshell-fifo", "sev": "malicious", "type": "regex",
     "pattern": r"mkfifo\b[^\n]{0,200}?\|\s{0,4}(?:nc|ncat|netcat|telnet)\b",
     "why": tr("reverse shell with FIFO and netcat")},
    {"name": "revshell-python", "sev": "malicious", "type": "regex",
     "pattern": r"socket\.socket[\s\S]{0,300}?(?:os\.dup2|subprocess\.\w{1,12}\([^\n]{0,40}(?:/bin/|\bsh\b))"
                r"|pty\.spawn\(\s{0,4}[\"'](?:/bin/)?(?:ba|z|da)?sh",
     "why": tr("Python reverse shell (socket with dup2 or a shell, or pty.spawn)")},
    {"name": "revshell-perl", "sev": "malicious", "type": "regex",
     "pattern": r"use\s{1,4}Socket\b[\s\S]{0,300}?exec\s{0,4}\(?\s{0,4}[\"'](?:/bin/)?(?:ba|z|da)?sh",
     "why": tr("Perl reverse shell (socket with exec of a shell)")},
    {"name": "revshell-php", "sev": "malicious", "type": "regex",
     "pattern": r"fsockopen\s{0,4}\([\s\S]{0,200}?(?:exec|shell_exec|system|passthru|proc_open)"
                r"\s{0,4}\(\s{0,4}[\"'](?:/bin/)?(?:ba|z|da)?sh",
     "why": tr("PHP reverse shell (fsockopen running a shell)")},
    {"name": "download-pipe-shell", "sev": "suspicious", "type": "regex",
     "pattern": r"(?:curl|wget)\b[^\n|]{0,120}\|\s{0,4}(?:sudo\s{1,4})?" + _SHELL,
     "why": tr("download piped straight into a shell (curl|sh)")},
    {"name": "base64-pipe-shell", "sev": "suspicious", "type": "regex",
     "pattern": r"base64\s{1,4}(?:--decode|-d\w{0,2})\b[^\n|]{0,80}\|\s{0,4}" + _SHELL,
     "why": tr("base64 payload run by a shell")},
    {"name": "crypto-miner", "sev": "suspicious", "type": "regex",
     "pattern": r"stratum\+tcp://|\bxmrig\b|\bminerd\b|\bcryptonight\b",
     "why": tr("cryptocurrency miner indicators")},
    {"name": "high-entropy-exec", "sev": "suspicious", "type": "entropy",
     "min_entropy": 7.2, "only_types": {"elf", "pe"},
     "why": tr("executable with very high entropy (packed/encrypted)")},
]

_SEV_RANK = {"malicious": 2, "suspicious": 1}


def validate() -> list[str]:
    """Integridad del set de reglas (lo vigila un test). [] = todo correcto."""
    errors, seen = [], set()
    for r in RULES:
        rid = r.get("name")
        if not rid or rid in seen:
            errors.append(tr("unnamed or duplicate rule: {rid}", rid=rid))
        seen.add(rid)
        if r.get("sev") not in _SEV_RANK:
            errors.append(tr("{rid}: invalid severity {sev}", rid=rid, sev=r.get('sev')))
        t = r.get("type")
        if t == "substr" and not isinstance(r.get("needle"), bytes):
            errors.append(tr("{rid}: substr needs 'needle' as bytes", rid=rid))
        elif t == "regex":
            try:
                re.compile(r["pattern"])
            except (re.error, KeyError):
                errors.append(tr("{rid}: invalid regex", rid=rid))
        elif t == "entropy" and not isinstance(r.get("min_entropy"), (int, float)):
            errors.append(tr("{rid}: entropy needs a numeric 'min_entropy'", rid=rid))
        elif t not in ("substr", "regex", "entropy", "filetype"):
            errors.append(tr("{rid}: unknown matcher type {t}", rid=rid, t=t))
    return errors


# ── primitivas de análisis (sin ejecutar nada) ───────────────────────────────
def file_type(data: bytes) -> str:
    """Tipo por magic bytes / shebang. Nunca ejecuta ni confía en la extensión."""
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    if data[:2] == b"#!":
        return "script"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if not data:
        return tr("empty")
    sample = data[:4096]
    printable = sum(1 for b in sample if 0x20 <= b <= 0x7e or b in (9, 10, 13))
    return tr("text") if printable / len(sample) > 0.85 else tr("data")


def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon (0..8 bits/byte). Alta = empaquetado/cifrado/comprimido."""
    if not data:
        return 0.0
    n = len(data)
    ent = 0.0
    for c in collections.Counter(data).values():  # Counter sobre bytes: bucle en C
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 3)


def extract_strings(data: bytes, limit: int = 40) -> list[str]:
    """Secuencias imprimibles (≥4) — acotadas: una muestra, no un volcado."""
    out = []
    for m in _STRING_RE.finditer(data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= limit:
            break
    return out


def _shebang(data: bytes) -> str | None:
    if data[:2] != b"#!":
        return None
    return data[:data.find(b"\n") if b"\n" in data[:256] else 256].decode("latin-1", "replace")[2:].strip()


def _rule_hits(data: bytes, text: str, ftype: str, entropy: float) -> list[dict]:
    hits = []
    for r in RULES:
        t = r["type"]
        ok = False
        if t == "substr":
            ok = r["needle"] in data
        elif t == "regex":
            ok = re.search(r["pattern"], text, re.IGNORECASE) is not None
        elif t == "entropy":
            ok = ftype in r["only_types"] and entropy >= r["min_entropy"]
        elif t == "filetype":
            ok = ftype in r["types"]
        if ok:
            hits.append({"rule": r["name"], "sev": r["sev"], "why": r["why"]})
    return hits


def _verdict(hits: list[dict]) -> str:
    if any(h["sev"] == "malicious" for h in hits):
        return "malicious"
    if any(h["sev"] == "suspicious" for h in hits):
        return "suspicious"
    return "clean"


class _BudgetExceeded(Exception):
    pass


@contextlib.contextmanager
def _time_budget(seconds: float):
    """Límite de tiempo real, también dentro de una regex: el motor de `re` atiende señales."""
    if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _expired(*_):
        raise _BudgetExceeded
    previous = signal.signal(signal.SIGALRM, _expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _unknown(path: str, reason: str) -> dict:
    return {"path": path, "ok": False, "verdict": "unknown", "reasons": [reason],
            "rules_version": RULES_VERSION}


def _analyze(path: str) -> dict:
    # O_NONBLOCK + fstat sobre el MISMO descriptor: un FIFO no bloquea y no hay carrera
    # entre comprobar el tipo y leerlo.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            return _unknown(path, tr("not a regular file: not read"))
        head = f.read(MAX_READ)
        digest = hashlib.sha256(head)
        tail, total = b"", len(head)
        while chunk := f.read(1024 * 1024):  # el hash es del fichero ENTERO, no de la muestra
            digest.update(chunk)
            total += len(chunk)
            tail = (tail + chunk)[-TAIL_READ:]
    data = head + b"\n" + tail if tail else head
    ftype = file_type(head)
    entropy = shannon_entropy(head)
    text = data.decode("latin-1")  # 1 byte ↔ 1 char: regex/substr sobre binario también
    hits = _rule_hits(data, text, ftype, entropy)
    try:
        from arx.modules import vaccines  # perezoso: vaccines importa este módulo
        hits += vaccines.static_hits(text, digest.hexdigest())
    except Exception:  # una vacuna rota no puede dejar a Arx sin análisis
        pass
    partial = total > len(head) + len(tail)
    verdict = _verdict(hits)
    reasons = [h["why"] for h in hits]
    if partial and verdict == "clean":  # lo no analizado no se puede declarar limpio
        verdict = "unknown"
        reasons = [tr("no indicators, but only {v} of {total} B were analyzed",
                      v=len(head) + len(tail), total=total)]
    return {
        "path": path, "ok": True, "sha256": digest.hexdigest(),
        "size": total, "truncated": partial,
        "type": ftype, "shebang": _shebang(head), "entropy": entropy,
        "strings": extract_strings(data),
        "hits": hits, "reasons": reasons, "verdict": verdict, "rules_version": RULES_VERSION,
    }


def analyze(path: str, budget: float = SCAN_BUDGET_S) -> dict:
    """Análisis estático de un fichero. Nunca lo ejecuta. Degrada con honestidad."""
    try:
        with _time_budget(budget):
            return _analyze(path)
    except OSError as e:
        return _unknown(path, tr("unreadable: {e}", e=e))
    except _BudgetExceeded:
        why = tr("the analysis ran out of its {budget:g} s budget (possible trap file)",
                 budget=budget)
        return {"path": path, "ok": True, "sha256": None, "size": None, "truncated": True,
                "type": tr("unknown"), "shebang": None, "entropy": None, "strings": [],
                "hits": [{"rule": "analysis-budget", "sev": "suspicious", "why": why}],
                "reasons": [why], "verdict": "suspicious", "rules_version": RULES_VERSION}


_CACHE: dict[tuple, dict] = {}  # el hallazgo se repite cada barrido: no re-analizar lo igual


def _analyze_cached(exe: str) -> dict:
    st = os.stat(exe)
    key = (exe, st.st_ino, st.st_size, st.st_mtime_ns, RULES_VERSION)
    if key not in _CACHE:
        if len(_CACHE) >= 256:
            _CACHE.clear()
        _CACHE[key] = analyze(exe, budget=ENRICH_BUDGET_S)
    return _CACHE[key]


def enrich_finding(finding: dict) -> dict:
    """Si el hallazgo apunta a un ejecutable en disco, le adjunta el veredicto estático.

    El "estático siempre" del plan: cuando `guard` ve un ejecutable nuevo (p. ej. un
    dropper en /tmp), Arx no solo lo suspende — dice QUÉ es. No mete ruido si el fichero
    sale limpio. Un veredicto malicioso sube la severidad, y eso habilita suspenderlo aunque
    esté en un directorio de sistema. La huella NO cambia con el veredicto: cambiar el
    contenido del fichero no debe convertirlo en una amenaza "nueva".
    """
    if finding.get("kind") not in ("executables", "processes"):
        return finding
    exe = str((finding.get("target") or {}).get("exe") or "")
    if not exe.startswith("/"):
        return finding
    try:
        rep = _analyze_cached(exe)
    except OSError:
        return finding  # ya no está en disco (p. ej. se borró a sí mismo)
    if rep["verdict"] not in ("malicious", "suspicious"):
        return finding
    f = dict(finding)
    tag = ", ".join(h["rule"] for h in rep["hits"][:3])
    f["fp_key"] = finding.get("fp_key") or f"{finding.get('kind', '')}|{finding.get('detail', '')}"
    f["detail"] = f"{finding.get('detail', '')} · sandbox: {tr(rep['verdict'])} ({tag})"
    f["why"] = tr("{why} · static analysis: {verdict}",
                  why=finding.get('why', ''), verdict=tr(rep['verdict']))
    f["sandbox"] = {k: v for k, v in rep.items() if k != "strings"}  # sale a la consola de flota
    if rep["verdict"] == "malicious":
        f["sev"] = "high"
    vaccine = next((h["vaccine"] for h in rep["hits"] if h.get("vaccine")), None)
    if vaccine:  # si el operador lo desmiente, cuenta contra esa vacuna
        f["vaccine"] = vaccine
    return f


# ── salida de consola (arx scan <fichero>) ────────────────────────────────────
_COLOR = {"malicious": "91;1", "suspicious": "93", "clean": "92", "unknown": "90"}


def _c(text: str, verdict: str) -> str:
    import sys
    if sys.stdout.isatty() and verdict in _COLOR:
        return f"\033[{_COLOR[verdict]}m{text}\033[0m"
    return text


def render(rep: dict) -> None:
    print(tr("\n▸ Static analysis · {v}", v=printable(rep['path'])))
    if not rep.get("ok"):
        print(f"  {'; '.join(rep.get('reasons', ['ilegible']))}")
        return
    shebang = f"  · shebang: {printable(rep['shebang'])}" if rep.get("shebang") else ""
    print(tr("  type       {type}{shebang}", type=rep['type'], shebang=shebang))
    print(f"  sha256     {rep['sha256'] or tr('not computed')}")
    print(tr("  size       {v} B", v=rep['size'] if rep['size'] is not None else '?')
          + (tr("  (partial analysis)") if rep["truncated"] else ""))
    print(tr("  entropy    {entropy} bits/byte", entropy=rep['entropy']))
    print(tr("  verdict    {v}", v=_c(tr(rep['verdict']).upper(), rep['verdict'])))
    if rep["verdict"] == "unknown":
        print(f"  {'; '.join(rep['reasons'])}")
    elif rep["hits"]:
        print(tr("  matched rules:"))
        for h in rep["hits"]:
            print(f"    [{tr(h['sev'])}] {h['rule']} — {h['why']}")
    else:
        print(tr("  (no rule matched; no static malware indicators)"))
    print()


def run(path: str) -> int:
    """`arx scan <fichero>`: 0 si limpio, 1 si sospechoso/malicioso/desconocido."""
    rep = analyze(path)
    render(rep)
    return 0 if rep.get("verdict") == "clean" else 1
