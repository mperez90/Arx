"""Arx · sandbox — análisis estático de ficheros sospechosos (¿es malicioso?).

ESTÁTICO (promesa Core, SIEMPRE): nunca ejecuta el fichero. Lee bytes y decide por
  · tipo (magic bytes / shebang), sha256, tamaño, entropía de Shannon,
  · strings imprimibles (acotadas),
  · reglas propias versionadas (estilo YARA, formato stdlib): substring / regex /
    umbral de entropía / tipo de fichero → severidad.
Veredicto: limpio | sospechoso | malicioso, con las razones (qué reglas casaron).

El análisis DINÁMICO (detonación en un entorno aislado con namespaces/seccomp, sin
docker.sock) es una promesa Pro y vivirá aparte. Aquí no se ejecuta nada JAMÁS.

Diseñado para degradar: un fichero ilegible devuelve un veredicto honesto
("desconocido"), nunca una excepción, para no romper el bucle de guardia.
"""
from __future__ import annotations

import hashlib
import math
import os
import re

MAX_READ = 5 * 1024 * 1024   # se analizan los primeros 5 MiB (entropía/strings/reglas)
_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")

# ── reglas propias versionadas (estilo YARA, formato stdlib) ──────────────────
# Cada regla: name · sev (malicioso|sospechoso) · why · un matcher:
#   substr  (needle: bytes)              · regex (pattern sobre el texto latin-1)
#   entropy (min_entropy + only_types)   · filetype (types)
# NOTA EICAR: se casa solo la FIRMA ("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"), no la
# cadena funcional completa, para que este propio fichero NO sea un EICAR detectable.
RULES_VERSION = "1"
RULES: list[dict] = [
    {"name": "eicar-test", "sev": "malicioso", "type": "substr",
     "needle": b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
     "why": "fichero de prueba EICAR (estándar antivirus)"},
    {"name": "revshell-devtcp", "sev": "malicioso", "type": "regex",
     "pattern": r"/dev/(tcp|udp)/[0-9a-zA-Z.\-]+/\d+",
     "why": "reverse shell por /dev/tcp de bash"},
    {"name": "revshell-nc-e", "sev": "malicioso", "type": "regex",
     "pattern": r"\bnc(?:at)?\b[^\n]{0,80}\s-\w*e\w*\b[^\n]{0,40}(/bin/|sh|bash)",
     "why": "netcat con -e: ejecuta un shell al conectar"},
    {"name": "revshell-python", "sev": "malicioso", "type": "regex",
     "pattern": r"socket\.socket[\s\S]{0,200}subprocess|pty\.spawn\([\"']/bin/(ba)?sh",
     "why": "reverse shell en Python (socket+subprocess o pty.spawn)"},
    {"name": "download-pipe-shell", "sev": "sospechoso", "type": "regex",
     "pattern": r"(curl|wget)\b[^\n|]{0,120}\|\s*(sudo\s+)?(ba)?sh",
     "why": "descarga tubería directa a un shell (curl|sh)"},
    {"name": "base64-pipe-shell", "sev": "sospechoso", "type": "regex",
     "pattern": r"base64\s+(--decode|-d)[^\n|]{0,80}\|\s*(ba)?sh",
     "why": "payload en base64 ejecutado por un shell"},
    {"name": "crypto-miner", "sev": "sospechoso", "type": "regex",
     "pattern": r"stratum\+tcp://|\bxmrig\b|\bminerd\b|\bcryptonight\b",
     "why": "indicadores de minero de criptomoneda"},
    {"name": "high-entropy-exec", "sev": "sospechoso", "type": "entropy",
     "min_entropy": 7.2, "only_types": {"elf", "pe"},
     "why": "ejecutable con entropía muy alta (empaquetado/cifrado)"},
]

_SEV_RANK = {"malicioso": 2, "sospechoso": 1}


def validate() -> list[str]:
    """Integridad del set de reglas (lo vigila un test). [] = todo correcto."""
    errors, seen = [], set()
    for r in RULES:
        rid = r.get("name")
        if not rid or rid in seen:
            errors.append(f"regla sin nombre o duplicada: {rid}")
        seen.add(rid)
        if r.get("sev") not in _SEV_RANK:
            errors.append(f"{rid}: severidad inválida {r.get('sev')}")
        t = r.get("type")
        if t == "substr" and not isinstance(r.get("needle"), bytes):
            errors.append(f"{rid}: substr necesita 'needle' en bytes")
        elif t == "regex":
            try:
                re.compile(r["pattern"])
            except (re.error, KeyError):
                errors.append(f"{rid}: regex inválida")
        elif t == "entropy" and not isinstance(r.get("min_entropy"), (int, float)):
            errors.append(f"{rid}: entropy necesita 'min_entropy' numérico")
        elif t not in ("substr", "regex", "entropy", "filetype"):
            errors.append(f"{rid}: tipo de matcher desconocido {t}")
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
        return "vacío"
    sample = data[:4096]
    printable = sum(1 for b in sample if 0x20 <= b <= 0x7e or b in (9, 10, 13))
    return "texto" if printable / len(sample) > 0.85 else "datos"


def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon (0..8 bits/byte). Alta = empaquetado/cifrado/comprimido."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
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
    if any(h["sev"] == "malicioso" for h in hits):
        return "malicioso"
    if any(h["sev"] == "sospechoso" for h in hits):
        return "sospechoso"
    return "limpio"


def analyze(path: str) -> dict:
    """Análisis estático de un fichero. Nunca lo ejecuta. Degrada con honestidad."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
        size = os.path.getsize(path)
    except OSError as e:
        return {"path": path, "ok": False, "verdict": "desconocido",
                "reasons": [f"ilegible: {e}"], "rules_version": RULES_VERSION}
    ftype = file_type(data)
    entropy = shannon_entropy(data)
    text = data.decode("latin-1", "replace")  # 1 byte ↔ 1 char: regex/substr sobre binario también
    hits = _rule_hits(data, text, ftype, entropy)
    return {
        "path": path, "ok": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": size, "truncated": size > MAX_READ,
        "type": ftype, "shebang": _shebang(data), "entropy": entropy,
        "strings": extract_strings(data),
        "hits": hits, "reasons": [h["why"] for h in hits],
        "verdict": _verdict(hits), "rules_version": RULES_VERSION,
    }


def enrich_finding(finding: dict) -> dict:
    """Si el hallazgo apunta a un ejecutable en disco, le adjunta el veredicto estático.

    El "estático siempre" del plan: cuando `guard` ve un ejecutable nuevo (p. ej. un
    dropper en /tmp), Arx no solo lo suspende — dice QUÉ es. No mete ruido si el fichero
    sale limpio; un veredicto malicioso sube la severidad (sin tocar kind/tier).
    """
    if finding.get("kind") not in ("executables", "processes"):
        return finding
    exe = str((finding.get("target") or {}).get("exe") or "")
    if not exe.startswith("/") or not os.path.exists(exe):
        return finding
    rep = analyze(exe)
    if not rep.get("ok") or rep["verdict"] == "limpio":
        return finding
    f = dict(finding)
    tag = ", ".join(h["rule"] for h in rep["hits"][:3])
    f["detail"] = f"{finding.get('detail', '')} · sandbox: {rep['verdict']} ({tag})"
    f["why"] = f"{finding.get('why', '')} · análisis estático: {rep['verdict']}"
    f["sandbox"] = rep
    if rep["verdict"] == "malicioso":
        f["sev"] = "high"
    return f


# ── salida de consola (arx scan <fichero>) ────────────────────────────────────
_COLOR = {"malicioso": "91;1", "sospechoso": "93", "limpio": "92", "desconocido": "90"}


def _c(text: str, verdict: str) -> str:
    import sys
    if sys.stdout.isatty() and verdict in _COLOR:
        return f"\033[{_COLOR[verdict]}m{text}\033[0m"
    return text


def render(rep: dict) -> None:
    print(f"\n▸ Análisis estático · {rep['path']}")
    if not rep.get("ok"):
        print(f"  {'; '.join(rep.get('reasons', ['ilegible']))}")
        return
    print(f"  tipo       {rep['type']}" + (f"  · shebang: {rep['shebang']}" if rep.get("shebang") else ""))
    print(f"  sha256     {rep['sha256']}")
    print(f"  tamaño     {rep['size']} B" + ("  (truncado para el análisis)" if rep["truncated"] else ""))
    print(f"  entropía   {rep['entropy']} bits/byte")
    print(f"  veredicto  {_c(rep['verdict'].upper(), rep['verdict'])}")
    if rep["hits"]:
        print("  reglas que casaron:")
        for h in rep["hits"]:
            print(f"    [{h['sev']}] {h['rule']} — {h['why']}")
    else:
        print("  (ninguna regla casó; sin indicadores estáticos de malware)")
    print()


def run(path: str) -> int:
    """`arx scan <fichero>`: 0 si limpio, 1 si sospechoso/malicioso/desconocido."""
    rep = analyze(path)
    render(rep)
    return 0 if rep.get("verdict") == "limpio" else 1
