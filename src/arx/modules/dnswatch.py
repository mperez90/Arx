"""Arx · dnswatch — qué dominios consulta cada servicio (F18.3).

Una regla de nftables por servicio vigilado registra sus consultas DNS por NFLOG, con un prefijo que
dice de qué servicio son (sin tocar marcas de paquete, que otros usan para enrutar). Un hilo las lee
(netlink, biblioteca estándar) y saca el nombre consultado. Se aprende por dominio registrable
(`cloudfront.net`, no `d3x9…cloudfront.net`): un CDN que rota subdominios no es noticia; un dominio
nuevo, sí, y uno con pinta de generado por un malware (DGA), más.

No se corta la consulta: la conexión al destino nuevo ya la corta el perfil de red del servicio. Lo
que no se ve: DNS sobre HTTPS, y lo que un servicio resuelva a través de otro (nscd, sssd).
"""
from __future__ import annotations

import collections
import math
import re
import socket
import struct
import subprocess
import threading

NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET, NFULNL_MSG_CONFIG = 0, 1
NFULA_PAYLOAD, NFULA_PREFIX = 9, 10
NFULA_CFG_CMD, NFULA_CFG_MODE = 1, 2
CMD_BIND, CMD_PF_BIND, CMD_PF_UNBIND = 1, 3, 4
COPY_PACKET = 2
GROUP = 7
PREFIX = "arxdns:"
CHAIN = "dnslog"
MAX_EVENTS = 4000

_events: collections.deque = collections.deque(maxlen=MAX_EVENTS)
_state = {"running": False, "rules": None}
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9@_.:\\-]{1,200}\.service$")
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil"}


# ── el paquete DNS ───────────────────────────────────────────────────────────
def qname(packet: bytes) -> str | None:
    """El nombre de la primera pregunta de una consulta DNS (paquete IP entero, v4 o v6, sobre UDP)."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4:
        ihl = (packet[0] & 0x0F) * 4
        if len(packet) < ihl + 8 or packet[9] != 17:
            return None
        udp = ihl
    elif version == 6:
        if len(packet) < 48 or packet[6] != 17:  # sin cabeceras de extensión: lo normal para DNS
            return None
        udp = 40
    else:
        return None
    dns = packet[udp + 8:]
    if len(dns) < 13 or struct.unpack_from("!H", dns, 4)[0] < 1 or dns[2] & 0x80:  # sin preguntas, o es respuesta
        return None
    labels, off = [], 12
    while off < len(dns):
        n = dns[off]
        if n == 0:
            break
        if n & 0xC0 or off + 1 + n > len(dns) or len(labels) >= 64:
            return None
        label = dns[off + 1:off + 1 + n].decode("ascii", "replace").lower()
        if not _LABEL_RE.match(label):
            return None
        labels.append(label)
        off += 1 + n
    return ".".join(labels) or None


def registrable(name: str) -> str:
    """Dominio registrable aproximado, sin lista de sufijos: `a.b.example.com` → `example.com`,
    `x.example.co.uk` → `example.co.uk`."""
    labels = name.rstrip(".").lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def dga_like(domain: str) -> bool:
    """¿Parece generado por un malware? Conservador: solo la etiqueta registrable larga y aleatoria."""
    label = registrable(domain).split(".")[0]
    if len(label) < 12:
        return False
    counts = collections.Counter(label)
    entropy = -sum(c / len(label) * math.log2(c / len(label)) for c in counts.values())
    digits = sum(ch.isdigit() for ch in label) / len(label)
    run = max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxz]+", label)), default=0)
    return entropy >= 3.6 or (digits >= 0.3 and entropy >= 3.0) or run >= 6


def ignored(name: str) -> bool:
    """Lo que no dice nada de un servicio: búsquedas inversas, mDNS, el propio host."""
    return name.endswith((".arpa", ".local", ".localdomain", ".internal", ".lan")) or "." not in name \
        or name in ("localhost",)


# ── NFLOG ────────────────────────────────────────────────────────────────────
def parse(data: bytes) -> list[tuple[str, bytes]]:
    """(prefijo, paquete) de cada mensaje NFLOG de un datagrama."""
    out, off = [], 0
    while off + 16 <= len(data):
        length, mtype = struct.unpack_from("=IH", data, off)
        if length < 16 or off + length > len(data):
            break
        if mtype == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
            prefix, payload, a = "", b"", off + 16 + 4  # nlmsghdr + nfgenmsg
            while a + 4 <= off + length:
                alen, atype = struct.unpack_from("=HH", data, a)
                if alen < 4:
                    break
                value = data[a + 4:a + alen]
                if atype & 0x7FFF == NFULA_PREFIX:
                    prefix = value.split(b"\0", 1)[0].decode("ascii", "replace")
                elif atype & 0x7FFF == NFULA_PAYLOAD:
                    payload = bytes(value)
                a += (alen + 3) & ~3
            if prefix.startswith(PREFIX) and payload:
                out.append((prefix[len(PREFIX):].strip(), payload))
        off += (length + 3) & ~3
    return out


def _config(sock: socket.socket, family: int, res_id: int, attrs: bytes) -> None:
    body = struct.pack("=BBH", family, 0, socket.htons(res_id)) + attrs
    sock.send(struct.pack("=IHHII", 16 + len(body), (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG, 1, 0, 0) + body)


def _attr(atype: int, value: bytes) -> bytes:
    raw = struct.pack("=HH", 4 + len(value), atype) + value
    return raw + b"\0" * ((-len(raw)) % 4)


def _subscribe() -> socket.socket:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    sock.bind((0, 0))
    for fam in (socket.AF_INET, socket.AF_INET6):
        _config(sock, fam, 0, _attr(NFULA_CFG_CMD, struct.pack("=B", CMD_PF_UNBIND)))
        _config(sock, fam, 0, _attr(NFULA_CFG_CMD, struct.pack("=B", CMD_PF_BIND)))
    _config(sock, socket.AF_UNSPEC, GROUP, _attr(NFULA_CFG_CMD, struct.pack("=B", CMD_BIND)))
    _config(sock, socket.AF_UNSPEC, GROUP, _attr(NFULA_CFG_MODE, struct.pack("!IBB", 512, COPY_PACKET, 0)))
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
    except OSError:
        pass
    return sock


def _listen(sock: socket.socket) -> None:
    while True:
        try:
            data = sock.recv(1 << 16)
        except OSError:
            continue
        for unit, packet in parse(data):
            name = qname(packet)
            if name and _UNIT_RE.match(unit) and not ignored(name):
                _events.append((unit, name))


def start() -> bool:
    if _state["running"]:
        return True
    try:
        sock = _subscribe()
    except (OSError, AttributeError):
        return False
    threading.Thread(target=_listen, args=(sock,), name="arx-dns", daemon=True).start()
    _state["running"] = True
    return True


def drain() -> list[tuple[str, str]]:
    out = []
    while _events:
        out.append(_events.popleft())
    return out


# ── las reglas: una por servicio, con su prefijo ──────────────────────────────
def rules_text(paths: list[str]) -> str:
    lines = [f"flush chain inet arx {CHAIN}"]
    for path in paths:
        unit = path.rsplit("/", 1)[-1]
        lines.append(f'add rule inet arx {CHAIN} socket cgroupv2 level 2 "{path}" '
                     f'log prefix "{PREFIX}{unit}" group {GROUP}')
    return "\n".join(lines) + "\n"


def sync(paths: list[str], signature) -> None:
    """Reconstruye la cadena si cambiaron los servicios o sus cgroups (un reinicio cambia el cgroup)."""
    if signature == _state["rules"]:
        return
    try:
        listing = subprocess.run(["nft", "list", "table", "inet", "arx"], capture_output=True, text=True,
                                 timeout=15).stdout or ""
        if f"chain {CHAIN} " not in listing:
            subprocess.run(["nft", "add", "chain", "inet", "arx", CHAIN], capture_output=True, timeout=15)
        if f"jump {CHAIN}" not in listing:
            subprocess.run(["nft", "add", "rule", "inet", "arx", "output", "meta", "l4proto", "udp", "th", "dport",
                            "53", "jump", CHAIN], capture_output=True, timeout=15)
        r = subprocess.run(["nft", "-f", "-"], input=rules_text(paths), capture_output=True, text=True, timeout=15)
        if r.returncode != 0:  # un servicio que se paró entre medias: regla a regla, sin él
            subprocess.run(["nft", "flush", "chain", "inet", "arx", CHAIN], capture_output=True, timeout=15)
            for path in paths:
                subprocess.run(["nft", "-f", "-"], input=rules_text([path]).split("\n", 1)[1], capture_output=True,
                               text=True, timeout=15)
    except Exception:  # sin la cadena no hay DNS por servicio, pero el barrido sigue
        return
    _state["rules"] = signature
