#!/usr/bin/env python3
"""Arx improvement-program collector (Python stdlib only).

Receives the anonymous reports that Arx installations send only after their owner said yes
(`arx telemetry enable`), stores them as JSONL and emails a daily digest.

    collector.py serve                    HTTP on 127.0.0.1:8787, behind an HTTPS reverse proxy
    collector.py digest [--date D] [--dry-run]   email the digest of day D (default: yesterday, UTC)
    collector.py summary [--days N]       print the summary of the last N days

Privacy by construction:
  · Source IPs are never written anywhere. The access log is silenced.
  · Every report is sanitized with the same rules as the client: only numbers, booleans and short
    identifiers survive; anything that looks like an IP is dropped. Unknown shapes are rejected.
  · Reception time is stored with hour precision.

Configuration (environment, e.g. a systemd EnvironmentFile with mode 0600):
  ARX_COLLECTOR_BIND (127.0.0.1)  ARX_COLLECTOR_PORT (8787)  ARX_COLLECTOR_DATA (/var/lib/arx-collector)
  ARX_COLLECTOR_INTERVAL_DAYS (7)  ARX_COLLECTOR_MIN_GAP_H (12)  ARX_COLLECTOR_MAX_PER_MIN (600)
  ARX_COLLECTOR_MAIL_TO  ARX_COLLECTOR_MAIL_FROM
  ARX_COLLECTOR_SMTP_HOST  ARX_COLLECTOR_SMTP_PORT (587)  ARX_COLLECTOR_SMTP_TLS (starttls|ssl|none)
  ARX_COLLECTOR_SMTP_USER  ARX_COLLECTOR_SMTP_PASSWORD
"""
from __future__ import annotations

import argparse
import collections
import gzip
import ipaddress
import json
import math
import os
import re
import smtplib
import sys
import threading
import time
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCHEMA = 1
MAX_BODY = 16 * 1024
MAX_DEPTH = 4
FP_TARGET = 0.1
_KEY = re.compile(r"[a-z0-9_]{1,40}")
_TEXT = re.compile(r"[A-Za-z0-9._+:-]{0,40}")
_ID = re.compile(r"[0-9a-f]{32}")
_DROP = object()


def env(name: str, default: str = "") -> str:
    return os.environ.get(f"ARX_COLLECTOR_{name}", default)


def data_dir() -> Path:
    return Path(env("DATA", "/var/lib/arx-collector"))


# ── validation ───────────────────────────────────────────────────────────────
def sanitize(obj, depth: int = 0):
    if obj is None or isinstance(obj, bool) or isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return round(obj, 3) if math.isfinite(obj) else None
    if isinstance(obj, str):
        if not _TEXT.fullmatch(obj):
            return _DROP
        try:
            ipaddress.ip_address(obj)
            return _DROP
        except ValueError:
            return obj
    if isinstance(obj, dict) and depth < MAX_DEPTH:
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _KEY.fullmatch(k):
                clean = sanitize(v, depth + 1)
                if clean is not _DROP:
                    out[k] = clean
        return out
    return _DROP


def validate(raw: bytes) -> dict:
    """The sanitized report, or ValueError with the reason. Never echoes the input back."""
    if len(raw) > MAX_BODY:
        raise ValueError("too large")
    try:
        body = json.loads(raw)
    except ValueError:
        raise ValueError("not json") from None
    if not isinstance(body, dict):
        raise ValueError("not an object")
    if body.get("schema") != SCHEMA:
        raise ValueError("unknown schema")
    if not _ID.fullmatch(str(body.get("install_id", ""))):
        raise ValueError("bad install_id")
    if not isinstance(body.get("arx"), str) or not _TEXT.fullmatch(body["arx"]):
        raise ValueError("bad version")
    clean = sanitize(body)
    if not isinstance(clean, dict):
        raise ValueError("bad shape")
    return clean


# ── storage and limits ───────────────────────────────────────────────────────
class Store:
    def __init__(self, root: Path, min_gap_s: float, max_per_min: int):
        self.root, self.min_gap_s, self.max_per_min = root, min_gap_s, max_per_min
        self._last: dict[str, float] = {}
        self._window: collections.deque = collections.deque()
        self._lock = threading.Lock()
        (root / "reports").mkdir(parents=True, exist_ok=True)

    def admit(self, install_id: str, now: float) -> str | None:
        """None if accepted; otherwise the reason (rate limits)."""
        with self._lock:
            while self._window and now - self._window[0] > 60:
                self._window.popleft()
            if len(self._window) >= self.max_per_min:
                return "busy"
            last = self._last.get(install_id)
            if last is not None and now - last < self.min_gap_s:
                return "too soon"
            self._window.append(now)
            self._last[install_id] = now
            if len(self._last) > 200_000:  # bounded memory: forget the oldest half
                for k, _ in sorted(self._last.items(), key=lambda kv: kv[1])[:100_000]:
                    del self._last[k]
            return None

    def save(self, report: dict, now: float) -> None:
        when = datetime.fromtimestamp(now, timezone.utc)
        line = json.dumps({"received": when.strftime("%Y-%m-%dT%H:00Z"), "report": report},
                          separators=(",", ":"), sort_keys=True)
        path = self.root / "reports" / f"{when.date().isoformat()}.jsonl"
        with self._lock:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line + "\n")


def handler_for(store: Store, interval_days: int):
    class Handler(BaseHTTPRequestHandler):
        server_version = "arx-collector"
        sys_version = ""

        def log_message(self, *args):  # never log source addresses
            pass

        def _reply(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/healthz":
                self._reply(200, {"ok": True})
            else:
                self._reply(404, {"ok": False})

        def do_POST(self):
            if self.path != "/v1/report":
                self._reply(404, {"ok": False})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_BODY:
                self._reply(413, {"ok": False, "error": "size"})
                return
            try:
                report = validate(self.rfile.read(length))
            except ValueError as e:
                self._reply(400, {"ok": False, "error": str(e)})
                return
            now = time.time()
            reason = store.admit(report["install_id"], now)
            if reason:
                self._reply(429, {"ok": False, "error": reason, "interval_days": interval_days})
                return
            store.save(report, now)
            self._reply(200, {"ok": True, "interval_days": interval_days})

    return Handler


def serve() -> int:
    interval = max(1, min(30, int(env("INTERVAL_DAYS", "7"))))
    store = Store(data_dir(), float(env("MIN_GAP_H", "12")) * 3600, int(env("MAX_PER_MIN", "600")))
    httpd = ThreadingHTTPServer((env("BIND", "127.0.0.1"), int(env("PORT", "8787"))),
                                handler_for(store, interval))
    print(f"arx-collector listening on {httpd.server_address[0]}:{httpd.server_address[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# ── digest ───────────────────────────────────────────────────────────────────
def load(root: Path, days: list[date]) -> list[dict]:
    out = []
    for d in days:
        try:
            text = (root / "reports" / f"{d.isoformat()}.jsonl").read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict) and isinstance(rec.get("report"), dict):
                out.append(rec["report"])
    return out


def _top(counter: collections.Counter, n: int = 8) -> str:
    return ", ".join(f"{k} ×{v}" for k, v in counter.most_common(n)) or "—"


def summarize(reports: list[dict], title: str, active_7d: int | None = None) -> str:
    latest: dict[str, dict] = {}
    for r in reports:  # per installation, its latest report of the period
        latest[r.get("install_id", "")] = r
    inst = list(latest.values())

    def count(fn) -> collections.Counter:
        return collections.Counter(str(fn(r)) for r in inst)

    def g(r, *keys, default=None):
        for k in keys:
            r = r.get(k) if isinstance(r, dict) else None
        return default if r is None else r

    systems = count(lambda r: "%s %s" % (r.get("os"), r.get("os_version")))
    lines = [title, "",
             f"Reports received: {len(reports)} · distinct installations: {len(inst)}"
             + (f" · active in the last 7 days: {active_7d}" if active_7d is not None else ""), ""]
    lines += [f"Versions:       {_top(count(lambda r: r.get('arx')))}",
              f"Systems:        {_top(systems)}",
              f"Kernels:        {_top(count(lambda r: r.get('kernel')))}",
              f"Architectures:  {_top(count(lambda r: r.get('arch')))}",
              f"Python:         {_top(count(lambda r: r.get('python')))}",
              f"Tiers:          {_top(count(lambda r: g(r, 'setup', 'tier')))}",
              f"Mode:           {_top(count(lambda r: g(r, 'setup', 'mode')))}",
              f"Alert channels: telegram {sum(bool(g(r, 'setup', 'telegram')) for r in inst)}"
              f" · webhook {sum(bool(g(r, 'setup', 'webhook')) for r in inst)}", ""]
    not_full = sum(g(r, "watch", "exec_capture") not in ("full", None) for r in inst)
    files_nf = sum(g(r, "watch", "files") not in ("full", None) for r in inst)
    lines += ["Watcher health (installations with a problem)",
              f"  exec capture not full: {not_full} · files watch not full: {files_nf}"
              f" · auditd missing: {sum(g(r, 'watch', 'auditd') is False for r in inst)}",
              f"  exec overflow > 0: {sum(g(r, 'watch', 'exec_overflow', default=0) > 0 for r in inst)}"
              f" · exec dropped > 0: {sum(g(r, 'watch', 'exec_dropped', default=0) > 0 for r in inst)}"
              f" · failed marks > 0: {sum(g(r, 'watch', 'exec_marks_failed', default=0) > 0 for r in inst)}",
              ""]
    fp_rates = []
    for r in inst:
        covered = g(r, "noise", "days_covered", default=0) or 0
        if covered:
            fp_rates.append((g(r, "noise", "false_positives", default=0) or 0) / covered)
    over = sum(rate >= FP_TARGET for rate in fp_rates)
    lines += ["Noise (latest report of each installation)",
              f"  high alerts: {sum(g(r, 'noise', 'alerts_high', default=0) or 0 for r in inst)}"
              f" · false positives: {sum(g(r, 'noise', 'false_positives', default=0) or 0 for r in inst)}"
              f" · unreviewed: {sum(g(r, 'noise', 'unreviewed_high', default=0) or 0 for r in inst)}",
              f"  mean FP/day: {round(sum(fp_rates) / len(fp_rates), 3) if fp_rates else 0}"
              f" · installations over the target (≥{FP_TARGET}/day): {over}", ""]
    kinds: collections.Counter = collections.Counter()
    for r in inst:
        for k, v in (g(r, "noise", "high_by_kind", default={}) or {}).items():
            if isinstance(v, int):
                kinds[k] += v
    restarts: collections.Counter = collections.Counter()
    delivery: dict[str, list[int]] = {}
    for r in inst:
        for k, v in (g(r, "health", "restart_state", default={}) or {}).items():
            if isinstance(v, int):
                restarts[k] += v
        for ch, d in (g(r, "health", "alert_delivery", default={}) or {}).items():
            if isinstance(d, dict):
                acc = delivery.setdefault(ch, [0, 0])
                acc[0] += d.get("ok", 0) if isinstance(d.get("ok"), int) else 0
                acc[1] += d.get("failed", 0) if isinstance(d.get("failed"), int) else 0
    lines += ["Stability",
              f"  self_down: {sum(g(r, 'health', 'self_down', default=0) or 0 for r in inst)}"
              f" ({_top(restarts)}) · self_stopped: {sum(g(r, 'health', 'self_stopped', default=0) or 0 for r in inst)}"
              f" · self_tamper: {sum(g(r, 'health', 'self_tamper', default=0) or 0 for r in inst)}"
              f" · self-check unavailable: {sum(g(r, 'health', 'self_check_unavailable', default=0) or 0 for r in inst)}",
              "Alert delivery",
              "  " + (" · ".join(f"{ch} ok {ok} / failed {bad}" for ch, (ok, bad) in sorted(delivery.items()))
                      or "—"),
              "", "High alerts by kind (top 10)"]
    lines += [f"  {k:<28} {v}" for k, v in kinds.most_common(10)] or ["  —"]
    return "\n".join(lines) + "\n"


def _gzip_day(root: Path, d: date) -> bytes | None:
    try:
        return gzip.compress((root / "reports" / f"{d.isoformat()}.jsonl").read_bytes())
    except OSError:
        return None


def build_digest(root: Path, d: date, mail_to: str, mail_from: str) -> EmailMessage:
    reports = load(root, [d])
    week = load(root, [d - timedelta(days=i) for i in range(7)])
    active = len({r.get("install_id") for r in week})
    msg = EmailMessage()
    msg["Subject"] = f"[Arx] improvement program · {d.isoformat()} · {len(reports)} reports"
    msg["From"] = mail_from or mail_to
    msg["To"] = mail_to
    msg.set_content(summarize(reports, f"Arx improvement program — daily digest {d.isoformat()} (UTC)",
                              active)
                    + "\nThe attachment holds the day's raw reports (anonymous, sanitized).\n")
    attachment = _gzip_day(root, d)
    if attachment:
        msg.add_attachment(attachment, maintype="application", subtype="gzip",
                           filename=f"arx-reports-{d.isoformat()}.jsonl.gz")
    return msg


def send_mail(msg: EmailMessage) -> None:
    host = env("SMTP_HOST")
    if not host:
        raise SystemExit("ARX_COLLECTOR_SMTP_HOST is not set")
    port, mode = int(env("SMTP_PORT", "587")), env("SMTP_TLS", "starttls").lower()
    cls = smtplib.SMTP_SSL if mode == "ssl" else smtplib.SMTP
    with cls(host, port, timeout=30) as s:
        if mode == "starttls":
            s.starttls()
        if env("SMTP_USER"):
            s.login(env("SMTP_USER"), env("SMTP_PASSWORD"))
        s.send_message(msg)


def digest(day: str | None, dry_run: bool) -> int:
    d = date.fromisoformat(day) if day else datetime.now(timezone.utc).date() - timedelta(days=1)
    mail_to = env("MAIL_TO")
    if not mail_to and not dry_run:
        raise SystemExit("ARX_COLLECTOR_MAIL_TO is not set")
    msg = build_digest(data_dir(), d, mail_to or "(dry run)", env("MAIL_FROM"))
    if dry_run:
        print(msg.get_body(("plain",)).get_content())
        return 0
    send_mail(msg)
    print(f"digest for {d.isoformat()} sent", flush=True)
    return 0


def summary(days: int) -> int:
    today = datetime.now(timezone.utc).date()
    reports = load(data_dir(), [today - timedelta(days=i) for i in range(days)])
    print(summarize(reports, f"Arx improvement program — last {days} days"))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="collector.py", description="Arx improvement-program collector")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="receive reports over HTTP (put HTTPS in front)")
    p_d = sub.add_parser("digest", help="email the daily digest")
    p_d.add_argument("--date", help="UTC day, YYYY-MM-DD (default: yesterday)")
    p_d.add_argument("--dry-run", action="store_true", help="print it instead of sending it")
    p_s = sub.add_parser("summary", help="print a summary of recent days")
    p_s.add_argument("--days", type=int, default=7)
    args = p.parse_args(argv)
    if args.cmd == "serve":
        return serve()
    if args.cmd == "digest":
        return digest(args.date, args.dry_run)
    return summary(args.days)


if __name__ == "__main__":
    sys.exit(main())
