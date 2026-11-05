#!/usr/bin/env python3
"""Un Telegram falso para el lab: misma forma de API, sin salir de la red aislada. Arx habla con él
por HTTP de verdad, desde el servicio real. /inject mete un mensaje; /sent dice lo que Arx envió."""
import json
import queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

inbox: "queue.Queue[dict]" = queue.Queue()
sent: list[dict] = []
next_id = [1]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(sent)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path == "/inject":
            next_id[0] += 1
            inbox.put({"update_id": next_id[0], "message": {"chat": {"id": data["chat"]}, "text": data["text"]}})
            self._send({"ok": True})
        elif self.path.endswith("/getUpdates"):
            try:
                self._send({"ok": True, "result": [inbox.get(timeout=min(int(data.get("timeout", 1)), 2))]})
            except queue.Empty:
                self._send({"ok": True, "result": []})
        elif self.path.endswith("/sendMessage"):
            sent.append(data)
            self._send({"ok": True, "result": {}})
        else:
            self._send({"ok": True, "result": {}})


ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
