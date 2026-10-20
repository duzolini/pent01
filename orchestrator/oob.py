"""Out-of-band (OOB) interaction listener for confirming *blind* vulnerabilities.

Some vulnerabilities produce no observable response — a blind SSRF, a blind/
stored XSS, an out-of-band RCE. The way to confirm them is to make the target
reach back to a listener you control: if a request arrives carrying a unique
token you planted, the vulnerability is real.

This is a small, self-hosted interactsh/Burp-Collaborator-style HTTP listener:

    orchestrator oob-listen --host 0.0.0.0 --port 8081 --base-url http://YOUR_IP:8081

It records every inbound request to ``data/oob/interactions.jsonl``. A validator
plants ``<base-url>/<token>`` into a candidate sink and then polls that file for
a hit on the token. The listener is passive — it only records callbacks; it
never initiates anything.

The base URL must be reachable by the TARGET, so in a real engagement bind it to
a routable interface and set ``oob_url`` in the scope file.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "oob"
DEFAULT_LOG = DATA_DIR / "interactions.jsonl"

_write_lock = threading.Lock()


def _record(log_path: Path, entry: dict) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        with open(log_path, "a") as fh:
            fh.write(json.dumps(entry) + "\n")


class _Handler(BaseHTTPRequestHandler):
    log_path: Path = DEFAULT_LOG

    def _common(self, method: str) -> None:
        token = self.path.strip("/").split("/")[0].split("?")[0]
        body = b""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            body = self.rfile.read(min(length, 8192))
        _record(self.log_path, {
            "ts": time.time(),
            "token": token,
            "method": method,
            "path": self.path,
            "src_ip": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
            "host": self.headers.get("Host", ""),
            "body": body.decode("utf-8", "replace")[:2000],
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):   # noqa: N802
        self._common("GET")

    def do_POST(self):  # noqa: N802
        self._common("POST")

    def log_message(self, *a):  # silence default stderr logging
        return


class OobListener:
    def __init__(self, host: str = "0.0.0.0", port: int = 8081,
                 log_path: Path | None = None):
        self.host, self.port = host, port
        self.log_path = log_path or DEFAULT_LOG
        handler = type("_H", (_Handler,), {"log_path": self.log_path})
        self.server = ThreadingHTTPServer((host, port), handler)

    def serve_forever(self) -> None:
        self.server.serve_forever()

    def shutdown(self) -> None:
        self.server.shutdown()


class OobClient:
    """Plant tokens and poll the interaction log for callbacks."""

    def __init__(self, base_url: str, log_path: Path | None = None):
        self.base_url = base_url.rstrip("/")
        self.log_path = log_path or DEFAULT_LOG

    @staticmethod
    def new_token() -> str:
        return secrets.token_hex(8)

    def callback_url(self, token: str) -> str:
        return f"{self.base_url}/{token}"

    def interactions(self, token: str) -> list[dict]:
        if not self.log_path.exists():
            return []
        hits = []
        for line in self.log_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("token") == token or token in entry.get("path", ""):
                hits.append(entry)
        return hits

    def wait_for(self, token: str, timeout: float = 6.0, interval: float = 0.4) -> list[dict]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            hits = self.interactions(token)
            if hits:
                return hits
            time.sleep(interval)
        return self.interactions(token)
