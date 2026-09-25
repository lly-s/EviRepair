#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SANDBOX_ID = os.environ.get("BRAINBOX_SANDBOX_ID", "sbx-ec349971-c4f")
SANDBOX_PROJECT = os.environ.get("SANDBOX_PROJECT", "anonymous-model")
SANDBOX_API_BASE = os.environ.get("SANDBOX_API_BASE", "https://h.example.invalid/brainbox/v1").rstrip("/")
UPSTREAM_BASE = f"{SANDBOX_API_BASE}/sandboxes/{SANDBOX_ID}/proxy/3000/v1"

OPEN_SANDBOX_API_KEY = os.environ.get("OPEN_SANDBOX_API_KEY", "").strip()
USER_SLOT = os.environ.get("BRAINBOX_USER_SLOT", "repair").strip().lower()

for _proxy_name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(_proxy_name, None)
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def urlopen_no_proxy(req: urllib.request.Request, timeout: int):
    return _NO_PROXY_OPENER.open(req, timeout=timeout)


def resolve_sub2api_key() -> str:
    direct = os.environ.get("BRAINBOX_SUB2API_KEY", "").strip()
    if direct:
        return direct
    if USER_SLOT == "repair":
        return os.environ.get("BRAINBOX_REPAIR_API_KEY", "").strip()
    if USER_SLOT == "exploit":
        return os.environ.get("BRAINBOX_EXPLOIT_API_KEY", "").strip()
    return ""

_sat_lock = threading.Lock()
_sat_value = ""
_sat_time = 0.0


def fetch_sat() -> str:
    if ":" not in OPEN_SANDBOX_API_KEY:
        raise RuntimeError("OPEN_SANDBOX_API_KEY must be ak:sk")
    url = f"{SANDBOX_API_BASE}/sandboxes/{SANDBOX_ID}?{urllib.parse.urlencode({'project': SANDBOX_PROJECT})}"
    req = urllib.request.Request(url, headers={"OPEN-SANDBOX-API-KEY": OPEN_SANDBOX_API_KEY})
    with urlopen_no_proxy(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    sat = (payload.get("endpoints") or {}).get("accessToken") or ""
    if not sat:
        raise RuntimeError("endpoints.accessToken is empty")
    return sat


def get_sat(force: bool = False) -> str:
    global _sat_value, _sat_time
    with _sat_lock:
        if force or not _sat_value or time.time() - _sat_time > 3000:
            _sat_value = fetch_sat()
            _sat_time = time.time()
        return _sat_value


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "BrainboxOpenAIProxy/1.2"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self) -> None:
        sub2api_key = resolve_sub2api_key()
        if not sub2api_key:
            self._send(500, json.dumps({"error": "missing Sub2API key", "slot": USER_SLOT}).encode("utf-8"))
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        path = self.path
        if path.startswith("/v1/"):
            path = path[3:]
        upstream = UPSTREAM_BASE + path
        headers = {
            "Content-Type": self.headers.get("Content-Type", "application/json"),
            "Authorization": f"Bearer {sub2api_key}",
            "X-Sandbox-Access-Token": get_sat(),
            "x-api-key": sub2api_key,
        }
        req = urllib.request.Request(upstream, data=body, headers=headers, method=self.command)
        for attempt in range(2):
            try:
                with urlopen_no_proxy(req, timeout=900) as resp:
                    self._send(resp.status, resp.read(), resp.headers.get("Content-Type", "application/json"))
                return
            except urllib.error.HTTPError as exc:
                err_body = exc.read()
                if exc.code == 401 and attempt == 0:
                    headers["X-Sandbox-Access-Token"] = get_sat(force=True)
                    req = urllib.request.Request(upstream, data=body, headers=headers, method=self.command)
                    continue
                self._send(exc.code, err_body or str(exc).encode("utf-8"))
                return
            except Exception as exc:
                self._send(502, json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8"))
                return

    def do_GET(self) -> None:
        if self.path == "/healthz":
            try:
                get_sat()
                payload = {"ok": True, "sandbox_id": SANDBOX_ID, "slot": USER_SLOT}
                self._send(200, json.dumps(payload).encode("utf-8"))
            except Exception as exc:
                self._send(500, json.dumps({"ok": False, "error": str(exc)}).encode("utf-8"))
            return
        self._proxy()

    def do_POST(self) -> None:
        self._proxy()


def main() -> int:
    port = int(os.environ.get("BRAINBOX_PROXY_PORT", "18104"))
    get_sat(force=True)
    server = ThreadingHTTPServer(("127.0.0.1", port), ProxyHandler)
    print(f"proxy_ready http://127.0.0.1:{port}/v1 -> {UPSTREAM_BASE} slot={USER_SLOT}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
