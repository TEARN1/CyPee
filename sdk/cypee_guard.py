"""
CyPee In-App Shield SDK (Python / FastAPI / Flask / Django) — v12 Sovereign Edition

Drop this file directly into any Python service in V-Gruvs, The Resident, The Gruvs, or Excellency
to integrate with the CyPee Federated Threat Mesh and V-Gruvs Host Guardian.

Usage in FastAPI:
    from cypee_guard import CyPeeFastAPIMiddleware
    app.add_middleware(CyPeeFastAPIMiddleware, cypee_url="http://127.0.0.1:3000", app_id="excellency")
"""

import os
import json
import hmac
import hashlib
import urllib.request
import threading
import time


class CyPeeGuard:
    def __init__(self, cypee_url=None, app_id=None, federated_salt=None, sync_interval=15):
        self.cypee_url = (cypee_url or os.getenv("CYPEE_URL", "http://127.0.0.1:3000")).rstrip("/")
        self.app_id = app_id or os.getenv("CYPEE_APP_ID", "excellency")
        self.federated_salt = (
            federated_salt or os.getenv("FEDERATED_SALT", "default-shield-edge-mesh-salt-key")
        ).encode("utf-8")
        self.sync_interval = sync_interval
        self.blocked_hashes = set()
        self._start_sync_thread()

    def _hash_indicator(self, raw_ip: str) -> str:
        return hmac.new(self.federated_salt, raw_ip.encode("utf-8"), hashlib.sha256).hexdigest()

    def _start_sync_thread(self):
        def _sync_loop():
            while True:
                try:
                    req = urllib.request.Request(f"{self.cypee_url}/api/v1/shield/federated/feed")
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode())
                            self.blocked_hashes = set(
                                item.get("indicatorHash", "") if isinstance(item, dict) else str(item)
                                for item in data
                            )
                except Exception:
                    pass
                time.sleep(self.sync_interval)

        t = threading.Thread(target=_sync_loop, daemon=True)
        t.start()

    def check_request(self, client_ip: str, payload_str: str) -> tuple[bool, str]:
        ip_hash = self._hash_indicator(client_ip)

        # 1. Mesh quarantine check (matches both HMAC-SHA256 hash and raw indicator)
        if ip_hash in self.blocked_hashes or client_ip in self.blocked_hashes:
            return False, "Client IP is quarantined by CyPee Cross-Application Threat Mesh."

        # 2. Local signature check (SQLi, XSS, Container Escape, and Spreadsheet DDE Formula Injection)
        lower = (payload_str or "").lower()
        signatures = [
            "union select",
            "or 1=1",
            "<script>alert(",
            "/etc/passwd",
            "/var/run/docker.sock",
            "/proc/self/environ",
            "=cmd|",
            "+cmd|",
            "-cmd|",
            "<!entity",
        ]
        if any(sig in lower for sig in signatures):
            self.blocked_hashes.add(ip_hash)

            def _report():
                try:
                    data = json.dumps({
                        "threatType": f"PYTHON_GUARD_{self.app_id.upper()}_INTERCEPT",
                        "rawIndicator": client_ip,
                    }).encode()
                    req = urllib.request.Request(
                        f"{self.cypee_url}/api/v1/shield/federated/share",
                        data=data,
                        headers={"Content-Type": "application/json"},
                    )
                    urllib.request.urlopen(req, timeout=2)
                except Exception:
                    pass

            threading.Thread(target=_report, daemon=True).start()
            return False, "Malicious payload intercepted by CyPee Sovereign Guard."

        return True, ""


# FastAPI ASGI Middleware
class CyPeeFastAPIMiddleware:
    def __init__(self, app, cypee_url=None, app_id=None):
        self.app = app
        self.guard = CyPeeGuard(cypee_url=cypee_url, app_id=app_id)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            client = scope.get("client")
            client_ip = client[0] if client else "127.0.0.1"

            more_body = True
            body_parts = []
            while more_body:
                message = await receive()
                body_parts.append(message.get("body", b""))
                more_body = message.get("more_body", False)
            body = b"".join(body_parts)

            allowed, reason = self.guard.check_request(client_ip, body.decode(errors="ignore"))
            if not allowed:
                response_body = json.dumps({"error": "Forbidden", "message": reason}).encode()
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"x-cypee-blocked", b"true"],
                    ],
                })
                await send({"type": "http.response.body", "body": response_body})
                return

            async def receive_replay():
                return {"type": "http.request", "body": body, "more_body": False}

            await self.app(scope, receive_replay, send)
        else:
            await self.app(scope, receive, send)
