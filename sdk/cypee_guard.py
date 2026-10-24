"""
CyPee In-App Shield SDK (Python / FastAPI / Flask / Django)

Drop this file directly into any Python web service to integrate with the CyPee Threat Mesh.

Usage in FastAPI:
    from cypee_guard import CyPeeFastAPIMiddleware
    app.add_middleware(CyPeeFastAPIMiddleware, cypee_url="http://localhost:3000", app_id="app2")
"""

import os
import json
import urllib.request
import threading
import time

class CyPeeGuard:
    def __init__(self, cypee_url=None, app_id=None, sync_interval=15):
        self.cypee_url = (cypee_url or os.getenv("CYPEE_URL", "http://127.0.0.1:3000")).rstrip("/")
        self.app_id = app_id or os.getenv("CYPEE_APP_ID", "py_app_default")
        self.sync_interval = sync_interval
        self.blocked_hashes = set()
        self._start_sync_thread()

    def _start_sync_thread(self):
        def _sync_loop():
            while True:
                try:
                    req = urllib.request.Request(f"{self.cypee_url}/api/v1/shield/federated/feed")
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode())
                            self.blocked_hashes = set(item.get("indicatorHash", "") if isinstance(item, dict) else str(item) for item in data)
                except Exception:
                    pass
                time.sleep(self.sync_interval)

        t = threading.Thread(target=_sync_loop, daemon=True)
        t.start()

    def check_request(self, client_ip: str, payload_str: str) -> tuple[bool, str]:
        # 1. Mesh quarantine check
        if client_ip in self.blocked_hashes:
            return False, "Client IP is quarantined by CyPee Cross-Application Threat Mesh."

        # 2. Local signature check
        lower = (payload_str or "").lower()
        if any(sig in lower for sig in ["union select", "or 1=1", "<script>alert(", "/etc/passwd"]):
            # Report back to mesh asynchronously
            def _report():
                try:
                    data = json.dumps({"threatType": "PYTHON_APP_INJECTION", "rawIndicator": client_ip}).encode()
                    req = urllib.request.Request(
                        f"{self.cypee_url}/api/v1/shield/federated/share",
                        data=data,
                        headers={"Content-Type": "application/json"}
                    )
                    urllib.request.urlopen(req, timeout=2)
                except Exception:
                    pass
            threading.Thread(target=_report, daemon=True).start()
            return False, "Malicious payload intercepted by CyPee Guard."

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
            
            # Read body
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
                    ]
                })
                await send({"type": "http.response.body", "body": response_body})
                return

            # Re-inject body for downstream
            async def receive_replay():
                return {"type": "http.request", "body": body, "more_body": False}

            await self.app(scope, receive_replay, send)
        else:
            await self.app(scope, receive, send)
