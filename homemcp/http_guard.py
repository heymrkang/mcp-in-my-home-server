"""Bound HTTP bodies and validate Host/Origin without trusting forwarded headers.

Use same-origin referrer policy: no-referrer can turn the Origin header into
`null` on browser HTML form POST, breaking OAuth decision CSRF checks.
Allow exactly chatgpt.com as an external form-action destination: Chromium
checks that directive across the POST /oauth/decision 303 redirect chain.
"""
import asyncio

from starlette.responses import JSONResponse

from .config import Config

HEADERS = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
           (b"referrer-policy", b"same-origin"), (b"x-frame-options", b"DENY"),
           (b"content-security-policy", b"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com; frame-ancestors 'none'; base-uri 'none'")]


class Guard:
    def __init__(self, app, config: Config):
        self.app, self.config = app, config

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = scope.get("headers", [])
        host_values = [value.decode("latin1").lower() for key, value in headers if key.lower() == b"host"]
        origins = [value.decode("latin1") for key, value in headers if key.lower() == b"origin"]
        allowed = {self.config.host.lower(), "127.0.0.1:" + str(self.config.port)}
        async def reject(status):
            await JSONResponse({"error": "REQUEST_REJECTED"}, status_code=status)(scope, receive, send)
        if len(host_values) != 1 or host_values[0] not in allowed:
            return await reject(421)
        if len(origins) > 1 or (origins and origins[0] != self.config.origin):
            return await reject(403)
        if scope["method"] not in {"GET", "HEAD", "POST", "DELETE"}:
            return await reject(405)
        cap = 2 * 1024 * 1024 if scope["path"] in {"/mcp", "/windows-agent/v1/result"} else 16384
        body = bytearray()
        async def collect():
            while True:
                part = await receive()
                if part["type"] == "http.disconnect":
                    raise ConnectionError
                body.extend(part.get("body", b""))
                if len(body) > cap:
                    raise OverflowError
                if not part.get("more_body", False):
                    return
        try:
            await asyncio.wait_for(collect(), 15)
        except OverflowError:
            return await reject(413)
        except asyncio.TimeoutError:
            return await reject(408)
        except ConnectionError:
            return
        delivered, started = False, False
        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        async def secure_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                removed = {key for key, _ in HEADERS}
                message["headers"] = [(key, value) for key, value in message.get("headers", []) if key.lower() not in removed] + HEADERS
            await send(message)
        try:
            await self.app(scope, replay, secure_send)
        except Exception:
            # Do not expose request bodies, tokens, cookie values or stack traces.
            if not started:
                await JSONResponse({"error": "INTERNAL_ERROR"}, status_code=500)(scope, replay, secure_send)
            else:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
