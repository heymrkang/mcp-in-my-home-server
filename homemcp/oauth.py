"""OAuth authorization-code + S256, fixed client, browser-only owner consent."""
from __future__ import annotations

import asyncio
import base64
import binascii
import html
import re
from urllib.parse import parse_qsl, urlencode, unquote

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from .auth_store import AuthStore, verify_password
from .config import Config, PolicyError, SCOPE, WORKSPACE, require

COOKIE = "__Host-home-mcp-auth"


def unique_pairs(pairs) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "invalid_request")
        result[key] = value
    return result


async def form(request: Request) -> dict:
    require(request.headers.get("content-type", "").split(";")[0] == "application/x-www-form-urlencoded", "invalid_request")
    raw = await request.body()
    require(len(raw) <= 16384, "invalid_request")
    try:
        return unique_pairs(parse_qsl(raw.decode("utf-8", "strict"), keep_blank_values=True, max_num_fields=24))
    except (ValueError, UnicodeError):
        raise PolicyError("invalid_request") from None


class OAuth:
    def __init__(self, config: Config, store: AuthStore):
        self.config, self.store = config, store
        # AnyHttpUrl used by SDK metadata canonicalizes a bare authority with '/'.
        # Issuer comparison is exact: metadata, authorization_servers and callback iss must agree.
        self.issuer = config.origin + "/"
        self.password_slots = asyncio.Semaphore(2)

    def routes(self) -> list[Route]:
        return [Route("/.well-known/oauth-authorization-server", self.metadata, methods=["GET"]),
                Route("/oauth/authorize", self.authorize, methods=["GET"]),
                Route("/oauth/decision", self.decision, methods=["POST"]),
                Route("/oauth/token", self.token, methods=["POST"]),
                Route("/oauth/revoke", self.revoke, methods=["POST"])]

    async def metadata(self, _request: Request):
        origin = self.config.origin
        return JSONResponse({"issuer": self.issuer, "authorization_endpoint": origin + "/oauth/authorize",
            "token_endpoint": origin + "/oauth/token", "revocation_endpoint": origin + "/oauth/revoke",
            "scopes_supported": [SCOPE], "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"], "authorization_response_iss_parameter_supported": True})

    @staticmethod
    def error(code: str, browser: bool = False):
        limited = code in {"AUTH_RATE_LIMIT", "AUTH_BUSY", "AUTH_GRANT_LIMIT"}
        if browser:
            text = "요청이 많습니다. 잠시 뒤 다시 연결하세요." if limited else "로그인에 실패했거나 연결 요청이 만료됐습니다. ChatGPT에서 연결을 다시 시작하세요."
            return HTMLResponse("<!doctype html><html lang=ko><meta charset=utf-8><meta name=viewport content='width=device-width'><title>Home MCP</title><p>" + text + "</p></html>", status_code=429 if limited else 400)
        name = "temporarily_unavailable" if limited else code if re.fullmatch(r"[a-z_]{1,48}", code) else "invalid_request"
        return JSONResponse({"error": name}, status_code=429 if limited else 401 if name == "invalid_client" else 400)

    async def authorize(self, request: Request):
        try:
            flow, cookie, csrf = self.store.create_flow(unique_pairs(request.query_params.multi_items()))
            response = HTMLResponse(f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Home MCP 연결</title>
<style>body{{font:16px system-ui;background:#151515;color:#eee;max-width:420px;margin:10vh auto;padding:24px}}input,button{{box-sizing:border-box;width:100%;padding:14px;margin:10px 0;font:inherit;border-radius:8px}}p{{line-height:1.6;color:#ccc}}code{{overflow-wrap:anywhere}}</style></head><body>
<h1>Home MCP 연결</h1><p>ChatGPT에 <code>{html.escape(WORKSPACE)}</code>의 파일 읽기·쓰기와 제한된 명령 실행을 허용한다. 서버 소스와 인증 정보는 제외되며, root·Docker·외부 통신 권한은 없다.</p>
<form method="post" action="/oauth/decision"><input type="hidden" name="flow" value="{flow}">
<input type="hidden" name="csrf" value="{csrf}"><label>설치할 때 발급된 관리자 비밀번호<input name="password" type="password" autocomplete="current-password" maxlength="1024"></label>
<button name="decision" value="allow">연결 허용</button><button name="decision" value="deny">거부</button></form>
<p>비밀번호·완료 주소·토큰을 채팅에 붙여넣지 마라.</p></body></html>""")
            response.set_cookie(COOKIE, cookie, max_age=300, secure=True, httponly=True, samesite="lax", path="/")
            return response
        except PolicyError as exc:
            return self.error(str(exc), browser=True)

    async def decision(self, request: Request):
        try:
            require(request.headers.get("origin") == self.config.origin, "AUTH_ORIGIN_REJECTED")
            data = await form(request)
            require(set(data) <= {"flow", "csrf", "password", "decision"} and data.get("decision") in {"allow", "deny"}, "invalid_request")
            cookie = request.cookies.get(COOKIE, "")
            self.store.flow(data.get("flow", ""), cookie, data.get("csrf", ""))
            approved = data["decision"] == "allow"
            if approved:
                self.store.throttle("owner-login", 10, 300)
                require(not self.password_slots.locked(), "AUTH_BUSY")
                async with self.password_slots:
                    valid = await asyncio.to_thread(verify_password, data.get("password", ""), self.store.owner["password_hash"])
                data["password"] = ""
                require(valid, "AUTH_PASSWORD_REJECTED")
            payload, code = self.store.finish_flow(data["flow"], cookie, data["csrf"], approved)
            values = {"state": payload["state"], "iss": self.issuer}
            values.update({"code": code} if approved else {"error": "access_denied"})
            response = RedirectResponse(payload["redirect_uri"] + "?" + urlencode(values), status_code=303)
            response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="lax")
            return response
        except PolicyError as exc:
            return self.error(str(exc), browser=True)

    def client(self, request: Request, data: dict) -> None:
        authorization = request.headers.get("authorization", "")
        if authorization:
            require(authorization.startswith("Basic ") and not data.get("client_secret"), "invalid_client")
            try:
                decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
                client_id, secret = decoded.split(":", 1)
                client_id, secret = unquote(client_id), unquote(secret)
            except (ValueError, UnicodeError, binascii.Error):
                raise PolicyError("invalid_client") from None
            require(not data.get("client_id") or data["client_id"] == client_id, "invalid_client")
        else:
            client_id, secret = data.get("client_id", ""), data.get("client_secret", "")
        require(client_id.isascii(), "invalid_client")
        self.store.authenticate_client(client_id, secret)
        data["client_id"] = client_id
        data.pop("client_secret", None)

    async def token(self, request: Request):
        try:
            self.store.throttle("token", 120, 60)
            data = await form(request)
            self.client(request, data)
            grant = data.get("grant_type")
            require(grant in {"authorization_code", "refresh_token"}, "unsupported_grant_type")
            result = self.store.exchange_code(data) if grant == "authorization_code" else self.store.refresh(data)
            return JSONResponse(result)
        except PolicyError as exc:
            return self.error(str(exc))

    async def revoke(self, request: Request):
        try:
            self.store.throttle("revoke", 60, 60)
            data = await form(request)
            self.client(request, data)
            self.store.revoke(data.get("token", ""))
            return JSONResponse({})
        except PolicyError as exc:
            return self.error(str(exc))
