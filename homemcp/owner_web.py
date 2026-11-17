"""Small owner-only approval website. Different UID/password from the MCP gateway."""
from __future__ import annotations
import asyncio
from dataclasses import replace
import hashlib
import hmac
import html
import json
import os
import pwd
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs
import uvicorn
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route
from .auth_store import verify_password
from .broker_client import call
from .config import PolicyError, load_config, require
from .http_guard import Guard
from .phase2_policy import OWNER_STATE, canonical, load_policy

COOKIE = "__Host-home-mcp-owner"
CHALLENGE = "__Host-home-mcp-owner-login"


def read_password_hash():
    folder = Path(OWNER_STATE)
    require(folder.resolve(strict=True) == folder and folder.stat().st_uid == os.geteuid()
            and folder.stat().st_mode & 0o077 == 0, "OWNER_STATE_PERMISSIONS")
    target = folder / "owner.json"
    require(not target.is_symlink() and target.stat().st_uid == os.geteuid()
            and target.stat().st_nlink == 1 and target.stat().st_mode & 0o077 == 0
            and target.stat().st_size <= 4096, "OWNER_SECRET_PERMISSIONS")
    value = json.loads(target.read_text())
    require(set(value) == {"version", "password_hash"} and value["version"] == 1
            and isinstance(value["password_hash"], str), "OWNER_BOOTSTRAP_REQUIRED")
    return value["password_hash"]


def page(body, status=200):
    style = 'body{font:16px system-ui;margin:0;background:#f7f7f8;color:#171717}main{max-width:760px;margin:auto;padding:24px 16px}h1{font-size:24px}a{color:#2457c5}article,form{padding:16px;margin:14px 0;background:white;border:1px solid #ddd;border-radius:12px}label{display:block;margin:12px 0}input{display:block;box-sizing:border-box;width:100%;padding:12px;font:inherit;border:1px solid #aaa;border-radius:8px}button{font:inherit;padding:11px 16px;margin:6px 6px 0 0;cursor:pointer;border:1px solid #bbb;border-radius:8px;background:white}button[value=allow]{background:#1f5fd6;color:white;border-color:#1f5fd6}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:50vh;overflow:auto;font-size:13px}.muted{color:#666;font-size:13px}.error{color:#a02020}details{margin:12px 0}'
    return HTMLResponse('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Home MCP 승인</title><style>' + style + '</style><main><h1>Home MCP 승인</h1>' + body + '</main></html>', status_code=status)


def create_app():
    config = replace(load_config(), port=load_policy()["owner_port"])
    require(os.geteuid() == pwd.getpwnam("home-mcp-owner").pw_uid and os.geteuid() != 0, "OWNER_WEB_IDENTITY_REQUIRED")
    encoded = read_password_hash()
    sessions, challenges, attempts = {}, {}, []
    hashing = asyncio.Semaphore(2)
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()
    def cleanup():
        now = time.time()
        for records in (sessions, challenges):
            for key in list(records):
                if records[key]["expires"] < now:
                    del records[key]
    def current(request):
        cleanup()
        token = request.cookies.get(COOKIE, "")
        return sessions.get(digest(token)) if len(token) == 43 else None
    async def fields(request):
        require(request.headers.get("origin") == config.origin, "OWNER_ORIGIN_REQUIRED")
        require(request.headers.get("content-type", "").split(";")[0] == "application/x-www-form-urlencoded", "OWNER_FORM_REQUIRED")
        raw = await request.body()
        require(len(raw) <= 16384, "OWNER_FORM_TOO_LARGE")
        values = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=10)
        require(all(len(v) == 1 for v in values.values()), "DUPLICATE_FORM_FIELD")
        return {k: v[0] for k, v in values.items()}
    async def password(value):
        now = time.monotonic()
        attempts[:] = [x for x in attempts if x > now - 900]
        require(len(attempts) < 10, "OWNER_LOGIN_RATE_LIMIT")
        attempts.append(now)
        try:
            await asyncio.wait_for(hashing.acquire(), 0.1)
        except asyncio.TimeoutError:
            raise PolicyError("OWNER_LOGIN_BUSY") from None
        try:
            valid = await asyncio.to_thread(verify_password, value, encoded)
        finally:
            hashing.release()
        require(valid, "OWNER_PASSWORD_REJECTED")
        attempts.clear()
    def csrf_form(session):
        return '<input type="hidden" name="csrf" value="' + session["csrf"] + '">'
    async def rpc(operation, args):
        result = await call(operation, args)
        require(result.get("ok"), result.get("error", "BROKER_UNAVAILABLE"))
        return result

    async def login(request):
        cleanup()
        if request.method == "GET":
            require(len(challenges) < 100, "OWNER_LOGIN_BUSY")
            token = secrets.token_urlsafe(32)
            challenges[digest(token)] = {"expires": time.time() + 300}
            response = page('<p>승인 전용 비밀번호를 입력해라. 채팅이나 MCP 도구에는 입력하지 않는다.</p><form method="post" action="/approval/login"><input type="hidden" name="csrf" value="' + token + '"><label>승인 비밀번호<input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label><button>로그인</button></form>')
            response.set_cookie(CHALLENGE, token, secure=True, httponly=True, samesite="strict", path="/", max_age=300)
            return response
        data = await fields(request)
        token = request.cookies.get(CHALLENGE, "")
        require(len(token) == 43 and hmac.compare_digest(token, data.get("csrf", "")) and challenges.pop(digest(token), None), "OWNER_CSRF_REJECTED")
        await password(data.get("password", ""))
        require(len(sessions) < 20, "OWNER_SESSION_LIMIT")
        session_token = secrets.token_urlsafe(32)
        sessions[digest(session_token)] = {"expires": time.time() + 900, "csrf": secrets.token_urlsafe(32)}
        response = RedirectResponse("/approval/", status_code=303)
        response.set_cookie(COOKIE, session_token, secure=True, httponly=True, samesite="strict", path="/", max_age=900)
        response.delete_cookie(CHALLENGE, secure=True, httponly=True, samesite="strict", path="/")
        return response

    async def route(request):
        session = current(request)
        if not session:
            return RedirectResponse("/approval/login", status_code=303)
        identifier = request.path_params.get("identifier")
        if request.method == "POST":
            data = await fields(request)
            require(hmac.compare_digest(session["csrf"], data.get("csrf", "")), "OWNER_CSRF_REJECTED")
            session["csrf"] = secrets.token_urlsafe(32)
            if request.url.path == "/approval/logout":
                sessions.pop(digest(request.cookies.get(COOKIE, "")), None)
                response = RedirectResponse("/approval/login", status_code=303)
                response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict", path="/")
                return response
            if request.url.path == "/approval/grants":
                await password(data.get("password", ""))
                await rpc("owner_revoke", {"id": data.get("id", "")})
                return RedirectResponse("/approval/grants", status_code=303)
            decision = data.get("decision")
            require(decision in {"allow", "deny", "always"}, "INVALID_DECISION")
            if decision != "deny":
                await password(data.get("password", ""))
            await rpc("owner_decide", {"id": identifier, "signature": data.get("signature", ""), "decision": decision})
            return RedirectResponse("/approval/" + identifier, status_code=303)
        navigation = '<p><a href="/approval/">요청 목록</a> · <a href="/approval/grants">항상 허용 관리</a></p>'
        if request.url.path == "/approval/grants":
            records = (await rpc("owner_grants", {}))["grants"]
            body = navigation + '<p class="muted">철회하면 아직 시작하지 않은 허용도 취소한다. 완료된 변경은 되돌리지 않는다.</p>'
            for row in records:
                body += '<article><pre>' + html.escape(canonical(row["scope"])) + '</pre><p>' + ('철회됨' if row["revoked"] else '허용 중') + '</p>'
                if not row["revoked"]:
                    body += '<form method="post" action="/approval/grants">' + csrf_form(session) + '<input type="hidden" name="id" value="' + html.escape(row["id"], quote=True) + '"><label>승인 비밀번호<input type="password" name="password" required maxlength="1024"></label><button>허용 철회</button></form>'
                body += '</article>'
            return page(body)
        if identifier:
            row = (await rpc("owner_get", {"id": identifier}))["request"]
            body = navigation + '<h2>' + html.escape(row["action"]) + '</h2><p>' + html.escape(row["status"]) + '</p><p class="muted">아래는 AI가 요청한 작업 내용이다. 대상·명령·파일 내용을 확인한 뒤 결정해라.</p><pre>' + html.escape(json.dumps(row["payload"], indent=2, ensure_ascii=False)) + '</pre>'
            if row["action"] == "network.run":
                body += '<p class="muted">일반 사용자로 실행한다. 표시된 공인 IP에는 접근할 수 있으며 공유 IP의 다른 서비스까지 도메인 단위로 구분하는 방화벽은 아니다. 작업 파일이 외부로 전송될 수 있다.</p>'
            if row["status"] == "PENDING":
                body += '<form method="post" action="/approval/' + identifier + '">' + csrf_form(session) + '<input type="hidden" name="signature" value="' + row["signature"] + '"><label>허용할 때 승인 비밀번호 재입력<input type="password" name="password" autocomplete="current-password" maxlength="1024"></label><button name="decision" value="allow">이번만 허용</button><button name="decision" value="deny">거부</button>'
                if row["can_always_allow"]:
                    body += '<button name="decision" value="always">이 범위 항상 허용</button><p class="muted">파일은 이 경로의 비관리자 쓰기만, 통신 작업은 동일 명령·경로·대상·시간만 반복 허용한다. root는 항상 허용할 수 없다.</p>'
                body += '</form>'
            elif row["status"] == "APPROVED":
                body += '<p>허용했다. 채팅에서 같은 요청 번호로 실행하면 된다.</p>'
            if row["result"]:
                body += '<details><summary>실행 결과</summary><pre>' + html.escape(json.dumps(row["result"], indent=2, ensure_ascii=False)) + '</pre></details>'
            return page(body)
        records = (await rpc("owner_list", {}))["requests"]
        body = navigation
        for row in records:
            body += '<article><a href="/approval/' + row["id"] + '">' + html.escape(row["action"]) + '</a> · ' + html.escape(row["status"]) + '</article>'
        if not records:
            body += '<p>요청이 없다.</p>'
        body += '<form method="post" action="/approval/logout">' + csrf_form(session) + '<button>로그아웃</button></form>'
        return page(body)

    async def guarded(request):
        try:
            return await (login(request) if request.url.path == "/approval/login" else route(request))
        except PolicyError as exc:
            return page('<p class="error">' + html.escape(str(exc)) + '</p><a href="/approval/">다시 열기</a>', 403)
        except Exception:
            return page('<p class="error">승인 처리를 완료하지 못했다. 상태를 확인한 뒤 다시 요청해라.</p><a href="/approval/">목록</a>', 503)
    app = Starlette(routes=[Route("/approval/login", guarded, methods=["GET", "POST"]),
        Route("/approval/grants", guarded, methods=["GET", "POST"]), Route("/approval/logout", guarded, methods=["POST"]),
        Route("/approval/", guarded, methods=["GET"]), Route("/approval/{identifier}", guarded, methods=["GET", "POST"])])
    return Guard(app, config), config

if __name__ == "__main__":
    os.umask(0o077)
    app, config = create_app()
    uvicorn.run(app, host="127.0.0.1", port=config.port, workers=1, access_log=False,
                proxy_headers=False, server_header=False, log_level="warning", limit_concurrency=16)
