"""Outbound Windows-agent bridge for the existing authenticated Home MCP gateway.

No extra public listener, no shared tunnel, and no administrative action hidden
behind agent registration. All device commands are explicit MCP tool calls.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import pwd
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

from mcp.types import CallToolResult, ImageContent, TextContent, ToolAnnotations
from starlette.responses import JSONResponse
from starlette.routing import Route

from .config import STATE

DB = Path(STATE) / "windows-agents.sqlite3"
DEVICE_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
REQUEST_ID = re.compile(r"^[a-f0-9]{32}$")
ACTIONS = frozenset({
    "windows_info", "windows_run", "windows_task_start", "windows_task_status",
    "windows_task_cancel", "windows_files_list", "windows_files_read",
    "windows_files_write", "windows_files_delete", "windows_files_move",
    "windows_files_mkdir", "windows_screen", "windows_mouse", "windows_keyboard",
    "windows_windows", "windows_browser_open",
})
MAX_ARGUMENT = 1536 * 1024
MAX_RESULT = 2 * 1024 * 1024 - 32768
# A synchronous Windows command can take 60s and posting its result can take
# another 40s. Keep the agent lease long enough for that bounded operation,
# without declaring a permanently stalled/disconnected agent ONLINE.
ONLINE_SECONDS = 150
MAX_TOOL_WAIT = 75
LOG = logging.getLogger(__name__)


def validate_device(device: str) -> str:
    if not isinstance(device, str) or DEVICE_ID.fullmatch(device) is None:
        raise ValueError("DEVICE_ID_INVALID")
    return device


def as_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class WindowsHub:
    def __init__(self, path: Path = DB):
        self.path = Path(path)
        # The systemd gateway has UMask=0077. Never put secrets in the checkout.
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise RuntimeError("WINDOWS_DB_SYMLINK")
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS devices(
                    device TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL,
                    created REAL NOT NULL,
                    last_seen REAL NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS requests(
                    id TEXT PRIMARY KEY,
                    device TEXT NOT NULL,
                    action TEXT NOT NULL,
                    args TEXT NOT NULL,
                    state TEXT NOT NULL,
                    result TEXT,
                    created REAL NOT NULL,
                    updated REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS windows_requests_queue
                    ON requests(device, state, created);
            """)
        os.chmod(self.path, 0o600)

    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def enroll(self, device: str) -> str:
        device = validate_device(device)
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connect() as db:
            row = db.execute("SELECT revoked FROM devices WHERE device=?", (device,)).fetchone()
            if row and not row["revoked"]:
                raise ValueError("DEVICE_ALREADY_ENROLLED: revoke before re-enrolling")
            if row:
                db.execute("UPDATE devices SET token_hash=?,created=?,last_seen=0,revoked=0 "
                           "WHERE device=? AND revoked=1", (digest, time.time(), device))
            else:
                db.execute("INSERT INTO devices(device,token_hash,created) VALUES(?,?,?)",
                           (device, digest, time.time()))
        return token

    def revoke(self, device: str):
        device = validate_device(device)
        with self._connect() as db:
            change = db.execute("UPDATE devices SET revoked=1 WHERE device=?", (device,))
            db.execute("UPDATE requests SET state='CANCELLED', updated=? "
                       "WHERE device=? AND state='QUEUED'", (time.time(), device))
            if change.rowcount != 1:
                raise ValueError("DEVICE_NOT_FOUND")

    def devices(self):
        with self._connect() as db:
            rows = db.execute("SELECT device,created,last_seen,revoked FROM devices "
                              "ORDER BY device").fetchall()
        now = time.time()
        return [{
            "device": row["device"],
            "online": not bool(row["revoked"]) and now - row["last_seen"] < ONLINE_SECONDS,
            "last_seen": (int(row["last_seen"]) if row["last_seen"] else None),
            "revoked": bool(row["revoked"]),
        } for row in rows]

    def _authorized(self, request):
        device = request.headers.get("x-windows-device", "")
        bearer = request.headers.get("authorization", "")
        if not DEVICE_ID.fullmatch(device) or not bearer.startswith("Bearer "):
            return None
        token = bearer[7:]
        if not (40 <= len(token) <= 128 and token.isascii()):
            return None
        with self._connect() as db:
            row = db.execute("SELECT token_hash,revoked FROM devices WHERE device=?",
                             (device,)).fetchone()
        if row is None or row["revoked"]:
            return None
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        return device if hmac.compare_digest(digest, row["token_hash"]) else None

    def _seen(self, device: str):
        with self._connect() as db:
            db.execute("UPDATE devices SET last_seen=? WHERE device=? AND revoked=0",
                       (time.time(), device))

    async def poll(self, request):
        device = self._authorized(request)
        if device is None:
            return JSONResponse({"error": "DEVICE_UNAUTHORIZED"}, status_code=401)
        self._seen(device)
        # One agent polls for each device. Claims are transactional even if
        # clients accidentally start two copies of the same configured ZIP.
        for _ in range(38):
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT id, action, args FROM requests "
                    "WHERE device=? AND state='QUEUED' ORDER BY created LIMIT 1",
                    (device,),
                ).fetchone()
                if row:
                    db.execute("UPDATE requests SET state='RUNNING', updated=? "
                               "WHERE id=? AND state='QUEUED'", (time.time(), row["id"]))
            if row:
                return JSONResponse({"ok": True, "job": {
                    "id": row["id"], "action": row["action"],
                    "arguments": json.loads(row["args"]),
                }}, headers={"Cache-Control": "no-store"},
                    media_type="application/json; charset=utf-8")
            await asyncio.sleep(0.5)
        return JSONResponse({"ok": True, "job": None}, headers={"Cache-Control": "no-store"},
                            media_type="application/json; charset=utf-8")

    async def result(self, request):
        device = self._authorized(request)
        if device is None:
            return JSONResponse({"error": "DEVICE_UNAUTHORIZED"}, status_code=401)
        if int(request.headers.get("content-length") or 0) > MAX_RESULT:
            return JSONResponse({"error": "RESULT_TOO_LARGE"}, status_code=413)
        raw = await request.body()
        if len(raw) > MAX_RESULT:
            return JSONResponse({"error": "RESULT_TOO_LARGE"}, status_code=413)
        try:
            value = json.loads(raw)
            identifier = value["id"]
            payload = value["result"]
            if not REQUEST_ID.fullmatch(identifier) or not isinstance(payload, dict):
                raise ValueError
            if not isinstance(payload.get("isError"), bool):
                raise ValueError
        except (ValueError, TypeError, KeyError):
            return JSONResponse({"error": "INVALID_RESULT"}, status_code=400)
        with self._connect() as db:
            row = db.execute("SELECT state FROM requests WHERE id=? AND device=?",
                             (identifier, device)).fetchone()
            if row is None:
                return JSONResponse({"error": "UNKNOWN_REQUEST"}, status_code=404)
            # A request may time out on the MCP side after the Agent claimed it.
            # Accept the late result once; never dispatch the command twice.
            if row["state"] in ("RUNNING", "UNKNOWN"):
                if row["state"] == "UNKNOWN":
                    LOG.warning("windows_late_result device=%s request_id=%s",
                                device, identifier)
                db.execute("UPDATE requests SET state='DONE',result=?,updated=? WHERE id=? "
                           "AND state IN ('RUNNING','UNKNOWN')",
                           (as_json(payload), time.time(), identifier))
            elif row["state"] != "DONE":
                return JSONResponse({"error": "REQUEST_NOT_RUNNING"}, status_code=409)
        self._seen(device)
        return JSONResponse({"ok": True, "delivered": True})

    def routes(self):
        return [
            Route("/windows-agent/v1/poll", self.poll, methods=["POST"]),
            Route("/windows-agent/v1/result", self.result, methods=["POST"]),
        ]

    def request_status(self, device: str, identifier: str):
        validate_device(device)
        if not isinstance(identifier, str) or not REQUEST_ID.fullmatch(identifier):
            return {"ok": False, "error": "INVALID_REQUEST_ID"}
        with self._connect() as db:
            row = db.execute("SELECT state, result, updated FROM requests "
                             "WHERE id=? AND device=?", (identifier, device)).fetchone()
        if row is None:
            return {"ok": False, "error": "REQUEST_NOT_FOUND"}
        result = json.loads(row["result"]) if row["result"] else None
        if isinstance(result, dict):
            result = result.get("structuredContent", result)
        # Older RUNNING rows (including pre-upgrade requests) may have lost
        # their Agent connection. Surface UNKNOWN without mutating a read.
        stale = (row["state"] == "RUNNING"
                 and time.time() - row["updated"] >= MAX_TOOL_WAIT)
        state = "UNKNOWN" if stale else row["state"]
        response = {"ok": True, "request_id": identifier,
                    "state": state, "result": result}
        if state == "UNKNOWN":
            response["effects_unknown"] = True
        if stale:
            response["recorded_state"] = "RUNNING"
        return response

    async def invoke(self, device: str, action: str, arguments: dict):
        validate_device(device)
        if action not in ACTIONS or not isinstance(arguments, dict):
            return {"ok": False, "error": "INVALID_WINDOWS_ACTION"}
        serialized = as_json(arguments)
        if len(serialized.encode("utf-8")) > MAX_ARGUMENT:
            return {"ok": False, "error": "WINDOWS_ARGUMENT_TOO_LARGE"}
        now = time.time()
        with self._connect() as db:
            row = db.execute("SELECT last_seen,revoked FROM devices WHERE device=?",
                             (device,)).fetchone()
            if row is None or row["revoked"]:
                return {"ok": False, "error": "DEVICE_NOT_REGISTERED"}
            if now - row["last_seen"] >= ONLINE_SECONDS:
                return {"ok": False, "error": "DEVICE_OFFLINE"}
            identifier = uuid.uuid4().hex
            db.execute("INSERT INTO requests(id,device,action,args,state,created,updated) "
                       "VALUES(?,?,?,?,'QUEUED',?,?)",
                       (identifier, device, action, serialized, now, now))
        # The queued request is durable. Uncertain running operations are NEVER
        # automatically retried or delivered to a different Windows device.
        for _ in range(MAX_TOOL_WAIT * 5):
            await asyncio.sleep(0.2)
            with self._connect() as db:
                row = db.execute("SELECT state,result FROM requests WHERE id=?",
                                 (identifier,)).fetchone()
            if row is not None and row["state"] == "DONE":
                try:
                    return json.loads(row["result"])
                except (ValueError, TypeError):
                    return {"ok": False, "error": "INVALID_AGENT_RESULT"}
            if row is not None and row["state"] == "CANCELLED":
                return {"ok": False, "error": "REQUEST_CANCELLED"}
        with self._connect() as db:
            # CANCELLED was never claimed. UNKNOWN was claimed and could
            # still complete; a late Agent result is accepted as DONE.
            now = time.time()
            db.execute("UPDATE requests SET state='CANCELLED', updated=? "
                       "WHERE id=? AND state='QUEUED'", (now, identifier))
            db.execute("UPDATE requests SET state='UNKNOWN', updated=? "
                       "WHERE id=? AND state='RUNNING'", (now, identifier))
            row = db.execute("SELECT state,result FROM requests WHERE id=?",
                             (identifier,)).fetchone()
        # Agent completion could race the timeout boundary.
        if row and row["state"] == "DONE" and row["result"]:
            return json.loads(row["result"])
        final_state = row["state"] if row is not None else "MISSING"
        LOG.warning("windows_request_timeout device=%s action=%s request_id=%s "
                    "state=%s auto_retried=false",
                    device, action, identifier, final_state)
        return {
            "ok": False, "error": "WINDOWS_RESULT_TIMEOUT",
            "request_id": identifier,
            "effects_unknown": bool(row and row["state"] == "UNKNOWN"),
            "auto_retried": False,
        }


def register_windows(mcp, security, hub: WindowsHub):
    readonly = ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                               idempotentHint=True, openWorldHint=False)
    mutate = ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                             idempotentHint=False, openWorldHint=True)

    async def dispatch(device_id, action, args):
        try:
            raw = await hub.invoke(device_id, action, args)
            if raw.get("content") and action == "windows_screen":
                image = next((x for x in raw["content"] if x.get("type") == "image"), None)
                if image and image.get("mimeType") == "image/jpeg":
                    info = raw.get("structuredContent") or {"ok": True}
                    return CallToolResult(content=[
                        ImageContent(type="image", mimeType="image/jpeg", data=image["data"]),
                        TextContent(type="text", text=as_json(info)),
                    ], structuredContent=info, isError=False)
            value = raw.get("structuredContent", raw)
            if not isinstance(value, dict):
                value = {"ok": False, "error": "INVALID_WINDOWS_RESULT"}
            return CallToolResult(
                content=[TextContent(type="text", text=as_json(value))],
                structuredContent=value,
                isError=bool(raw.get("isError", not value.get("ok", False))),
            )
        except (ValueError, TypeError, KeyError):
            value = {"ok": False, "error": "WINDOWS_BRIDGE_REJECTED"}
            return CallToolResult(content=[TextContent(type="text", text=as_json(value))],
                                  structuredContent=value, isError=True)

    @mcp.tool(title="Windows 장치 목록", annotations=readonly, meta=security)
    async def windows_devices() -> CallToolResult:
        """List enrolled Windows agents, their IDs, last check-in, and online state."""
        value = {"ok": True, "devices": hub.devices()}
        return CallToolResult(content=[TextContent(type="text", text=as_json(value))],
                              structuredContent=value, isError=False)

    @mcp.tool(title="Windows 요청 결과 조회", annotations=readonly, meta=security)
    async def windows_request_status(device_id: str, request_id: str) -> CallToolResult:
        """Look up a previous request ID after a timeout; never blindly retry writes."""
        value = hub.request_status(device_id, request_id)
        return CallToolResult(content=[TextContent(type="text", text=as_json(value))],
                              structuredContent=value, isError=not value["ok"])

    @mcp.tool(title="Windows PC 정보", annotations=readonly, meta=security)
    async def windows_info(device_id: str) -> CallToolResult:
        """Inspect the named Windows PC and whether its interactive GUI is ready."""
        return await dispatch(device_id, "windows_info", {})

    @mcp.tool(title="Windows 명령 실행", annotations=mutate, meta=security)
    async def windows_run(device_id: str, command: str, shell: str = "powershell",
                          cwd: str = "", timeout_seconds: int = 60) -> CallToolResult:
        """Run PowerShell/CMD on a specific Windows PC with its configured privileges.
        No command allowlist. Use windows_task_start for long builds or tests."""
        return await dispatch(device_id, "windows_run",
                              {"command": command, "shell": shell,
                               "cwd": cwd, "timeout_seconds": timeout_seconds})

    @mcp.tool(title="Windows 긴 작업 시작", annotations=mutate, meta=security)
    async def windows_task_start(device_id: str, command: str, cwd: str = "",
                                 timeout_seconds: int = 1800) -> CallToolResult:
        """Start detached PowerShell build/test and return a task_id for later polling."""
        return await dispatch(device_id, "windows_task_start", {
            "command": command, "cwd": cwd, "timeout_seconds": timeout_seconds})

    @mcp.tool(title="Windows 긴 작업 조회", annotations=readonly, meta=security)
    async def windows_task_status(device_id: str, task_id: str) -> CallToolResult:
        """Read task state and bounded stdout/stderr from the named device."""
        return await dispatch(device_id, "windows_task_status", {"task_id": task_id})

    @mcp.tool(title="Windows 긴 작업 취소", annotations=mutate, meta=security)
    async def windows_task_cancel(device_id: str, task_id: str) -> CallToolResult:
        """Stop a detached job and its descendants. Previously applied changes stay."""
        return await dispatch(device_id, "windows_task_cancel", {"task_id": task_id})

    @mcp.tool(title="Windows 파일 목록", annotations=readonly, meta=security)
    async def windows_files_list(device_id: str, path: str, limit: int = 100) -> CallToolResult:
        """List folders or files at a Windows path, including other volumes."""
        return await dispatch(device_id, "windows_files_list", {"path": path, "limit": limit})

    @mcp.tool(title="Windows 파일 읽기", annotations=readonly, meta=security)
    async def windows_files_read(device_id: str, path: str,
                                 encoding: str = "utf8") -> CallToolResult:
        """Read a Windows text or base64 file up to 1 MiB."""
        return await dispatch(device_id, "windows_files_read",
                              {"path": path, "encoding": encoding})

    @mcp.tool(title="Windows 파일 쓰기", annotations=mutate, meta=security)
    async def windows_files_write(device_id: str, path: str, content: str,
                                  encoding: str = "utf8") -> CallToolResult:
        """Create/overwrite Windows file. No built-in path allowlist."""
        return await dispatch(device_id, "windows_files_write",
                              {"path": path, "content": content, "encoding": encoding})

    @mcp.tool(title="Windows 파일 삭제", annotations=mutate, meta=security)
    async def windows_files_delete(device_id: str, path: str,
                                   recursive: bool = False) -> CallToolResult:
        """Delete Windows file/folder. Recursive deletion is irreversible."""
        return await dispatch(device_id, "windows_files_delete",
                              {"path": path, "recursive": recursive})

    @mcp.tool(title="Windows 파일 이동", annotations=mutate, meta=security)
    async def windows_files_move(device_id: str, source: str,
                                 destination: str) -> CallToolResult:
        """Move or rename Windows file/folder."""
        return await dispatch(device_id, "windows_files_move",
                              {"source": source, "destination": destination})

    @mcp.tool(title="Windows 폴더 만들기", annotations=mutate, meta=security)
    async def windows_files_mkdir(device_id: str, path: str) -> CallToolResult:
        """Create a directory on a Windows PC."""
        return await dispatch(device_id, "windows_files_mkdir", {"path": path})

    @mcp.tool(title="Windows 화면 캡처", annotations=readonly, meta=security)
    async def windows_screen(device_id: str) -> CallToolResult:
        """Return a Windows screenshot as MCP JPEG ImageContent, when desktop unlocked."""
        return await dispatch(device_id, "windows_screen", {})

    @mcp.tool(title="Windows 마우스", annotations=mutate, meta=security)
    async def windows_mouse(device_id: str, action: str,
                            x: int = 0, y: int = 0, to_x: int = 0,
                            to_y: int = 0, delta: int = 120) -> CallToolResult:
        """Move/click/double_click/right_click/drag/scroll a logged-in Windows desktop."""
        return await dispatch(device_id, "windows_mouse", {
            "action": action, "x": x, "y": y, "to_x": to_x, "to_y": to_y, "delta": delta})

    @mcp.tool(title="Windows 키보드", annotations=mutate, meta=security)
    async def windows_keyboard(device_id: str, text: str = "",
                               keys: str = "") -> CallToolResult:
        """Type text or a key combo on an unlocked Windows desktop."""
        return await dispatch(device_id, "windows_keyboard", {"text": text, "keys": keys})

    @mcp.tool(title="Windows 창 관리", annotations=mutate, meta=security)
    async def windows_windows(device_id: str, action: str = "list",
                              process_id: int = 0) -> CallToolResult:
        """List or activate windows in the interactive user session."""
        return await dispatch(device_id, "windows_windows",
                              {"action": action, "process_id": process_id})

    @mcp.tool(title="Windows 브라우저 열기", annotations=mutate, meta=security)
    async def windows_browser_open(device_id: str, url: str) -> CallToolResult:
        """Open HTTP(S) URL in the default Windows browser, then use GUI tools."""
        return await dispatch(device_id, "windows_browser_open", {"url": url})


def main():
    parser = argparse.ArgumentParser(description="Home MCP: outbound Windows device management")
    parser.add_argument("command", choices=["enroll", "list", "revoke"])
    parser.add_argument("device", nargs="?")
    args = parser.parse_args()
    service_uid = pwd.getpwnam("home-mcp").pw_uid
    if os.geteuid() != service_uid:
        parser.error("run as home-mcp service user (sudo runuser -u home-mcp -- ...)")
    os.umask(0o077)
    hub = WindowsHub()
    if args.command == "list":
        for row in hub.devices():
            print(f'{row["device"]}: {"ONLINE" if row["online"] else "OFFLINE"}'
                  + (" REVOKED" if row["revoked"] else ""))
    else:
        if not args.device:
            parser.error("device ID required")
        if args.command == "enroll":
            token = hub.enroll(args.device)
            print("DEVICE_ID=" + args.device)
            print("DEVICE_TOKEN=" + token)
            print("Copy the token directly to the Windows setup, never chat or git.")
        else:
            hub.revoke(args.device)
            print("REVOKED=" + args.device)


if __name__ == "__main__":
    main()
