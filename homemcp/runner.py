"""Unprivileged, socket-activated execution service; never receives OAuth secrets."""
from __future__ import annotations

import asyncio
import grp
import json
import os
import pwd
import socket
import struct
import uuid

from .config import PolicyError, SOURCE, WORKSPACE, load_config, require
from .sandbox import ensure_host_layout, execute

MAX_FRAME = 2 * 1024 * 1024


async def read_frame(reader):
    length = struct.unpack("!I", await reader.readexactly(4))[0]
    require(0 < length <= MAX_FRAME, "RUNNER_FRAME_TOO_LARGE")
    return json.loads(await reader.readexactly(length))


async def write_frame(writer, value):
    body = json.dumps(value, ensure_ascii=False).encode()
    require(len(body) <= MAX_FRAME, "RUNNER_RESULT_TOO_LARGE")
    writer.write(struct.pack("!I", len(body)) + body)
    await writer.drain()


async def serve():
    config = load_config()
    runner = pwd.getpwnam("home-mcp-runner")
    gateway = pwd.getpwnam("home-mcp")
    require(os.geteuid() == runner.pw_uid and runner.pw_uid != 0 and runner.pw_uid != gateway.pw_uid,
            "RUNNER_IDENTITY_REQUIRED")
    require(set(os.getgroups()) <= {runner.pw_gid} and os.getegid() == runner.pw_gid, "RUNNER_EXTRA_GROUPS_FORBIDDEN")
    ensure_host_layout(config)
    # Fail startup if the kernel / AppArmor / bubblewrap policy cannot actually run.
    # This probe does not modify the workspace. Never replace it with host execution.
    probe = await execute(config, {"operation": "terminal_run", "arguments": {"command": "/usr/bin/true", "timeout_seconds": min(5, config.timeout)}})
    require(probe.get("ok") is True, "SANDBOX_PREFLIGHT_FAILED")
    require(os.environ.get("LISTEN_PID") == str(os.getpid()) and os.environ.get("LISTEN_FDS") == "1", "SYSTEMD_SOCKET_REQUIRED")
    listener = socket.socket(fileno=3)
    require(listener.family == socket.AF_UNIX, "UNIX_SOCKET_REQUIRED")
    listener.setblocking(False)
    slot = asyncio.Semaphore(1)

    async def handle(reader, writer):
        identifier = uuid.uuid4().hex
        task = disconnected = None
        operation = "unknown"
        acquired = False
        try:
            connection = writer.get_extra_info("socket")
            _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == gateway.pw_uid, "RUNNER_PEER_REJECTED")
            request = await asyncio.wait_for(read_frame(reader), 10)
            require(isinstance(request, dict), "INVALID_RUNNER_REQUEST")
            operation = request.get("operation", "unknown")
            if operation == "workspace_status":
                ensure_host_layout(config)
                await write_frame(writer, {"ok": True, "phase": 1, "workspace": WORKSPACE,
                    "protected": [SOURCE], "read_only_paths": list(config.read_only), "root_available": False,
                    "network": "disabled", "max_command_seconds": config.timeout, "sandbox_startup_probe": "passed"})
                return
            try:
                await asyncio.wait_for(slot.acquire(), 0.2)
                acquired = True
            except asyncio.TimeoutError:
                raise PolicyError("RUNNER_BUSY") from None
            task = asyncio.create_task(execute(config, request))
            # A cancelled MCP call must not silently become a detached command.
            disconnected = asyncio.create_task(reader.read(1))
            completed, _ = await asyncio.wait({task, disconnected}, return_when=asyncio.FIRST_COMPLETED)
            if disconnected in completed:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                return
            result = await task
            await write_frame(writer, {**result, "request_id": identifier})
            print(json.dumps({"event": "operation", "id": identifier, "operation": operation, "ok": result.get("ok", False)}), flush=True)
        except (PolicyError, OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
            code = str(exc) if isinstance(exc, PolicyError) else "RUNNER_REQUEST_FAILED"
            try:
                await write_frame(writer, {"ok": False, "error": code, "request_id": identifier})
            except (OSError, ConnectionError):
                pass
            print(json.dumps({"event": "operation_error", "id": identifier, "code": code}), flush=True)
        finally:
            for active in (task, disconnected):
                if active is not None and not active.done():
                    active.cancel()
            await asyncio.gather(*(active for active in (task, disconnected) if active is not None), return_exceptions=True)
            if acquired:
                slot.release()
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    server = await asyncio.start_unix_server(handle, sock=listener)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    os.umask(0o077)
    asyncio.run(serve())
