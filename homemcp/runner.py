"""Unprivileged socket-activated execution service. Detached jobs are explicit only."""
from __future__ import annotations
import asyncio
import json
import os
import pwd
import signal
import socket
import struct
import uuid
from .config import PolicyError, SOURCE, WORKSPACE, load_config, require
from .sandbox import ensure_host_layout, execute
from .phase2_policy import load_policy
from .tasks import Tasks
from .git_tasks import git_arguments

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
    config, policy = load_config(), load_policy()
    runner, gateway = pwd.getpwnam("home-mcp-runner"), pwd.getpwnam("home-mcp")
    require(os.geteuid() == runner.pw_uid and runner.pw_uid != 0 and runner.pw_uid != gateway.pw_uid, "RUNNER_IDENTITY_REQUIRED")
    require(set(os.getgroups()) <= {runner.pw_gid} and os.getegid() == runner.pw_gid, "RUNNER_EXTRA_GROUPS_FORBIDDEN")
    ensure_host_layout(config)
    probe = await execute(config, {"operation": "terminal_run", "arguments": {"command": "/usr/bin/true", "timeout_seconds": min(5, config.timeout)}})
    require(probe.get("ok") is True, "SANDBOX_PREFLIGHT_FAILED")
    require(os.environ.get("LISTEN_PID") == str(os.getpid()) and os.environ.get("LISTEN_FDS") == "1", "SYSTEMD_SOCKET_REQUIRED")
    listener = socket.socket(fileno=3)
    require(listener.family == socket.AF_UNIX, "UNIX_SOCKET_REQUIRED")
    listener.setblocking(False)
    slot = asyncio.Semaphore(policy["max_active_tasks"])
    jobs = Tasks(config, policy, slot)
    stopping = asyncio.Event()
    handlers = set()
    for name in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(name, stopping.set)

    async def handle(reader, writer):
        handler = asyncio.current_task()
        handlers.add(handler)
        identifier, operation = uuid.uuid4().hex, "unknown"
        task = disconnected = None
        acquired = False
        try:
            connection = writer.get_extra_info("socket")
            _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == gateway.pw_uid, "RUNNER_PEER_REJECTED")
            request = await asyncio.wait_for(read_frame(reader), 10)
            require(isinstance(request, dict) and set(request) == {"operation", "arguments"}
                    and isinstance(request["arguments"], dict), "INVALID_RUNNER_REQUEST")
            operation, args = request["operation"], request["arguments"]
            if operation == "workspace_status":
                ensure_host_layout(config)
                await write_frame(writer, {"ok": True, "phase": 2, "workspace": WORKSPACE, "protected": [SOURCE],
                    "read_only_paths": list(config.read_only), "root_available_in_runner": False,
                    "network": "disabled; separately approved broker jobs only", "max_command_seconds": config.timeout,
                    "max_task_seconds": policy["task_timeout_seconds"], "sandbox_startup_probe": "passed"})
                return
            if operation in {"task_start", "git_task", "task_get", "task_list", "task_cancel"}:
                if operation in {"task_start", "git_task"}:
                    require(set(args) == {"request_key", "task"}, "INVALID_TASK_REQUEST")
                    payload = git_arguments(args["task"]) if operation == "git_task" else args["task"]
                    result = jobs.start(args["request_key"], payload)
                elif operation == "task_list":
                    require(not args, "INVALID_TASK_REQUEST")
                    result = jobs.list()
                else:
                    require(set(args) == {"task_id"}, "INVALID_TASK_REQUEST")
                    result = jobs.get(args["task_id"]) if operation == "task_get" else jobs.cancel(args["task_id"])
                await write_frame(writer, result)
                return
            try:
                await asyncio.wait_for(slot.acquire(), 0.2)
                acquired = True
            except asyncio.TimeoutError:
                raise PolicyError("RUNNER_BUSY") from None
            task = asyncio.create_task(execute(config, request))
            disconnected = asyncio.create_task(reader.read(1))
            completed, _ = await asyncio.wait({task, disconnected}, return_when=asyncio.FIRST_COMPLETED)
            if disconnected in completed:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                return
            result = await task
            await write_frame(writer, {**result, "request_id": identifier})
            print(json.dumps({"event": "operation", "id": identifier, "operation": operation, "ok": result.get("ok", False)}), flush=True)
        except (PolicyError, OSError, ValueError, TypeError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
            code = str(exc) if isinstance(exc, PolicyError) else "RUNNER_REQUEST_FAILED"
            try:
                await write_frame(writer, {"ok": False, "error": code, "request_id": identifier})
            except (OSError, ConnectionError):
                pass
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
            handlers.discard(handler)

    server = await asyncio.start_unix_server(handle, sock=listener)
    try:
        async with server:
            await stopping.wait()
    finally:
        server.close()
        await server.wait_closed()
        for handler in list(handlers):
            handler.cancel()
        await asyncio.gather(*list(handlers), return_exceptions=True)
        await jobs.close()

if __name__ == "__main__":
    os.umask(0o077)
    asyncio.run(serve())
