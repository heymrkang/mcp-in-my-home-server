"""Root authority with distinct MCP and owner-UI peer identities."""
from __future__ import annotations
import asyncio
import os
import pwd
import signal
import socket
import struct
from .config import PolicyError, load_config, require
from .phase2_policy import fingerprint, load_policy, normalize, public_addresses
from .approval_store import Approvals
from .runner import read_frame, write_frame
from .admin_executor import execute
from .network_executor import recover_network
from .host_exec import run_host, validate_command

async def serve():
    require(os.geteuid() == 0, "ROOT_BROKER_REQUIRED")
    config = load_config()
    gateway, owner = pwd.getpwnam("home-mcp").pw_uid, pwd.getpwnam("home-mcp-owner").pw_uid
    require(gateway != owner and gateway != 0 and owner != 0, "SEPARATE_OWNER_IDENTITY_REQUIRED")
    load_policy()
    store = Approvals()
    # Root-owned markers survive request-DB/crash timing; cleanup must succeed before accepting work.
    await recover_network()
    require(os.environ.get("LISTEN_PID") == str(os.getpid()) and os.environ.get("LISTEN_FDS") == "1", "SYSTEMD_SOCKET_REQUIRED")
    listener = socket.socket(fileno=3)
    require(listener.family == socket.AF_UNIX, "UNIX_SOCKET_REQUIRED")
    listener.setblocking(False)
    running, handlers = {}, set()
    stopped = asyncio.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(name, stopped.set)

    async def work(row):
        identifier = row["id"]
        try:
            result = await execute(identifier, row["action"], row["payload"])
            store.finish(identifier, result)
        except asyncio.CancelledError:
            store.finish(identifier, {"ok": False, "error": "CANCELLED_OR_SERVICE_STOPPED", "effects_may_have_occurred": True}, "UNKNOWN" if stopped.is_set() else "CANCELLED")
        except Exception as exc:
            store.finish(identifier, {"ok": False, "error": str(exc) if isinstance(exc, PolicyError) else "ADMIN_RESULT_UNCERTAIN", "effects_may_have_occurred": True}, "UNKNOWN")
        finally:
            running.pop(identifier, None)

    async def dispatch(uid, operation, args):
        policy = load_policy()
        if uid == owner:
            if operation == "owner_list":
                return {"ok": True, "requests": store.list()}
            if operation == "owner_get":
                return {"ok": True, "request": store.get(args["id"])}
            if operation == "owner_grants":
                return {"ok": True, "grants": store.grants()}
            if operation == "owner_decide":
                return {"ok": True, "request": store.decide(args["id"], args["signature"], args["decision"], policy)}
            if operation == "owner_revoke":
                store.revoke(args["id"])
                return {"ok": True}
            require(False, "OWNER_RPC_REJECTED")
        require(uid == gateway, "BROKER_PEER_REJECTED")
        if operation == "host_run":
            validate_command(args)
            return await run_host(args)
        if operation == "admin_catalog":
            return {"ok": True, "docker_targets": policy["docker_targets"], "systemd_units": policy["systemd_units"],
                    "external_files": policy["external_files"], "egress_hosts": policy["egress_hosts"],
                    "root_shell": True, "docker_access": True, "host_run_approval": False,
                    "approval_url": config.origin + "/approval/"}
        if operation == "admin_request":
            require(set(args) == {"request_key", "action", "parameters"}, "INVALID_ADMIN_REQUEST")
            require(isinstance(args["action"], str), "INVALID_ADMIN_ACTION")
            payload = normalize(args["action"], args["parameters"], policy)
            signature = fingerprint({"action": args["action"], "payload": payload, "policy": fingerprint(policy)})
            old = store.existing(args["request_key"], signature)
            if old:
                return {"ok": True, "request": old, "approval_url": config.origin + "/approval/" + old["id"]}
            if args["action"] == "network.run":
                payload["addresses"] = await asyncio.wait_for(asyncio.to_thread(public_addresses, payload["hosts"]), 8)
            row = store.create(args["request_key"], signature, args["action"], payload, policy)
            return {"ok": True, "request": row, "approval_url": config.origin + "/approval/" + row["id"]}
        require(set(args) == {"id"}, "INVALID_ADMIN_REQUEST")
        row = store.get(args["id"])
        if operation == "admin_get":
            return {"ok": True, "request": row}
        if operation == "admin_execute":
            if row["status"] in {"RUNNING", "COMPLETED", "FAILED", "UNKNOWN", "CANCELLED"}:
                return {"ok": True, "request": row}
            require(len(running) < policy["max_active_tasks"], "ADMIN_BUSY")
            claimed = store.claim(args["id"], policy)
            running[row["id"]] = asyncio.create_task(work(claimed))
            return {"ok": True, "request": store.get(row["id"])}
        if operation == "admin_cancel":
            if row["id"] in running:
                running[row["id"]].cancel()
            else:
                store.cancel_pending(row["id"])
            return {"ok": True, "request": store.get(row["id"]), "rollback": False}
        require(False, "BROKER_OPERATION_REJECTED")

    async def handle(reader, writer):
        handlers.add(asyncio.current_task())
        try:
            connection = writer.get_extra_info("socket")
            _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid in {gateway, owner}, "BROKER_PEER_REJECTED")
            request = await asyncio.wait_for(read_frame(reader), 5)
            require(isinstance(request, dict) and set(request) == {"operation", "arguments"}
                    and isinstance(request["arguments"], dict), "INVALID_BROKER_REQUEST")
            result = await dispatch(uid, request["operation"], request["arguments"])
            await asyncio.wait_for(write_frame(writer, result), 5)
        except Exception as exc:
            try:
                await write_frame(writer, {"ok": False, "error": str(exc) if isinstance(exc, PolicyError) else "BROKER_REQUEST_FAILED"})
            except (OSError, ConnectionError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            handlers.discard(asyncio.current_task())

    server = await asyncio.start_unix_server(handle, sock=listener)
    try:
        async with server:
            await stopped.wait()
    finally:
        server.close()
        await server.wait_closed()
        for task in list(handlers):
            task.cancel()
        await asyncio.gather(*list(handlers), return_exceptions=True)
        active = list(running.values())
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        store.db.close()

if __name__ == "__main__":
    os.umask(0o077)
    asyncio.run(serve())
