"""Authenticated MCP root authority via the local root broker.

This tool intentionally permits arbitrary root commands and Docker access without
the separate owner web approval. No fallback from broker failure.
"""
import asyncio
import os
from pathlib import Path
import signal
import time

from .config import require

CAP = 65536


def validate_command(args):
    require(isinstance(args, dict) and set(args) <= {"command", "cwd", "timeout_seconds"}, "HOST_ARGUMENTS_INVALID")
    command, cwd, timeout = args.get("command"), args.get("cwd", "/"), args.get("timeout_seconds", 60)
    require(isinstance(command, str) and 0 < len(command) <= 16384 and "\x00" not in command,
            "HOST_COMMAND_INVALID")
    require(isinstance(cwd, str) and cwd.startswith("/") and 1 <= len(cwd) <= 4096
            and not any(x in cwd for x in ("\x00", "\n", "\r")), "HOST_CWD_INVALID")
    require(type(timeout) is int and 1 <= timeout <= 120, "HOST_TIMEOUT_INVALID")
    return command, cwd, timeout


async def run_host(args):
    command, cwd, timeout = validate_command(args)
    require(os.geteuid() == 0, "ROOT_BROKER_REQUIRED")
    require(Path(cwd).is_dir(), "HOST_CWD_INVALID")
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "HOME": "/root", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "DOCKER_HOST": "unix:///var/run/docker.sock", "GIT_TERMINAL_PROMPT": "0"}
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        "/bin/bash", "--noprofile", "--norc", "-c", command,
        cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True)
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = {"stdout": False, "stderr": False}

    async def drain(name, reader):
        while chunk := await reader.read(8192):
            room = CAP - len(streams[name])
            if len(chunk) > room:
                overflow[name] = True
            streams[name].extend(chunk[:max(0, room)])

    async def collect():
        await asyncio.gather(proc.wait(), drain("stdout", proc.stdout), drain("stderr", proc.stderr))

    timed_out = False
    try:
        await asyncio.wait_for(collect(), timeout)
    except asyncio.TimeoutError:
        timed_out = True
    finally:
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()
    return {"ok": not timed_out and proc.returncode == 0,
            "exit_code": proc.returncode, "timed_out": timed_out,
            "effects_may_have_occurred": timed_out,
            "stdout": streams["stdout"].decode("utf-8", "replace"),
            "stderr": streams["stderr"].decode("utf-8", "replace"),
            "truncated": overflow, "elapsed_seconds": round(time.monotonic() - started, 2),
            "root": True, "docker_socket": "/var/run/docker.sock"}
