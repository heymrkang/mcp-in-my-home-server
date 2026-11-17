"""Bounded subprocess collection with process-group cleanup and no shell wrapper."""
from __future__ import annotations
import asyncio
import os
import signal

async def collect(process, data=b"", timeout=60, limit=131072, on_output=None):
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    readers = []
    async def drain(name, stream):
        while chunk := await stream.read(8192):
            room = max(0, limit - len(buffers[name]))
            buffers[name].extend(chunk[:room])
            truncated[name] |= len(chunk) > room
            if on_output and room:
                on_output(name, bytes(buffers[name]).decode("utf-8", "replace"), truncated[name])
    async def work():
        readers.extend(asyncio.create_task(drain(name, getattr(process, name))) for name in buffers)
        try:
            if process.stdin is not None:
                process.stdin.write(data)
                try:
                    await process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                process.stdin.close()
            await process.wait()
            await asyncio.gather(*readers)
        finally:
            for task in readers:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
    timed_out = False
    try:
        await asyncio.wait_for(work(), timeout)
    except asyncio.TimeoutError:
        timed_out = True
    finally:
        # Callers launch with start_new_session=True. Never use a user supplied PID.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.returncode is None:
            process.kill()
        await process.wait()
    return {"ok": not timed_out and process.returncode == 0, "exit_code": process.returncode,
            "error": "COMMAND_TIMEOUT" if timed_out else None,
            "stdout": buffers["stdout"].decode("utf-8", "replace"),
            "stderr": buffers["stderr"].decode("utf-8", "replace"), "truncated": truncated,
            "effects_may_have_occurred": True}

async def run(argv, data=b"", timeout=60, limit=131072, on_output=None, **options):
    process = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"}, **options)
    return await collect(process, data, timeout, limit, on_output)
