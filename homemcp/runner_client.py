"""Gateway -> runner IPC. Close the connection on cancellation; never replay commands."""
import asyncio
import json
import struct

from .config import PolicyError, SOCKET, require


async def call(operation: str, arguments: dict) -> dict:
    writer = None
    try:
        async with asyncio.timeout(75):
            reader, writer = await asyncio.open_unix_connection(SOCKET)
            body = json.dumps({"operation": operation, "arguments": arguments}, ensure_ascii=False).encode()
            require(len(body) <= 2 * 1024 * 1024, "REQUEST_TOO_LARGE")
            writer.write(struct.pack("!I", len(body)) + body)
            await writer.drain()
            length = struct.unpack("!I", await reader.readexactly(4))[0]
            require(0 < length <= 2 * 1024 * 1024, "INVALID_RUNNER_RESPONSE")
            result = json.loads(await reader.readexactly(length))
            require(isinstance(result, dict) and isinstance(result.get("ok"), bool), "INVALID_RUNNER_RESPONSE")
            return result
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        # The caller must inspect the real effects before deliberately repeating a write.
        return {"ok": False, "error": "RUNNER_CONNECTION_LOST", "effects_unknown": True, "auto_retried": False}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
