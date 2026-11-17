"""Same framed transport, separate root broker socket. No decision API exported to MCP."""
import asyncio
import os
import pwd
import socket
import struct
from .config import PolicyError, require
from .phase2_policy import BROKER_SOCKET
from .runner import read_frame, write_frame

async def call(operation, arguments):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(BROKER_SOCKET), 3)
        peer = writer.get_extra_info("socket")
        _pid, uid, _gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(uid == 0, "BROKER_IDENTITY_REJECTED")
        await asyncio.wait_for(write_frame(writer, {"operation": operation, "arguments": arguments}), 5)
        result = await asyncio.wait_for(read_frame(reader), 15)
        require(isinstance(result, dict) and type(result.get("ok")) is bool, "BROKER_RESPONSE_INVALID")
        return result
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        raise PolicyError("BROKER_CONNECTION_UNCERTAIN_USE_SAME_REQUEST_KEY") from None
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
