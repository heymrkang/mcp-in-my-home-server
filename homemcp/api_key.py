"""Optional static bearer token for mobile MCP clients.

The root-only recovery file is never loaded by this module. The gateway reads
only a strict home-mcp-owned SHA256 hash. No bearer token is logged or returned.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from .config import PolicyError, STATE, require

HASH_FILE = Path(STATE) / "mobile-api-key.json"


def load_hash() -> str | None:
    if not HASH_FILE.exists() and not HASH_FILE.is_symlink():
        return None
    require(not HASH_FILE.is_symlink(), "MOBILE_KEY_SYMLINK")
    stat = HASH_FILE.stat()
    require(stat.st_uid == os.geteuid() and stat.st_mode & 0o077 == 0
            and stat.st_nlink == 1 and stat.st_size <= 2048, "MOBILE_KEY_PERMISSIONS")
    payload = json.loads(HASH_FILE.read_text())
    require(isinstance(payload, dict) and set(payload) == {"version", "sha256"}
            and payload["version"] == 1 and isinstance(payload["sha256"], str)
            and re.fullmatch(r"[a-f0-9]{64}", payload["sha256"]), "MOBILE_KEY_INVALID")
    return payload["sha256"]


def matches(token: str, stored_hash: str | None) -> bool:
    # The token is URL-safe random material of fixed prefix and bounded length.
    if not stored_hash or not isinstance(token, str) or not re.fullmatch(r"hmcp_[A-Za-z0-9_-]{64}", token):
        return False
    actual = hashlib.sha256(token.encode("ascii")).hexdigest()
    return hmac.compare_digest(actual, stored_hash)
