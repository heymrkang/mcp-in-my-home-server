"""Root-invoked one-time setup for mobile Bearer authentication.

Keeps only a hash in gateway-readable private state and writes the raw API
key to a separate root-only recovery file. Existing OAuth secrets untouched.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
from .api_key import HASH_FILE
from .config import STATE, require

RECOVERY = Path("/var/lib/home-mcp/mobile-api-key.json")


def create():
    require(os.geteuid() == 0, "ROOT_INSTALLER_REQUIRED")
    gateway = pwd.getpwnam("home-mcp")
    parent = Path(STATE)
    require(parent.exists() and not parent.is_symlink()
            and parent.stat().st_uid == gateway.pw_uid
            and parent.stat().st_mode & 0o077 == 0, "MOBILE_KEY_STATE_INVALID")
    base = RECOVERY.parent
    require(base.exists() and not base.is_symlink() and base.stat().st_uid == 0
            and base.stat().st_mode & 0o022 == 0, "MOBILE_KEY_PARENT_INVALID")
    require(not HASH_FILE.exists() and not HASH_FILE.is_symlink()
            and not RECOVERY.exists() and not RECOVERY.is_symlink(), "MOBILE_KEY_ALREADY_INITIALIZED")
    secret = "hmcp_" + secrets.token_urlsafe(48)  # 64 URL-safe characters; 384 bits.
    raw = json.dumps({"api_key": secret, "note": "Use only in the mobile Authorization Bearer header; never send in chat/Git."}).encode() + b"\n"
    # Exclusive files: failures must not replace other credentials or overwrite keys.
    fd = os.open(RECOVERY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    value = json.dumps({"version": 1, "sha256": hashlib.sha256(secret.encode()).hexdigest()}).encode() + b"\n"
    fd = os.open(HASH_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(fd, gateway.pw_uid, gateway.pw_gid)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        pass
    print("Mobile API key created. Read /var/lib/home-mcp/mobile-api-key.json locally as root; never paste into chat.")


if __name__ == "__main__":
    os.umask(0o077)
    create()
