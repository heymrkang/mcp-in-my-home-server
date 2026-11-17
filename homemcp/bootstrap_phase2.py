"""Run by the phase-3 installer AFTER creating separate service accounts. No default password."""
import json
import os
from pathlib import Path
import pwd
import secrets
from .auth_store import password_hash
from .config import require
from .phase2_policy import BROKER_STATE, OWNER_STATE, RUNNER_STATE


def directory(path, uid, gid, mode):
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True, mode=mode)
    require(target.resolve(strict=True) == target, "STATE_PATH_SYMLINK")
    # Existing non-empty directories must already belong to the intended account.
    require(target.stat().st_uid in {0, uid}, "STATE_OWNER_MISMATCH")
    os.chown(target, uid, gid)
    os.chmod(target, mode)
    return target


def main():
    require(os.geteuid() == 0, "ROOT_INSTALLER_REQUIRED")
    runner, owner = pwd.getpwnam("home-mcp-runner"), pwd.getpwnam("home-mcp-owner")
    require(len({runner.pw_uid, owner.pw_uid, pwd.getpwnam("home-mcp").pw_uid, 0}) == 4, "SERVICE_UIDS_MUST_DIFFER")
    directory(BROKER_STATE, 0, 0, 0o700)
    directory(RUNNER_STATE, runner.pw_uid, runner.pw_gid, 0o700)
    directory("/var/lib/home-mcp-network", 0, 0, 0o711)
    directory("/var/lib/home-mcp-owner", 0, 0, 0o711)
    root = directory(OWNER_STATE, owner.pw_uid, owner.pw_gid, 0o700)
    target = root / "owner.json"
    require(not target.is_symlink(), "OWNER_SECRET_SYMLINK")
    if target.exists():
        require(target.stat().st_uid == owner.pw_uid and not target.stat().st_mode & 0o077, "OWNER_SECRET_PERMISSIONS")
        print("Approval credentials preserved. No password reset performed.")
        return
    password = secrets.token_urlsafe(24)
    # Keep a root-only recovery copy before creating the nonrecoverable password hash.
    recovery = Path("/var/lib/home-mcp/phase2-setup-credentials.json")
    descriptor = os.open(recovery, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump({"approval_password": password, "note": "Enter only in the /approval/ owner page; never in chat/MCP."}, output)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.fchown(descriptor, owner.pw_uid, owner.pw_gid)
    with os.fdopen(descriptor, "w") as output:
        json.dump({"version": 1, "password_hash": password_hash(password)}, output)
        output.flush()
        os.fsync(output.fileno())
    password = ""
    print("Approval credential created outside Git. Read the root-only setup file locally, then store securely and remove it.")

if __name__ == "__main__":
    os.umask(0o077)
    main()
