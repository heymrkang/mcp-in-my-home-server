"""One-time credential creation for the phase-3 installer; never called by MCP tools."""
import json
import os
import pwd
from pathlib import Path

from .auth_store import digest, new_secret, password_hash
from .config import STATE, require


def exclusive_json(path, value, uid, gid):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        data = json.dumps(value, ensure_ascii=False, indent=2).encode() + b"\n"
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(fd)
        os.fchown(fd, uid, gid)
    finally:
        os.close(fd)


def main():
    require(os.geteuid() == 0, "BOOTSTRAP_REQUIRES_LOCAL_ADMIN")
    gateway, runner = pwd.getpwnam("home-mcp"), pwd.getpwnam("home-mcp-runner")
    require(gateway.pw_uid != 0 and runner.pw_uid != 0 and gateway.pw_uid != runner.pw_uid, "SERVICE_USERS_REQUIRED")
    base = Path("/var/lib/home-mcp")
    base.mkdir(mode=0o711, parents=False, exist_ok=True)
    require(base.resolve() == base and base.stat().st_uid == 0 and base.stat().st_mode & 0o022 == 0, "STATE_PARENT_UNSAFE")
    state = Path(STATE)
    require(not state.is_symlink(), "STATE_SYMLINK_REJECTED")
    state.mkdir(mode=0o700, exist_ok=True)
    require(not (state / "owner.json").exists() and not (base / "setup-credentials.json").exists(), "ALREADY_INITIALIZED")
    os.chmod(state, 0o700)
    os.chown(state, gateway.pw_uid, gateway.pw_gid)
    password, client_secret = new_secret(), new_secret()
    client_id = "home-" + new_secret()[:24]
    # Keep the first-login information outside the checkout, readable by root only.
    exclusive_json(str(base / "setup-credentials.json"), {"owner_password": password,
        "client_id": client_id, "client_secret": client_secret,
        "note": "관리자 비밀번호와 client_secret은 채팅/Git에 보내지 말고 안전하게 보관 후 이 파일을 삭제하세요."}, 0, 0)
    exclusive_json(str(state / "owner.json"), {"version": 1, "password_hash": password_hash(password),
        "client_id": client_id, "client_secret_hash": digest(client_secret)}, gateway.pw_uid, gateway.pw_gid)
    print("초기 인증 정보를 /var/lib/home-mcp/setup-credentials.json 에 생성했습니다. 원문을 로그로 출력하지 않습니다.")


if __name__ == "__main__":
    os.umask(0o077)
    main()
