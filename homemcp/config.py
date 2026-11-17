"""Load administrator-owned, non-secret policy. No tool can edit it."""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

WORKSPACE = "/mnt/storage/dev"
SOURCE = WORKSPACE + "/server"
INSTALL = "/opt/home-mcp"
STATE = "/var/lib/home-mcp/private"
SOCKET = "/run/home-mcp-runner.sock"
SCOPE = "home:tools"


class PolicyError(Exception):
    """Only short, allowlisted codes cross the tool boundary."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PolicyError(code)


def within(root: str, path: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def admin_file(path: str) -> bytes:
    resolved = Path(path).resolve(strict=True)
    require(str(resolved) == path, "CONFIG_SYMLINK_REJECTED")
    for part in (resolved, *resolved.parents):
        info = part.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, "CONFIG_NOT_ADMIN_OWNED")
    require(resolved.is_file() and resolved.stat().st_size <= 32768, "CONFIG_FILE_INVALID")
    return resolved.read_bytes()


@dataclass(frozen=True)
class Config:
    origin: str
    redirects: tuple[str, ...]
    read_only: tuple[str, ...]
    port: int = 18790
    timeout: int = 60
    output_limit: int = 65536

    @property
    def resource(self) -> str:
        return self.origin + "/mcp"

    @property
    def host(self) -> str:
        return urlsplit(self.origin).netloc


def load_config(path: str = "/etc/home-mcp/config.json") -> Config:
    data = json.loads(admin_file(path))
    keys = {"version", "public_origin", "workspace", "source_checkout", "listen_host", "listen_port",
            "read_only_paths", "oauth_redirect_uris", "command_timeout_seconds", "output_limit_bytes"}
    require(isinstance(data, dict) and set(data) == keys and data["version"] == 1, "CONFIG_SCHEMA_INVALID")
    require(data["workspace"] == WORKSPACE and data["source_checkout"] == SOURCE, "WORKSPACE_POLICY_FIXED")
    require(data["listen_host"] == "127.0.0.1", "PUBLIC_BIND_FORBIDDEN")
    origin = data["public_origin"]
    url = urlsplit(origin)
    require(url.scheme == "https" and bool(url.hostname) and not url.username and not url.password
            and not url.query and not url.fragment and url.path == "" and url.port in (None, 443), "HTTPS_ORIGIN_REQUIRED")
    redirects = data["oauth_redirect_uris"]
    require(isinstance(redirects, list) and 1 <= len(redirects) <= 8, "REDIRECT_LIST_INVALID")
    for redirect in redirects:
        target = urlsplit(redirect)
        require(target.scheme == "https" and target.hostname == "chatgpt.com" and target.port in (None, 443)
                and not target.username and not target.password and not target.query and not target.fragment
                and (target.path == "/connector_platform_oauth_redirect" or target.path.startswith("/connector/oauth/")),
                "REDIRECT_REJECTED")
    reads = data["read_only_paths"]
    require(isinstance(reads, list) and len(reads) <= 16, "READ_PATHS_INVALID")
    for item in reads:
        require(isinstance(item, str) and item.startswith("/") and os.path.normpath(item) == item
                and not any(c in item for c in "\x00\r\n"), "READ_PATH_INVALID")
        # Expose explicit data subdirectories or public configuration files, never the host root.
        require((within("/mnt/storage", item) and item != "/mnt/storage")
                or (within("/etc", item) and item != "/etc")
                or (within("/var/log", item) and item != "/var/log"), "READ_PATH_TOO_BROAD")
        forbidden = [WORKSPACE, "/etc/home-mcp", "/etc/ssh", "/etc/ssl/private", "/etc/shadow",
                     "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d"]
        require(not any(within(root, item) or within(item, root) for root in forbidden), "READ_PATH_RESERVED")
    for key, minimum, maximum in [("listen_port", 1024, 65535), ("command_timeout_seconds", 1, 60),
                                   ("output_limit_bytes", 4096, 131072)]:
        require(type(data[key]) is int and minimum <= data[key] <= maximum, "CONFIG_LIMIT_INVALID")
    return Config(origin, tuple(redirects), tuple(reads), data["listen_port"],
                  data["command_timeout_seconds"], data["output_limit_bytes"])
