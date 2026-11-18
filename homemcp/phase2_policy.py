"""Administrator-owned targets. Approval cannot broaden this policy."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
import re
import socket
from .config import INSTALL, SOURCE, WORKSPACE, admin_file, require, within

BROKER_SOCKET = "/run/home-mcp-broker.sock"
BROKER_STATE = "/var/lib/home-mcp-broker"
OWNER_STATE = "/var/lib/home-mcp-owner/private"
RUNNER_STATE = "/var/lib/home-mcp-runner"
PROTECTED = (SOURCE, INSTALL, "/etc/home-mcp", "/var/lib/home-mcp", BROKER_STATE,
             "/var/lib/home-mcp-owner", RUNNER_STATE, "/var/lib/home-mcp-installer", "/var/lib/home-mcp-network",
             "/usr/local/sbin/home-mcp", "/root", "/proc", "/sys", "/dev", "/run",
             "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/ssl/private",
             "/etc/systemd", "/usr/lib/systemd", "/lib/systemd")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def request_key(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value), "REQUEST_KEY_REQUIRED")
    return value


def task_arguments(value, maximum):
    require(isinstance(value, dict) and set(value) <= {"command", "cwd", "timeout_seconds"}, "INVALID_TASK")
    command = value.get("command")
    require(isinstance(command, str) and 0 < len(command) <= 16384 and "\0" not in command, "INVALID_COMMAND")
    cwd = value.get("cwd", ".")
    require(isinstance(cwd, str) and 0 < len(cwd) <= 4096 and ".." not in cwd.split("/")
            and not any(c in cwd for c in "\0\r\n"), "INVALID_CWD")
    cwd = os.path.normpath(cwd if cwd.startswith("/") else WORKSPACE + "/" + cwd)
    require(within(WORKSPACE, cwd), "WORKSPACE_PATH_REQUIRED")
    timeout = value.get("timeout_seconds", min(1800, maximum))
    require(type(timeout) is int and 1 <= timeout <= maximum, "INVALID_TIMEOUT")
    return {"command": command, "cwd": cwd, "timeout_seconds": timeout}


def load_policy(path="/etc/home-mcp/phase2.json"):
    # Only the local installer supplies a candidate path; runtime uses the fixed default.
    p = json.loads(admin_file(path))
    keys = {"version", "task_timeout_seconds", "max_active_tasks", "log_limit_bytes", "request_ttl_seconds",
            "approval_ttl_seconds", "owner_port", "docker_targets", "systemd_units", "external_files", "egress_hosts"}
    require(isinstance(p, dict) and set(p) == keys and p["version"] == 1, "PHASE2_POLICY_INVALID")
    for key, low, high in (("task_timeout_seconds", 60, 86400), ("max_active_tasks", 1, 4),
                           ("log_limit_bytes", 4096, 131072), ("request_ttl_seconds", 60, 3600),
                           ("approval_ttl_seconds", 30, 600), ("owner_port", 1024, 65535)):
        require(type(p[key]) is int and low <= p[key] <= high, "PHASE2_LIMIT_INVALID")
    for key in ("docker_targets", "systemd_units", "external_files", "egress_hosts"):
        require(isinstance(p[key], list) and len(p[key]) <= 64, "PHASE2_TARGETS_INVALID")
    require(all(isinstance(x, str) and re.fullmatch(r"[a-f0-9]{64}", x) for x in p["docker_targets"]), "FULL_CONTAINER_ID_REQUIRED")
    require(all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", x)
                and not x.startswith(("home-mcp", "dbus", "systemd-", "polkit")) for x in p["systemd_units"]), "SERVICE_TARGET_REJECTED")
    seen = set()
    for row in p["external_files"]:
        require(isinstance(row, dict) and set(row) == {"path", "as_root"} and type(row["as_root"]) is bool, "FILE_POLICY_INVALID")
        path = row["path"]
        require(isinstance(path, str) and path.startswith("/") and path == os.path.normpath(path)
                and len(path) <= 4096 and not any(c in path for c in "\0\r\n"), "FILE_POLICY_INVALID")
        # Unit definitions and network gate/installer state are execution policy,
        # not editable application data. An approval cannot authorize self-modification.
        require(not within(WORKSPACE, path) and not any(within(x, path) or within(path, x) for x in PROTECTED), "FILE_POLICY_PROTECTED")
        require(path not in seen, "DUPLICATE_FILE_POLICY")
        seen.add(path)
    require(all(isinstance(x, str) and len(x) <= 253 and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", x)
                and "." in x and not x.endswith((".local", ".localhost", ".internal")) for x in p["egress_hosts"]), "EGRESS_HOST_INVALID")
    return p


def public_addresses(hosts):
    result = {}
    for host in hosts:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        require(0 < len(addresses) <= 16, "EGRESS_DNS_INVALID")
        for value in addresses:
            ip = ipaddress.ip_address(value)
            require(ip.is_global and not ip.is_multicast and not ip.is_unspecified
                    and not getattr(ip, "ipv4_mapped", None), "EGRESS_PRIVATE_ADDRESS_REJECTED")
        result[host] = addresses
    return result


def normalize(action, args, policy):
    require(isinstance(args, dict), "INVALID_ADMIN_ARGUMENTS")
    if action.startswith("docker."):
        require(action in {"docker.inspect", "docker.logs", "docker.start", "docker.stop", "docker.restart", "docker.remove"}, "ADMIN_ACTION_REJECTED")
        require(set(args) <= {"container_id", "tail"} and args.get("container_id") in policy["docker_targets"], "CONTAINER_NOT_REGISTERED")
        value = {"container_id": args["container_id"]}
        if action == "docker.logs":
            tail = args.get("tail", 100)
            require(type(tail) is int and 1 <= tail <= 200, "INVALID_LOG_LIMIT")
            value["tail"] = tail
        else:
            require("tail" not in args, "INVALID_ADMIN_ARGUMENTS")
        return value
    if action.startswith("service."):
        require(action in {"service.status", "service.start", "service.stop", "service.restart"}
                and set(args) == {"unit"} and args["unit"] in policy["systemd_units"], "SERVICE_NOT_REGISTERED")
        return {"unit": args["unit"]}
    if action in {"file.read", "file.write"}:
        allowed = {"path"} if action == "file.read" else {"path", "content", "expected_sha256"}
        require(set(args) == allowed, "INVALID_ADMIN_ARGUMENTS")
        target = next((row for row in policy["external_files"] if row["path"] == args["path"]), None)
        require(target is not None, "FILE_NOT_REGISTERED")
        if action == "file.write":
            require(isinstance(args["content"], str) and len(args["content"].encode()) <= 65536, "FILE_TOO_LARGE")
            require(isinstance(args["expected_sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", args["expected_sha256"]), "CURRENT_FILE_HASH_REQUIRED")
        return {**args, "as_root": target["as_root"]}
    if action == "network.run":
        require(set(args) <= {"command", "cwd", "timeout_seconds", "hosts"}, "INVALID_ADMIN_ARGUMENTS")
        hosts = args.get("hosts")
        require(isinstance(hosts, list) and 1 <= len(hosts) <= 8
                and all(isinstance(x, str) and x in policy["egress_hosts"] for x in hosts), "EGRESS_HOST_NOT_REGISTERED")
        task = task_arguments({key: value for key, value in args.items() if key != "hosts"}, policy["task_timeout_seconds"])
        return {**task, "hosts": sorted(set(hosts))}
    require(False, "ADMIN_ACTION_REJECTED")


def grant_scope(action, normalized):
    # Root and lifecycle operations NEVER get permanent grants.
    if action == "file.write" and normalized.get("as_root") is False:
        return {"action": action, "path": normalized["path"], "as_root": False}
    if action == "network.run":
        return {"action": action, **{key: value for key, value in normalized.items() if key != "addresses"}}
    return None
