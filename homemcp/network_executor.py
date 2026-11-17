"""A root broker creates filtered units, never executes the payload as root."""
from __future__ import annotations
import asyncio
import hashlib
import json
import os
import pwd
import shutil
from pathlib import Path
from .config import PolicyError, require
from .phase2_policy import canonical
from .process import collect, run

ROOT = Path("/var/lib/home-mcp-network")

def unit_name(identifier):
    require(len(identifier) == 32 and all(c in "0123456789abcdef" for c in identifier), "INVALID_APPROVAL_ID")
    return "home-mcp-net-" + identifier + ".service"

async def stop_unit(identifier):
    unit = unit_name(identifier)
    state = await run(["/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit], timeout=5, limit=4096)
    if state["stdout"].strip() == "not-found":
        return {"ok": True, "absent": True}
    return await run(["/usr/bin/systemctl", "--no-ask-password", "stop", unit], timeout=20, limit=4096)

async def recover_network():
    require(ROOT.resolve(strict=True) == ROOT and ROOT.stat().st_uid == 0 and not ROOT.stat().st_mode & 0o022, "NETWORK_STATE_INVALID")
    # A root-owned directory is created BEFORE systemd-run and removed only after
    # confirmed unit stop. It survives even a crash while updating the request DB.
    for directory in ROOT.iterdir():
        require(not directory.is_symlink() and directory.is_dir() and directory.stat().st_uid == 0
                and not directory.stat().st_mode & 0o022, "NETWORK_RECOVERY_ENTRY_INVALID")
        unit_name(directory.name)
        result = await stop_unit(directory.name)
        require(result["ok"], "NETWORK_CLEANUP_REQUIRED")
        shutil.rmtree(directory)

async def execute_network(identifier, payload):
    require(os.geteuid() == 0, "ROOT_BROKER_REQUIRED")
    require(ROOT.resolve(strict=True) == ROOT and ROOT.stat().st_uid == 0 and not ROOT.stat().st_mode & 0o022, "NETWORK_STATE_INVALID")
    user = pwd.getpwnam("home-mcp-runner")
    directory = ROOT / identifier
    directory.mkdir(mode=0o750)
    os.chown(directory, 0, user.pw_gid)
    # umask 0077 must not remove the worker's read/traverse permission.
    os.chmod(directory, 0o750)
    process = None
    unit = unit_name(identifier)
    def write(name, content):
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        try:
            os.fchown(descriptor, 0, user.pw_gid)
            os.fchmod(descriptor, 0o640)
            with os.fdopen(descriptor, "w", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
    try:
        request = canonical(payload)
        require(len(request.encode()) <= 32768, "NETWORK_REQUEST_TOO_LARGE")
        write("request.json", request)
        addresses = sorted({ip for ips in payload["addresses"].values() for ip in ips})
        write("hosts", "\n".join(ip + " " + host for host, ips in payload["addresses"].items() for ip in ips) + "\n")
        write("nsswitch.conf", "hosts: files\npasswd: files\ngroup: files\n")
        properties = {
            "User": user.pw_name, "Group": user.pw_name, "SupplementaryGroups": "",
            "WorkingDirectory": "/opt/home-mcp/app", "NoNewPrivileges": "yes",
            "ProtectSystem": "strict", "ReadWritePaths": "/mnt/storage/dev", "ProtectHome": "yes",
            "PrivateTmp": "yes", "PrivateDevices": "yes", "PrivateNetwork": "no",
            "CapabilityBoundingSet": "", "AmbientCapabilities": "", "KillMode": "control-group",
            "ProtectControlGroups": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
            "RestrictSUIDSGID": "yes", "RestrictRealtime": "yes", "LockPersonality": "yes",
            "IPAddressDeny": "any", "IPAddressAllow": " ".join(addresses),
            "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6", "SystemCallArchitectures": "native",
            "TasksMax": "256", "MemoryMax": "2G", "CPUQuota": "200%", "LimitFSIZE": "268435456",
            "RuntimeMaxSec": str(payload["timeout_seconds"] + 45), "TimeoutStopSec": "5", "UMask": "0077"
        }
        argv = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--unit=" + unit]
        argv += ["--property=" + key + "=" + value for key, value in properties.items()]
        argv += ["--", "/usr/bin/python3", "-I", "-S", "-B", "/opt/home-mcp/app/homemcp/network_payload.py", str(directory)]
        process = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"})
        bpftool = shutil.which("bpftool", path="/usr/sbin:/usr/bin:/sbin:/bin")
        require(bpftool is not None and os.stat(bpftool).st_uid == 0 and not os.stat(bpftool).st_mode & 0o022, "BPFTOOL_REQUIRED")
        verified = False
        for _ in range(30):
            info = await run(["/usr/bin/systemctl", "show", "--property=ControlGroup", "--value", unit], timeout=3, limit=4096)
            group = info["stdout"].strip()
            if group.startswith("/system.slice/") and ".." not in group.split("/"):
                evidence = await run([bpftool, "-j", "cgroup", "show", "/sys/fs/cgroup" + group], timeout=3, limit=16384)
                try:
                    names = {row.get("attach_type") for row in json.loads(evidence["stdout"])}
                except (ValueError, TypeError, AttributeError):
                    names = set()
                if evidence["ok"] and names & {"ingress", "cgroup_inet_ingress"} and names & {"egress", "cgroup_inet_egress"}:
                    verified = True
                    break
            require(process.returncode is None, "NETWORK_UNIT_FAILED")
            await asyncio.sleep(0.1)
        require(verified, "NETWORK_KERNEL_FILTER_UNVERIFIED")
        write("go", hashlib.sha256(request.encode()).hexdigest())
        result = await collect(process, timeout=payload["timeout_seconds"] + 35, limit=1048576)
        require(not result["truncated"]["stdout"], "NETWORK_RESULT_TOO_LARGE")
        try:
            body = json.loads(result["stdout"])
        except ValueError:
            raise PolicyError("NETWORK_RESULT_UNCERTAIN") from None
        require(isinstance(body, dict) and type(body.get("ok")) is bool, "NETWORK_RESULT_INVALID")
        return {**body, "network": "approved public IPs only", "root": False}
    finally:
        confirmed = process is None
        if process is not None:
            cleanup = asyncio.create_task(stop_unit(identifier))
            try:
                outcome = await asyncio.shield(cleanup)
                confirmed = outcome["ok"]
            finally:
                if process.returncode is None:
                    process.kill()
                await process.wait()
        if confirmed:
            shutil.rmtree(directory)
        else:
            # Retain the marker for the next startup. Never report cleanup success.
            raise PolicyError("NETWORK_CLEANUP_REQUIRED")
