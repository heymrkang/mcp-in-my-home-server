"""Unprivileged gated network worker. Executed only by an IP-filtered transient unit."""
from __future__ import annotations
import asyncio
import ctypes
import errno
import hashlib
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, "/opt/home-mcp/app")
from homemcp.config import admin_file, load_config, require
from homemcp.sandbox import command
from homemcp.process import run


def network_rules():
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.seccomp_export_bpf.restype = ctypes.c_int
    class Compare(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int), ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]
    context = lib.seccomp_init(0x7FFF0000)
    require(bool(context), "SECCOMP_UNAVAILABLE")
    output = tempfile.TemporaryFile()
    try:
        denied = ["socketpair", "io_uring_setup", "mount", "umount2", "pivot_root", "unshare", "setns",
                  "ptrace", "process_vm_readv", "process_vm_writev", "bpf", "perf_event_open", "keyctl",
                  "add_key", "request_key", "open_by_handle_at", "name_to_handle_at", "reboot", "kexec_load",
                  "kexec_file_load", "init_module", "finit_module", "delete_module", "userfaultfd"]
        for name in denied:
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number >= 0:
                require(lib.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM, number, 0, None) == 0, "SECCOMP_RULE_FAILED")
        # libseccomp permits only one comparison per argument per rule. Separate
        # LT/GT/EQ rules reject every family except Linux AF_INET(2), AF_INET6(10).
        require(socket.AF_INET == 2 and socket.AF_INET6 == 10, "SOCKET_ABI_UNSUPPORTED")
        number = lib.seccomp_syscall_resolve_name(b"socket")
        require(number >= 0, "SOCKET_FILTER_UNAVAILABLE")
        for operation, value in [(2, 2), (6, 10), *((4, x) for x in range(3, 10))]:
            comparison = Compare(0, operation, value, 0)
            require(lib.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM, number,
                    1, ctypes.byref(comparison)) == 0, "SECCOMP_RULE_FAILED")
        require(lib.seccomp_export_bpf(context, output.fileno()) == 0, "SECCOMP_EXPORT_FAILED")
        output.seek(0)
        return output
    except BaseException:
        output.close()
        raise
    finally:
        lib.seccomp_release(context)


async def main(directory):
    require(os.geteuid() != 0, "ROOT_NETWORK_PAYLOAD_FORBIDDEN")
    root = Path(directory)
    require(str(root.parent) == "/var/lib/home-mcp-network" and len(root.name) == 32
            and all(c in "0123456789abcdef" for c in root.name), "NETWORK_DIRECTORY_REJECTED")
    data = admin_file(str(root / "request.json"))
    payload = json.loads(data)
    end = time.monotonic() + 20
    while not (root / "go").exists():
        require(time.monotonic() < end, "NETWORK_FILTER_NOT_CONFIRMED")
        await asyncio.sleep(0.1)
    require(admin_file(str(root / "go")).decode() == hashlib.sha256(data).hexdigest(), "NETWORK_GATE_MISMATCH")
    config = load_config()
    with network_rules() as rules:
        argv = command(config, rules.fileno())
        marker = argv.index("--")
        argv[marker:marker] = ["--share-net", "--ro-bind", str(root / "hosts"), "/etc/hosts",
                             "--ro-bind", str(root / "nsswitch.conf"), "/etc/nsswitch.conf",
                             "--ro-bind", "/etc/ssl/certs", "/etc/ssl/certs"]
        args = {key: payload[key] for key in ("command", "cwd", "timeout_seconds")}
        result = await run(argv, json.dumps({"operation": "terminal_run", "arguments": args,
                           "read_only": list(config.read_only)}).encode(), timeout=args["timeout_seconds"],
                           limit=65536, pass_fds=(rules.fileno(),))
    print(json.dumps(result, ensure_ascii=False), flush=True)

if __name__ == "__main__":
    try:
        asyncio.run(main(sys.argv[1]))
    except Exception:
        print(json.dumps({"ok": False, "error": "NETWORK_SANDBOX_FAILED", "effects_may_have_occurred": True}), flush=True)
        sys.exit(1)
