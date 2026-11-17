"""Unprivileged bubblewrap executor. No unsafe host-command fallback."""
from __future__ import annotations

import asyncio
import ctypes
import errno
import os
import signal
import stat
import tempfile
from pathlib import Path

from .config import Config, INSTALL, PolicyError, SOURCE, WORKSPACE, require, within

OPERATIONS = {"files_list", "files_read", "files_write", "files_mkdir", "terminal_run"}


def seccomp_file():
    # Block socket access as well as networking: a read-only bind containing a
    # Docker/other UNIX socket must not become a host-control side channel.
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
    context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW; architecture validation is included.
    require(bool(context), "SECCOMP_UNAVAILABLE")
    output = tempfile.TemporaryFile()
    try:
        names = ["socket", "socketpair", "connect", "sendto", "sendmsg", "sendmmsg", "io_uring_setup",
                 "mount", "umount2", "pivot_root", "unshare", "setns", "ptrace", "process_vm_readv",
                 "process_vm_writev", "bpf", "perf_event_open", "keyctl", "add_key", "request_key",
                 "open_by_handle_at", "name_to_handle_at", "kexec_load", "kexec_file_load", "reboot",
                 "init_module", "finit_module", "delete_module", "userfaultfd"]
        for name in names:
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number == -1:
                continue
            require(lib.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM, number, 0, None) == 0,
                    "SECCOMP_RULE_FAILED")
        require(lib.seccomp_export_bpf(context, output.fileno()) == 0, "SECCOMP_EXPORT_FAILED")
        output.seek(0)
        return output
    except BaseException:
        output.close()
        raise
    finally:
        lib.seccomp_release(context)


def mounts_below_workspace() -> bool:
    # Explicitly refuse inherited nested host mounts rather than accidentally
    # making another host filesystem writable through the workspace bind.
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        mount = fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
        if mount != WORKSPACE and within(WORKSPACE, mount):
            return True
    return False


def ensure_host_layout(config: Config) -> None:
    require(os.geteuid() != 0, "ROOT_RUNNER_FORBIDDEN")
    for folder in (WORKSPACE, SOURCE):
        require(os.path.isdir(folder) and os.path.realpath(folder) == folder, "WORKSPACE_OR_SOURCE_MISSING")
    require(not mounts_below_workspace(), "NESTED_WORKSPACE_MOUNT_REJECTED")
    for filename in (INSTALL + "/app/homemcp/operation.py", INSTALL + "/empty", "/usr/bin/bwrap"):
        info = os.stat(filename)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "RUNTIME_NOT_ADMIN_OWNED")
    for item in config.read_only:
        actual = os.path.realpath(item)
        require(os.path.exists(item) and (actual == item or item in {"/etc/os-release", "/etc/hostname"}), "READ_SOURCE_SYMLINK_REJECTED")
        require(os.path.isfile(actual) or os.path.isdir(actual), "READ_SOURCE_INVALID")


def command(config: Config, seccomp_fd: int) -> list[str]:
    ensure_host_layout(config)
    args = ["/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns", "--assert-userns-disabled",
            "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv",
            "--ro-bind", "/usr", "/usr"]
    for root in ("/bin", "/sbin", "/lib", "/lib64"):
        if os.path.islink(root):
            require(within("/usr", os.path.realpath(root)), "RUNTIME_LINK_REJECTED")
            args += ["--symlink", os.readlink(root), root]
        elif os.path.isdir(root):
            args += ["--ro-bind", root, root]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/tmp/home", "--dir", "/etc"]
    if os.path.isfile("/etc/ld.so.cache"):
        args += ["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"]
    args += ["--bind", WORKSPACE, WORKSPACE, "--ro-bind", INSTALL + "/empty", SOURCE]
    for item in config.read_only:
        args += ["--ro-bind", os.path.realpath(item), item]
    args += ["--ro-bind", INSTALL + "/app/homemcp/operation.py", "/.home-mcp-operation.py",
             "--remount-ro", "/", "--chdir", WORKSPACE,
             "--setenv", "HOME_MCP_SANDBOX", "1", "--setenv", "HOME", "/tmp/home",
             "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8",
             "--seccomp", str(seccomp_fd), "--", "/usr/bin/python3", "-I", "-S", "-B", "/.home-mcp-operation.py"]
    return args


async def execute(config: Config, request: dict) -> dict:
    import json
    require(set(request) == {"operation", "arguments"} and request["operation"] in OPERATIONS
            and isinstance(request["arguments"], dict), "INVALID_RUNNER_REQUEST")
    operation, params = request["operation"], request["arguments"]
    timeout = params.get("timeout_seconds", config.timeout) if operation == "terminal_run" else 15
    require(type(timeout) is int and 1 <= timeout <= config.timeout, "INVALID_TIMEOUT")
    output_limit = config.output_limit if operation == "terminal_run" else 512 * 1024
    data = json.dumps({**request, "read_only": list(config.read_only)}, ensure_ascii=False).encode()
    require(len(data) <= 2 * 1024 * 1024, "REQUEST_TOO_LARGE")
    process = None
    with seccomp_file() as rules:
        try:
            process = await asyncio.create_subprocess_exec(*command(config, rules.fileno()),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, pass_fds=(rules.fileno(),),
                start_new_session=True, close_fds=True)
            captured = {"stdout": bytearray(), "stderr": bytearray()}
            truncated = {"stdout": False, "stderr": False}
            async def drain(name, pipe):
                while chunk := await pipe.read(8192):
                    room = max(0, output_limit - len(captured[name]))
                    captured[name].extend(chunk[:room])
                    if len(chunk) > room:
                        truncated[name] = True
            async def work():
                readers = [asyncio.create_task(drain("stdout", process.stdout)), asyncio.create_task(drain("stderr", process.stderr))]
                try:
                    process.stdin.write(data)
                    await process.stdin.drain()
                    process.stdin.close()
                    await process.wait()
                    await asyncio.gather(*readers)
                finally:
                    for task in readers:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*readers, return_exceptions=True)
            timed_out = False
            try:
                await asyncio.wait_for(work(), timeout)
            except asyncio.TimeoutError:
                timed_out = True
            if timed_out:
                return {"ok": False, "error": "COMMAND_TIMEOUT", "effects_may_have_occurred": True,
                        "stdout": captured["stdout"].decode("utf-8", "replace")}
            if operation == "terminal_run":
                return {"ok": process.returncode == 0, "exit_code": process.returncode,
                        "stdout": captured["stdout"].decode("utf-8", "replace"),
                        "stderr": captured["stderr"].decode("utf-8", "replace"), "truncated": truncated,
                        "network": "disabled", "root": False}
            require(process.returncode == 0 and not truncated["stdout"], "SANDBOX_OR_FILE_OPERATION_FAILED")
            result = json.loads(captured["stdout"])
            require(isinstance(result, dict) and isinstance(result.get("ok"), bool), "INVALID_WORKER_RESPONSE")
            return result
        except (FileNotFoundError, PermissionError):
            raise PolicyError("SANDBOX_UNAVAILABLE") from None
        finally:
            if process is not None:
                # A timeout/disconnect is NOT a rollback. Kill the namespace init as
                # well as the process group so daemonized descendants cannot survive.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if process.returncode is None:
                    process.kill()
                await process.wait()
