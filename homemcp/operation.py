"""Runs ONLY inside the filesystem/network sandbox. Standard-library only."""
import fcntl
import hashlib
import json
import os
import re
import stat
import sys

ROOT = "/mnt/storage/dev"
PROTECTED = ROOT + "/server"
MAX_FILE = 1024 * 1024


class Denied(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Denied(code)


def inside(root, path):
    return path == root or path.startswith(root + "/")


def target(value, reads, writing=False):
    need(isinstance(value, str) and 0 < len(value) <= 4096 and not any(c in value for c in "\x00\r\n"), "INVALID_PATH")
    need(".." not in value.split("/"), "PATH_TRAVERSAL_REJECTED")
    path = os.path.normpath(value if value.startswith("/") else ROOT + "/" + value)
    need(not inside(PROTECTED, path), "MCP_SOURCE_PROTECTED")
    need(inside(ROOT, path) or (not writing and any(inside(item, path) for item in reads)), "PATH_NOT_ALLOWED")
    return path


def directory(path):
    """Walk using directory descriptors; never follow a link during the traversal."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.strip("/").split("/"):
            if not component:
                continue
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_file(path, flags):
    parent = directory(os.path.dirname(path))
    try:
        fd = os.open(os.path.basename(path), flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=parent)
    finally:
        os.close(parent)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise Denied("REGULAR_SINGLE_LINK_FILE_REQUIRED")
    return fd


def list_files(args, reads):
    path = target(args.get("path", "."), reads)
    limit = args.get("limit", 100)
    need(type(limit) is int and 1 <= limit <= 200, "INVALID_LIMIT")
    fd = directory(path)
    rows, truncated = [], False
    try:
        with os.scandir(fd) as entries:
            for item in entries:
                if len(rows) >= limit:
                    truncated = True
                    break
                item_path = path.rstrip("/") + "/" + item.name
                if inside(PROTECTED, item_path):
                    rows.append({"name": item.name, "type": "protected"})
                    continue
                info = item.stat(follow_symlinks=False)
                kind = "link" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "special"
                rows.append({"name": item.name, "type": kind, "bytes": info.st_size})
    finally:
        os.close(fd)
    return {"path": path, "entries": sorted(rows, key=lambda row: row["name"]), "truncated": truncated}


def read_file(args, reads):
    path = target(args.get("path"), reads)
    offset, limit = args.get("offset", 0), args.get("limit", 32768)
    need(type(offset) is int and 0 <= offset <= 1024**3 and type(limit) is int and 1 <= limit <= 65536, "INVALID_LIMIT")
    fd = open_file(path, os.O_RDONLY)
    try:
        info = os.fstat(fd)
        content = os.pread(fd, limit, offset)
        sha = hashlib.sha256(os.pread(fd, MAX_FILE + 1, 0)).hexdigest() if info.st_size <= MAX_FILE else None
        return {"path": path, "text": content.decode("utf-8", "replace"), "offset": offset,
                "next_offset": offset + len(content) if offset + len(content) < info.st_size else None,
                "bytes": info.st_size, "sha256": sha, "encoding": "UTF-8; invalid sequences replaced"}
    finally:
        os.close(fd)


def write_file(args, reads):
    path = target(args.get("path"), reads, writing=True)
    need(path != ROOT, "INVALID_FILE_PATH")
    content = args.get("content")
    need(isinstance(content, str), "TEXT_REQUIRED")
    data = content.encode("utf-8")
    need(len(data) <= MAX_FILE, "FILE_TOO_LARGE")
    expected = args.get("expected_sha256")
    need(expected is None or (isinstance(expected, str) and re.fullmatch(r"[a-f0-9]{64}", expected)), "INVALID_HASH")
    # Missing hash means CREATE ONLY. Existing contents must have been read first.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL if expected is None else os.O_RDWR
    fd = open_file(path, flags)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if expected is not None:
            existing = os.pread(fd, MAX_FILE + 1, 0)
            need(len(existing) <= MAX_FILE and hashlib.sha256(existing).hexdigest() == expected, "FILE_CHANGED_READ_AGAIN")
        # The descriptor remains pinned even if a different process renames a parent.
        os.lseek(fd, 0, os.SEEK_SET)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            need(written > 0, "WRITE_FAILED")
            view = view[written:]
        os.ftruncate(fd, len(data))
        os.fsync(fd)
        return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    finally:
        os.close(fd)


def mkdir(args, reads):
    path = target(args.get("path"), reads, writing=True)
    need(path != ROOT, "PATH_EXISTS")
    fd = directory(os.path.dirname(path))
    try:
        os.mkdir(os.path.basename(path), mode=0o750, dir_fd=fd)
    finally:
        os.close(fd)
    return {"path": path, "created": True}


def run(request):
    need(os.environ.get("HOME_MCP_SANDBOX") == "1" and os.geteuid() != 0, "SANDBOX_REQUIRED")
    operation, args, reads = request["operation"], request["arguments"], request["read_only"]
    if operation == "terminal_run":
        command = args.get("command")
        need(isinstance(command, str) and 0 < len(command) <= 16384 and "\x00" not in command, "INVALID_COMMAND")
        path = target(args.get("cwd", "."), [], writing=True)
        fd = directory(path)
        try:
            os.fchdir(fd)
        finally:
            os.close(fd)
        os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-c", command],
                  {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp/home", "TMPDIR": "/tmp",
                   "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb"})
    functions = {"files_list": list_files, "files_read": read_file, "files_write": write_file, "files_mkdir": mkdir}
    need(operation in functions, "UNKNOWN_OPERATION")
    return functions[operation](args, reads)


if __name__ == "__main__":
    try:
        payload = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
        need(len(payload) <= 2 * 1024 * 1024, "REQUEST_TOO_LARGE")
        result = {"ok": True, "result": run(json.loads(payload))}
    except Denied as exc:
        result = {"ok": False, "error": str(exc)}
    except FileExistsError:
        result = {"ok": False, "error": "PATH_EXISTS_READ_FIRST"}
    except FileNotFoundError:
        result = {"ok": False, "error": "PATH_NOT_FOUND"}
    except PermissionError:
        result = {"ok": False, "error": "PERMISSION_DENIED"}
    except (OSError, ValueError, TypeError, KeyError):
        result = {"ok": False, "error": "FILE_OPERATION_REJECTED"}
    print(json.dumps(result, ensure_ascii=False))
