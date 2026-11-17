"""Fixed file executor. Broker chooses UID; stdin contains ONE approved exact file operation."""
import fcntl
import hashlib
import json
import os
import stat
import sys

MAX = 65536


def operation(value):
    path, root = value["path"], value["as_root"]
    if bool(os.geteuid() == 0) != root or not path.startswith("/") or os.path.normpath(path) != path:
        raise ValueError("FILE_IDENTITY_REJECTED")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in os.path.dirname(path).strip("/").split("/"):
            if not part:
                continue
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = following
            info = os.fstat(parent)
            # Root writes cannot traverse a directory controlled by the task user.
            if root and (info.st_uid != 0 or info.st_mode & 0o022):
                raise ValueError("ROOT_FILE_PARENT_UNTRUSTED")
        writing = value["action"] == "file.write"
        descriptor = os.open(os.path.basename(path), (os.O_RDWR if writing else os.O_RDONLY)
                             | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX:
                raise ValueError("SINGLE_REGULAR_SMALL_FILE_REQUIRED")
            if root and (info.st_uid != 0 or info.st_mode & 0o022):
                raise ValueError("ROOT_FILE_UNTRUSTED")
            fcntl.flock(descriptor, (fcntl.LOCK_EX if writing else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            before = os.pread(descriptor, MAX + 1, 0)
            if len(before) > MAX:
                raise ValueError("FILE_TOO_LARGE")
            digest = hashlib.sha256(before).hexdigest()
            if not writing:
                return {"ok": True, "path": path, "content": before.decode("utf-8"), "sha256": digest}
            if digest != value["expected_sha256"]:
                raise ValueError("FILE_CHANGED_REQUEST_AGAIN")
            data = value["content"].encode("utf-8")
            if len(data) > MAX:
                raise ValueError("FILE_TOO_LARGE")
            os.lseek(descriptor, 0, os.SEEK_SET)
            pending = memoryview(data)
            while pending:
                count = os.write(descriptor, pending)
                if count <= 0:
                    raise OSError("WRITE_FAILED")
                pending = pending[count:]
            os.ftruncate(descriptor, len(data))
            os.fsync(descriptor)
            return {"ok": True, "path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)

if __name__ == "__main__":
    os.umask(0o077)
    try:
        body = sys.stdin.buffer.read(262145)
        if len(body) > 262144:
            raise ValueError("REQUEST_TOO_LARGE")
        result = operation(json.loads(body))
    except Exception as exc:
        code = str(exc) if type(exc) is ValueError and str(exc).replace("_", "").isupper() else "HOST_FILE_OPERATION_FAILED"
        result = {"ok": False, "error": code, "effects_may_have_occurred": True}
    print(json.dumps(result, ensure_ascii=False))
