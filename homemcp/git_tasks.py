"""Structured local Git helpers. Network Git uses a separately approved network.run."""
import re
import shlex
from .config import require


def git_arguments(arguments):
    require(isinstance(arguments, dict) and set(arguments) <= {"action", "cwd", "paths", "message", "branch"}, "INVALID_GIT_ARGUMENTS")
    action = arguments.get("action")
    argv = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "credential.helper=",
            "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never"]
    if action == "status":
        argv += ["status", "--short", "--branch"]
    elif action == "diff":
        argv += ["--no-pager", "diff", "--no-ext-diff", "--no-textconv"]
    elif action == "log":
        argv += ["--no-pager", "log", "-20", "--oneline", "--no-decorate"]
    elif action == "add":
        paths = arguments.get("paths")
        require(isinstance(paths, list) and 1 <= len(paths) <= 100 and all(isinstance(p, str) and p and not p.startswith(("/", "-"))
                and ".." not in p.split("/") and not any(c in p for c in "\0\r\n") for p in paths), "EXPLICIT_GIT_PATHS_REQUIRED")
        argv += ["--literal-pathspecs", "add", "--", *paths]
    elif action == "commit":
        message = arguments.get("message")
        require(isinstance(message, str) and 1 <= len(message) <= 4000 and "\0" not in message, "COMMIT_MESSAGE_REQUIRED")
        argv += ["-c", "commit.gpgSign=false", "commit", "--no-gpg-sign", "-m", message]
    elif action == "switch":
        branch = arguments.get("branch")
        require(isinstance(branch, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,160}", branch)
                and ".." not in branch and not branch.endswith(("/", ".lock")), "BRANCH_INVALID")
        argv += ["switch", "--", branch]
    else:
        require(False, "LOCAL_GIT_ACTION_REJECTED")
    return {"command": shlex.join(argv), "cwd": arguments.get("cwd", "."), "timeout_seconds": 120}
