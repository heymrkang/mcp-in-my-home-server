"""Durable task IDs; disconnected start calls never create automatic retries."""
from __future__ import annotations
import asyncio
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from .config import PolicyError, require
from .phase2_policy import RUNNER_STATE, canonical, fingerprint, request_key, task_arguments
from .sandbox import command, seccomp_file
from .process import run


def private_database(directory, name):
    root = Path(directory)
    require(root.resolve(strict=True) == root and root.stat().st_uid == os.geteuid()
            and root.stat().st_mode & 0o077 == 0, "STATE_DIRECTORY_PERMISSIONS")
    filename = root / name
    require(not filename.is_symlink(), "STATE_SYMLINK_REJECTED")
    if filename.exists():
        info = filename.stat()
        require(info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_mode & 0o077 == 0, "STATE_FILE_PERMISSIONS")
    db = sqlite3.connect(filename, isolation_level=None, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    return db

class Tasks:
    def __init__(self, config, policy, slot):
        self.config, self.policy, self.slot = config, policy, slot
        self.db = private_database(RUNNER_STATE, "tasks.sqlite3")
        self.db.executescript("""CREATE TABLE IF NOT EXISTS tasks(
          id TEXT PRIMARY KEY, request_key TEXT UNIQUE NOT NULL, signature TEXT NOT NULL,
          payload TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, started REAL,
          finished REAL, stdout TEXT NOT NULL DEFAULT '', stderr TEXT NOT NULL DEFAULT '', result TEXT);
        """)
        self.db.execute("UPDATE tasks SET status='UNKNOWN',finished=? WHERE status IN ('QUEUED','RUNNING')", (time.time(),))
        self.running = {}
        self.closed = False

    def get(self, identifier):
        require(isinstance(identifier, str) and len(identifier) <= 64, "INVALID_TASK_ID")
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (identifier,)).fetchone()
        require(row is not None, "TASK_NOT_FOUND")
        result = json.loads(row["result"]) if row["result"] else None
        if result:
            result = {key: value for key, value in result.items() if key not in {"stdout", "stderr"}}
        return {"ok": True, "task": {key: row[key] for key in ("id", "status", "created", "started", "finished", "stdout", "stderr")}, "result": result}

    def list(self):
        return {"ok": True, "tasks": [dict(row) for row in self.db.execute("SELECT id,status,created,started,finished FROM tasks ORDER BY created DESC LIMIT 50")]}

    def start(self, key, arguments):
        request_key(key)
        payload = task_arguments(arguments, self.policy["task_timeout_seconds"])
        signature = fingerprint(payload)
        old = self.db.execute("SELECT id,signature FROM tasks WHERE request_key=?", (key,)).fetchone()
        if old:
            require(old["signature"] == signature, "REQUEST_KEY_CONFLICT")
            return self.get(old["id"])
        require(not self.closed and len(self.running) < self.policy["max_active_tasks"] + 8, "TASK_QUEUE_FULL")
        require(self.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] < 10000, "TASK_RETENTION_REQUIRED")
        identifier = uuid.uuid4().hex
        self.db.execute("INSERT INTO tasks(id,request_key,signature,payload,status,created) VALUES (?,?,?,?,'QUEUED',?)", (identifier, key, signature, canonical(payload), time.time()))
        task = asyncio.create_task(self._run(identifier, payload))
        self.running[identifier] = task
        task.add_done_callback(lambda finished: self.running.pop(identifier, None))
        return self.get(identifier)

    async def _run(self, identifier, payload):
        result, status = None, "UNKNOWN"
        try:
            async with self.slot:
                self.db.execute("UPDATE tasks SET status='RUNNING',started=? WHERE id=?", (time.time(), identifier))
                last = {}
                def output(name, value, truncated):
                    now = time.monotonic()
                    if now - last.get(name, 0) >= 0.5:
                        self.db.execute(f"UPDATE tasks SET {name}=? WHERE id=?", (value, identifier))
                        last[name] = now
                data = canonical({"operation": "terminal_run", "arguments": payload, "read_only": list(self.config.read_only)}).encode()
                with seccomp_file() as rules:
                    result = await run(command(self.config, rules.fileno()), data, timeout=payload["timeout_seconds"],
                        limit=self.policy["log_limit_bytes"], on_output=output, pass_fds=(rules.fileno(),))
                status = "COMPLETED" if result["ok"] else "FAILED"
        except asyncio.CancelledError:
            status = "UNKNOWN" if self.closed else "CANCELLED"
            result = {"ok": False, "error": "RUNNER_STOPPED" if self.closed else "TASK_CANCELLED", "effects_may_have_occurred": True}
        except Exception as exc:
            result = {"ok": False, "error": str(exc) if isinstance(exc, PolicyError) else "TASK_EXECUTION_FAILED", "effects_may_have_occurred": True}
        finally:
            result = result or {"ok": False, "error": "TASK_INTERRUPTED", "effects_may_have_occurred": True}
            # Logs have their own columns; do not persist/send duplicate copies.
            summary = {key: value for key, value in result.items() if key not in {"stdout", "stderr"}}
            self.db.execute("UPDATE tasks SET status=?,finished=?,result=?,stdout=COALESCE(?,stdout),stderr=COALESCE(?,stderr) WHERE id=?",
                (status, time.time(), canonical(summary), result.get("stdout"), result.get("stderr"), identifier))

    def cancel(self, identifier):
        current = self.get(identifier)
        task = self.running.get(identifier)
        if task:
            if current["task"]["status"] == "QUEUED":
                self.db.execute("UPDATE tasks SET status='CANCELLED',finished=?,result=? WHERE id=? AND status='QUEUED'",
                    (time.time(), canonical({"ok": False, "error": "TASK_CANCELLED"}), identifier))
            task.cancel()
            return {"ok": True, "id": identifier, "status": "STOPPING", "rollback": False}
        return current

    async def close(self):
        self.closed = True
        active = list(self.running.values())
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        self.db.execute("UPDATE tasks SET status='UNKNOWN',finished=? WHERE status IN ('QUEUED','RUNNING')", (time.time(),))
        self.db.close()
