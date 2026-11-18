"""Offline policy/ledger cases. Never invoke Docker, systemd, network, root or a real workspace.
These tests have been written, not executed, during the implementation stage.
"""
import copy
import sqlite3
import time
import unittest
from unittest.mock import patch
from homemcp.config import PolicyError
from homemcp.phase2_policy import fingerprint, grant_scope, normalize, task_arguments
from homemcp.approval_store import Approvals
from homemcp.git_tasks import git_arguments

POLICY = {"task_timeout_seconds": 7200, "max_active_tasks": 2, "log_limit_bytes": 131072,
          "request_ttl_seconds": 600, "approval_ttl_seconds": 300, "owner_port": 18791,
          "docker_targets": ["a" * 64], "systemd_units": ["nginx.service"],
          "external_files": [{"path": "/mnt/storage/notes/file.txt", "as_root": False},
                             {"path": "/etc/example.conf", "as_root": True}],
          "egress_hosts": ["github.com"], "version": 1}

class PolicyTests(unittest.TestCase):
    def test_task_paths_and_time(self):
        self.assertEqual(task_arguments({"command": "true", "cwd": "project"}, 7200)["cwd"], "/mnt/storage/dev/project")
        for path in ("../etc", "/etc"):
            with self.subTest(path=path), self.assertRaises(PolicyError):
                task_arguments({"command": "true", "cwd": path}, 7200)
        self.assertEqual(task_arguments({"command": "true", "cwd": "server"}, 7200)["cwd"], "/mnt/storage/dev/server")
        with self.assertRaises(PolicyError):
            task_arguments({"command": "true", "timeout_seconds": 7201}, 7200)

    def test_target_registration_and_no_root_shell(self):
        for action, args in (("docker.restart", {"container_id": "b" * 64}),
                             ("service.restart", {"unit": "home-mcp.service"}),
                             ("root.exec", {"command": "id"}),
                             ("network.run", {"command": "true", "hosts": ["localhost"]})):
            with self.subTest(action=action), self.assertRaises(PolicyError):
                normalize(action, args, POLICY)

    def test_file_hash_and_grants(self):
        args = {"path": "/etc/example.conf", "content": "text", "expected_sha256": "a" * 64}
        value = normalize("file.write", args, POLICY)
        self.assertIsNone(grant_scope("file.write", value))
        args["path"] = "/mnt/storage/notes/file.txt"
        value = normalize("file.write", args, POLICY)
        self.assertEqual(grant_scope("file.write", value)["path"], args["path"])
        self.assertNotIn("content", grant_scope("file.write", value))
        args["expected_sha256"] = None
        with self.assertRaises(PolicyError):
            normalize("file.write", args, POLICY)

    def test_network_grant_is_exact_command_and_hosts(self):
        value = normalize("network.run", {"command": "git fetch", "hosts": ["github.com"]}, POLICY)
        value["addresses"] = {"github.com": ["1.1.1.1"]}
        scope = grant_scope("network.run", value)
        self.assertNotIn("addresses", scope)
        self.assertEqual(scope["command"], "git fetch")
        self.assertEqual(scope["hosts"], ["github.com"])

    def test_git_values_are_quoted(self):
        args = git_arguments({"action": "commit", "message": "a'; touch /etc/unwanted; echo '", "cwd": "p"})
        import shlex
        words = shlex.split(args["command"])
        self.assertEqual(words[-1], "a'; touch /etc/unwanted; echo '")
        for action in ("reset", "clean", "push"):
            with self.assertRaises(PolicyError):
                git_arguments({"action": action})

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.patch = patch("homemcp.approval_store.private_database", return_value=self.db)
        self.patch.start()
        self.store = Approvals()
        self.n = 0

    def tearDown(self):
        self.db.close()
        self.patch.stop()

    def request(self, action="service.restart", parameters=None):
        self.n += 1
        parameters = parameters or {"unit": "nginx.service"}
        payload = normalize(action, parameters, POLICY)
        signature = fingerprint({"action": action, "payload": payload})
        return self.store.create(str(self.n).zfill(32), signature, action, payload, POLICY)

    def test_no_approval_no_execution_and_no_repeat(self):
        row = self.request()
        with self.assertRaises(PolicyError):
            self.store.claim(row["id"], POLICY)
        self.store.decide(row["id"], row["signature"], "allow", POLICY)
        self.store.claim(row["id"], POLICY)
        with self.assertRaises(PolicyError):
            self.store.claim(row["id"], POLICY)
        self.store.finish(row["id"], {"ok": True})
        self.assertEqual(self.store.get(row["id"])["status"], "COMPLETED")

    def test_root_always_denied(self):
        row = self.request()
        with self.assertRaises(PolicyError):
            self.store.decide(row["id"], row["signature"], "always", POLICY)
        self.assertEqual(self.store.get(row["id"])["status"], "PENDING")

    def test_key_conflict_and_idempotence(self):
        row = self.request()
        self.assertEqual(self.store.existing(row["request_key"], row["signature"])["id"], row["id"])
        with self.assertRaises(PolicyError):
            self.store.existing(row["request_key"], "different")

    def test_denial_expiry_and_policy_change(self):
        row = self.request()
        self.store.decide(row["id"], row["signature"], "deny", POLICY)
        with self.assertRaises(PolicyError):
            self.store.claim(row["id"], POLICY)
        row = self.request()
        self.db.execute("UPDATE approvals SET expires=? WHERE id=?", (time.time() - 1, row["id"]))
        with self.assertRaises(PolicyError):
            self.store.decide(row["id"], row["signature"], "allow", POLICY)
        row = self.request()
        self.store.decide(row["id"], row["signature"], "allow", POLICY)
        changed = copy.deepcopy(POLICY)
        changed["systemd_units"] = []
        with self.assertRaises(PolicyError):
            self.store.claim(row["id"], changed)

    def test_exact_file_grant_and_revocation(self):
        args = {"path": "/mnt/storage/notes/file.txt", "content": "one", "expected_sha256": "a" * 64}
        row = self.request("file.write", args)
        self.store.decide(row["id"], row["signature"], "always", POLICY)
        args["content"] = "two"
        following = self.request("file.write", args)
        self.assertEqual(following["status"], "APPROVED")
        self.store.revoke(following["grant_id"])
        with self.assertRaises(PolicyError):
            self.store.claim(following["id"], POLICY)
        self.assertEqual(self.store.list()[0].keys(), {"id", "action", "status", "created", "expires", "approved_until"})

if __name__ == "__main__":
    unittest.main()
