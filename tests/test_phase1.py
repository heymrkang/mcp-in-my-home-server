"""Offline unit cases. They are not substitutes for namespace/ChatGPT integration tests."""
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from homemcp.auth_store import AuthStore, digest, password_hash, verify_password
from homemcp.config import Config, PolicyError, WORKSPACE
from homemcp import operation


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = Config("https://mcp.example.invalid", ("https://chatgpt.com/connector_platform_oauth_redirect",), ())
        self.owner = {"client_id": "home-fixture000000000000", "client_secret_hash": digest("fixture-only-client-secret")}
        self.store = AuthStore(str(Path(self.temp.name) / "auth.sqlite3"), self.config, self.owner)
        self.verifier = "v" * 64
        self.challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()
        self.query = {"client_id": self.owner["client_id"], "redirect_uri": self.config.redirects[0],
                      "response_type": "code", "resource": self.config.resource, "scope": "home:tools",
                      "code_challenge_method": "S256", "code_challenge": self.challenge, "state": "fixture-state"}

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def code(self):
        flow, cookie, csrf = self.store.create_flow(self.query)
        _, code = self.store.finish_flow(flow, cookie, csrf, True)
        return {"code": code, "redirect_uri": self.query["redirect_uri"], "resource": self.config.resource,
                "code_verifier": self.verifier}

    def test_password_hash(self):
        encoded = password_hash("fixture-only-owner-password")
        self.assertTrue(verify_password("fixture-only-owner-password", encoded))
        self.assertFalse(verify_password("wrong", encoded))

    def test_client_authentication(self):
        self.store.authenticate_client(self.owner["client_id"], "fixture-only-client-secret")
        with self.assertRaises(PolicyError):
            self.store.authenticate_client(self.owner["client_id"], "wrong")

    def test_pkce_and_one_time_code(self):
        request = self.code()
        with self.assertRaises(PolicyError):
            self.store.exchange_code({**request, "code_verifier": "x" * 64})
        result = self.store.exchange_code(request)
        self.assertEqual(self.store.access(result["access_token"])["resource"], self.config.resource)
        with self.assertRaises(PolicyError):
            self.store.exchange_code(request)

    def test_token_database_has_hashes_not_bearers(self):
        result = self.store.exchange_code(self.code())
        values = [row[0] for row in self.store.db.execute("SELECT hash FROM tokens")]
        self.assertNotIn(result["access_token"], values)
        self.assertNotIn(result["refresh_token"], values)

    def test_wrong_resource(self):
        with self.assertRaises(PolicyError):
            self.store.exchange_code({**self.code(), "resource": "https://other.invalid/mcp"})

    def test_redirect_and_scope_are_not_user_expandable(self):
        for change in ({"redirect_uri": "https://attacker.invalid/callback"}, {"scope": "root"},
                       {"code_challenge_method": "plain"}):
            with self.assertRaises(PolicyError):
                self.store.create_flow({**self.query, **change})

    def test_browser_cookie_and_csrf_required(self):
        flow, cookie, csrf = self.store.create_flow(self.query)
        with self.assertRaises(PolicyError):
            self.store.finish_flow(flow, "wrong", csrf, True)
        with self.assertRaises(PolicyError):
            self.store.finish_flow(flow, cookie, "wrong", True)
        self.store.finish_flow(flow, cookie, csrf, False)
        with self.assertRaises(PolicyError):
            self.store.finish_flow(flow, cookie, csrf, True)

    def test_refresh_reuse_revokes_entire_grant(self):
        first = self.store.exchange_code(self.code())
        request = {"refresh_token": first["refresh_token"], "resource": self.config.resource}
        second = self.store.refresh(request)
        self.assertIsNotNone(self.store.access(second["access_token"]))
        with self.assertRaises(PolicyError):
            self.store.refresh(request)
        self.assertIsNone(self.store.access(first["access_token"]))
        self.assertIsNone(self.store.access(second["access_token"]))

    def test_revocation(self):
        result = self.store.exchange_code(self.code())
        self.store.revoke(result["refresh_token"])
        self.assertIsNone(self.store.access(result["access_token"]))


class PathTests(unittest.TestCase):
    def test_relative_workspace(self):
        self.assertEqual(operation.target("example.txt", []), WORKSPACE + "/example.txt")

    def test_outside_paths_and_traversal(self):
        for name in ("../etc/shadow", "/etc/shadow", "server/config.json", "a/../../escape"):
            with self.assertRaises(operation.Denied):
                operation.target(name, [])

    def test_read_permission_does_not_imply_write(self):
        self.assertEqual(operation.target("/etc/hostname", ["/etc/hostname"]), "/etc/hostname")
        with self.assertRaises(operation.Denied):
            operation.target("/etc/hostname", ["/etc/hostname"], writing=True)

    def test_file_create_edit_conflict_and_links(self):
        with tempfile.TemporaryDirectory() as root, patch.object(operation, "ROOT", root), patch.object(operation, "PROTECTED", root + "/server"):
            first = operation.write_file({"path": "a.txt", "content": "one"}, [])
            self.assertEqual(operation.read_file({"path": "a.txt"}, [])["text"], "one")
            with self.assertRaises(FileExistsError):
                operation.write_file({"path": "a.txt", "content": "overwrite"}, [])
            with self.assertRaises(operation.Denied):
                operation.write_file({"path": "a.txt", "content": "bad", "expected_sha256": "0" * 64}, [])
            operation.write_file({"path": "a.txt", "content": "two", "expected_sha256": first["sha256"]}, [])
            os.link(root + "/a.txt", root + "/hard.txt")
            with self.assertRaises(operation.Denied):
                operation.read_file({"path": "hard.txt"}, [])
            os.symlink(root + "/a.txt", root + "/link.txt")
            with self.assertRaises(OSError):
                operation.read_file({"path": "link.txt"}, [])



class MobileAPIKeyTests(unittest.TestCase):
    def test_hash_match_and_rejection(self):
        from homemcp.api_key import matches
        raw = "hmcp_" + "a" * 64
        stored = hashlib.sha256(raw.encode()).hexdigest()
        self.assertTrue(matches(raw, stored))
        self.assertFalse(matches("hmcp_" + "b" * 64, stored))
        self.assertFalse(matches("", stored))
        self.assertFalse(matches("hmcp_" + "a" * 63, stored))
        self.assertFalse(matches("any-oauth-access-token", stored))
        self.assertFalse(matches(raw, None))

    def test_missing_hash_disables_only_mobile_auth(self):
        from homemcp.api_key import load_hash
        with tempfile.TemporaryDirectory() as folder:
            with patch("homemcp.api_key.HASH_FILE", Path(folder) / "absent.json"):
                self.assertIsNone(load_hash())

    def test_invalid_hash_file_is_rejected(self):
        from homemcp.api_key import load_hash
        with tempfile.TemporaryDirectory() as folder:
            location = Path(folder) / "bad.json"
            location.write_text('{"version":1,"sha256":"invalid"}')
            location.chmod(0o600)
            with patch("homemcp.api_key.HASH_FILE", location):
                with self.assertRaises(PolicyError):
                    load_hash()

if __name__ == "__main__":
    unittest.main()
