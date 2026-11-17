"""Single-owner OAuth state. Opaque tokens are stored as hashes, never raw values."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .config import Config, PolicyError, SCOPE, STATE, require


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def password_hash(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(key).decode()


def verify_password(password: str, encoded: str) -> bool:
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        return False
    try:
        algorithm, salt, expected = encoded.split("$")
        if algorithm != "scrypt":
            return False
        salt_bytes = base64.b64decode(salt, validate=True)
        expected_bytes = base64.b64decode(expected, validate=True)
        if len(salt_bytes) != 16 or len(expected_bytes) != 32:
            return False
        actual = hashlib.scrypt(password.encode(), salt=salt_bytes, n=16384, r=8, p=1,
                                dklen=32, maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(actual, expected_bytes)
    except (ValueError, TypeError):
        return False


def read_owner() -> dict:
    directory = Path(STATE)
    require(directory.resolve(strict=True) == directory, "AUTH_DIRECTORY_SYMLINK")
    info = directory.stat()
    require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, "AUTH_DIRECTORY_PERMISSIONS")
    filename = directory / "owner.json"
    require(not filename.is_symlink(), "AUTH_FILE_SYMLINK")
    info = filename.stat()
    require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0 and info.st_size <= 4096, "AUTH_FILE_PERMISSIONS")
    owner = json.loads(filename.read_text())
    require(set(owner) == {"version", "password_hash", "client_id", "client_secret_hash"}
            and owner["version"] == 1, "AUTH_BOOTSTRAP_REQUIRED")
    require(re.fullmatch(r"[a-f0-9]{64}", owner["client_secret_hash"]) is not None
            and isinstance(owner["password_hash"], str)
            and re.fullmatch(r"home-[A-Za-z0-9_-]{16,64}", owner["client_id"]) is not None,
            "AUTH_BOOTSTRAP_REQUIRED")
    return owner


class AuthStore:
    def __init__(self, filename: str, config: Config, owner: dict):
        require(not Path(filename).is_symlink(), "AUTH_DATABASE_SYMLINK")
        self.config, self.owner = config, owner
        self.db = sqlite3.connect(filename, isolation_level=None, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS rate_limits(name TEXT PRIMARY KEY, until INTEGER NOT NULL, count INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS flows(id TEXT PRIMARY KEY, payload TEXT NOT NULL,
          cookie_hash TEXT NOT NULL, csrf_hash TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS codes(hash TEXT PRIMARY KEY, payload TEXT NOT NULL,
          expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, client_id TEXT NOT NULL,
          resource TEXT NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
          kind TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS token_grant ON tokens(grant_id);
        """)

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def throttle(self, name: str, maximum: int, seconds: int) -> None:
        now = int(time.time())
        self.db.execute("DELETE FROM rate_limits WHERE until<=?", (now,))
        self.db.execute("INSERT INTO rate_limits VALUES (?,?,1) ON CONFLICT(name) DO UPDATE SET count=count+1",
                        (name, now + seconds))
        count = self.db.execute("SELECT count FROM rate_limits WHERE name=?", (name,)).fetchone()[0]
        require(count <= maximum, "AUTH_RATE_LIMIT")

    def cleanup(self) -> None:
        now = int(time.time())
        self.db.execute("DELETE FROM flows WHERE expires<=?", (now,))
        self.db.execute("DELETE FROM codes WHERE expires<=?", (now,))
        self.db.execute("DELETE FROM grants WHERE expires<=?", (now,))

    def validate_authorization(self, query: dict) -> dict:
        require(query.get("client_id") == self.owner["client_id"], "invalid_client")
        require(query.get("redirect_uri") in self.config.redirects, "invalid_redirect_uri")
        require(query.get("response_type") == "code", "unsupported_response_type")
        require(query.get("resource") == self.config.resource, "invalid_target")
        require(query.get("scope", SCOPE) == SCOPE, "invalid_scope")
        require(query.get("code_challenge_method") == "S256"
                and re.fullmatch(r"[A-Za-z0-9_-]{43}", query.get("code_challenge", "")) is not None,
                "invalid_request")
        require(1 <= len(query.get("state", "")) <= 2048, "invalid_request")
        return {key: query[key] for key in ("client_id", "redirect_uri", "resource", "code_challenge", "state")}

    def create_flow(self, query: dict) -> tuple[str, str, str]:
        payload = self.validate_authorization(query)
        self.throttle("authorize", 40, 300)
        self.cleanup()
        require(self.db.execute("SELECT COUNT(*) FROM flows").fetchone()[0] < 64, "AUTH_BUSY")
        flow, cookie, csrf = new_secret(), new_secret(), new_secret()
        self.db.execute("INSERT INTO flows VALUES (?,?,?,?,?)",
                        (flow, json.dumps(payload), digest(cookie), digest(csrf), int(time.time()) + 300))
        return flow, cookie, csrf

    def flow(self, flow: str, cookie: str, csrf: str) -> dict:
        row = self.db.execute("SELECT * FROM flows WHERE id=? AND expires>?", (flow, int(time.time()))).fetchone()
        require(row is not None and hmac.compare_digest(row["cookie_hash"], digest(cookie))
                and hmac.compare_digest(row["csrf_hash"], digest(csrf)), "AUTH_FLOW_EXPIRED")
        return json.loads(row["payload"])

    def finish_flow(self, flow: str, cookie: str, csrf: str, approved: bool) -> tuple[dict, str | None]:
        with self.transaction():
            payload = self.flow(flow, cookie, csrf)
            self.db.execute("DELETE FROM flows WHERE id=?", (flow,))
            code = new_secret() if approved else None
            if code:
                self.db.execute("INSERT INTO codes(hash,payload,expires) VALUES (?,?,?)",
                                (digest(code), json.dumps(payload), int(time.time()) + 120))
        return payload, code

    def authenticate_client(self, client_id: str, secret: str) -> None:
        require(isinstance(secret, str) and len(secret) <= 256
                and hmac.compare_digest(client_id, self.owner["client_id"])
                and hmac.compare_digest(digest(secret), self.owner["client_secret_hash"]), "invalid_client")

    def _issue(self, grant: str, expires: int) -> dict:
        now = int(time.time())
        access, refresh = new_secret(), new_secret()
        access_until = min(now + 900, expires)
        self.db.execute("INSERT INTO tokens(hash,grant_id,kind,expires) VALUES (?,?,?,?)",
                        (digest(access), grant, "access", access_until))
        self.db.execute("INSERT INTO tokens(hash,grant_id,kind,expires) VALUES (?,?,?,?)",
                        (digest(refresh), grant, "refresh", expires))
        return {"access_token": access, "token_type": "Bearer", "expires_in": access_until - now,
                "refresh_token": refresh, "scope": SCOPE}

    def exchange_code(self, data: dict) -> dict:
        require(data.get("resource") == self.config.resource, "invalid_target")
        verifier = data.get("code_verifier", "")
        require(re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) is not None, "invalid_grant")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.cleanup()
        with self.transaction():
            row = self.db.execute("SELECT * FROM codes WHERE hash=?", (digest(data.get("code", "")),)).fetchone()
            require(row is not None and not row["used"] and row["expires"] > time.time(), "invalid_grant")
            payload = json.loads(row["payload"])
            require(payload["resource"] == data["resource"] and payload["client_id"] == self.owner["client_id"]
                    and payload["redirect_uri"] == data.get("redirect_uri")
                    and hmac.compare_digest(challenge, payload["code_challenge"]), "invalid_grant")
            require(self.db.execute("SELECT COUNT(*) FROM grants WHERE revoked=0").fetchone()[0] < 32, "AUTH_GRANT_LIMIT")
            self.db.execute("UPDATE codes SET used=1 WHERE hash=?", (row["hash"],))
            grant, until = new_secret(), int(time.time()) + 30 * 86400
            self.db.execute("INSERT INTO grants(id,client_id,resource,expires) VALUES (?,?,?,?)",
                            (grant, payload["client_id"], payload["resource"], until))
            result = self._issue(grant, until)
        return result

    def refresh(self, data: dict) -> dict:
        require(data.get("resource") == self.config.resource, "invalid_target")
        require(data.get("scope", SCOPE) == SCOPE, "invalid_scope")
        replay = False
        result = None
        with self.transaction():
            row = self.db.execute("""SELECT t.*, g.resource, g.client_id, g.revoked, g.expires AS grant_expires
              FROM tokens t JOIN grants g ON g.id=t.grant_id WHERE t.hash=? AND t.kind='refresh'""",
                                  (digest(data.get("refresh_token", "")),)).fetchone()
            require(row is not None and row["resource"] == self.config.resource
                    and row["client_id"] == self.owner["client_id"] and not row["revoked"]
                    and row["expires"] > time.time(), "invalid_grant")
            if row["used"]:
                self.db.execute("UPDATE grants SET revoked=1 WHERE id=?", (row["grant_id"],))
                replay = True
            else:
                self.db.execute("UPDATE tokens SET used=1 WHERE hash=?", (row["hash"],))
                result = self._issue(row["grant_id"], row["grant_expires"])
        require(not replay, "invalid_grant")
        return result

    def access(self, token: str) -> dict | None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        row = self.db.execute("""SELECT t.expires, g.client_id, g.resource FROM tokens t
          JOIN grants g ON g.id=t.grant_id WHERE t.hash=? AND t.kind='access' AND t.used=0
          AND t.expires>? AND g.expires>? AND g.revoked=0""", (digest(token), int(time.time()), int(time.time()))).fetchone()
        if row and row["resource"] == self.config.resource and row["client_id"] == self.owner["client_id"]:
            return dict(row)
        return None

    def revoke(self, token: str) -> None:
        self.db.execute("UPDATE grants SET revoked=1 WHERE id IN (SELECT grant_id FROM tokens WHERE hash=?)", (digest(token),))
