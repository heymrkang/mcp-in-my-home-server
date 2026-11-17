"""Root-owned requests. The MCP-facing peer has no decision method."""
from __future__ import annotations
import json
import time
import uuid
from .config import require
from .phase2_policy import BROKER_STATE, canonical, fingerprint, grant_scope, request_key
from .tasks import private_database

class Approvals:
    def __init__(self):
        self.db = private_database(BROKER_STATE, "approvals.sqlite3")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, request_key TEXT UNIQUE NOT NULL,
          signature TEXT NOT NULL, action TEXT NOT NULL, payload TEXT NOT NULL, policy_hash TEXT NOT NULL,
          status TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, approved_until REAL,
          grant_id TEXT, result TEXT, finished REAL);
        CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, scope_hash TEXT UNIQUE NOT NULL,
          scope TEXT NOT NULL, policy_hash TEXT NOT NULL, created REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, request_id TEXT, event TEXT NOT NULL, created REAL NOT NULL);
        """)
        self.interrupted = [dict(row) for row in self.db.execute("SELECT id,action FROM approvals WHERE status='RUNNING'")]
        self.db.execute("UPDATE approvals SET status='UNKNOWN',finished=? WHERE status='RUNNING'", (time.time(),))

    def audit(self, identifier, event):
        self.db.execute("INSERT INTO audit(request_id,event,created) VALUES (?,?,?)", (identifier, event, time.time()))

    def get(self, identifier):
        require(isinstance(identifier, str) and len(identifier) <= 64, "INVALID_APPROVAL_ID")
        row = self.db.execute("SELECT * FROM approvals WHERE id=?", (identifier,)).fetchone()
        require(row is not None, "APPROVAL_NOT_FOUND")
        if row["status"] == "PENDING" and row["expires"] < time.time():
            self.db.execute("UPDATE approvals SET status='EXPIRED' WHERE id=? AND status='PENDING'", (identifier,))
            row = self.db.execute("SELECT * FROM approvals WHERE id=?", (identifier,)).fetchone()
        if row["status"] == "APPROVED" and (row["approved_until"] or 0) < time.time():
            self.db.execute("UPDATE approvals SET status='EXPIRED' WHERE id=? AND status='APPROVED'", (identifier,))
            row = self.db.execute("SELECT * FROM approvals WHERE id=?", (identifier,)).fetchone()
        value = dict(row)
        value["payload"] = json.loads(value["payload"])
        value["result"] = json.loads(value["result"]) if value["result"] else None
        value["can_always_allow"] = grant_scope(value["action"], value["payload"]) is not None
        return value

    def existing(self, key, signature):
        request_key(key)
        row = self.db.execute("SELECT id,signature FROM approvals WHERE request_key=?", (key,)).fetchone()
        if row:
            require(row["signature"] == signature, "REQUEST_KEY_CONFLICT")
            return self.get(row["id"])
        return None

    def create(self, key, signature, action, payload, policy):
        existing = self.existing(key, signature)
        if existing:
            return existing
        require(self.db.execute("SELECT COUNT(*) FROM approvals WHERE status IN ('PENDING','APPROVED') AND expires>?", (time.time(),)).fetchone()[0] < 64, "APPROVAL_QUEUE_FULL")
        require(self.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] < 10000, "APPROVAL_RETENTION_REQUIRED")
        identifier, now, ph = uuid.uuid4().hex, time.time(), fingerprint(policy)
        scope = grant_scope(action, payload)
        scope_hash = fingerprint(scope) if scope else None
        grant = self.db.execute("SELECT id FROM grants WHERE scope_hash=? AND policy_hash=? AND revoked=0", (scope_hash, ph)).fetchone() if scope else None
        state = "APPROVED" if grant else "PENDING"
        self.db.execute("INSERT INTO approvals(id,request_key,signature,action,payload,policy_hash,status,created,expires,approved_until,grant_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (identifier, key, signature, action, canonical(payload), ph, state, now, now + policy["request_ttl_seconds"],
                         now + policy["approval_ttl_seconds"] if grant else None, grant["id"] if grant else None))
        self.audit(identifier, "AUTO_APPROVED_SCOPED_GRANT" if grant else "REQUESTED")
        return self.get(identifier)

    def decide(self, identifier, signature, decision, policy):
        row = self.get(identifier)
        require(row["status"] == "PENDING" and row["signature"] == signature and row["policy_hash"] == fingerprint(policy), "APPROVAL_STALE")
        require(decision in {"allow", "deny", "always"}, "INVALID_DECISION")
        scope = grant_scope(row["action"], row["payload"])
        require(decision != "always" or scope is not None, "PERMANENT_ROOT_GRANT_FORBIDDEN")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            grant_id = None
            if decision == "always":
                scope_hash = fingerprint(scope)
                existing = self.db.execute("SELECT id,revoked FROM grants WHERE scope_hash=?", (scope_hash,)).fetchone()
                if not existing or existing["revoked"]:
                    require(self.db.execute("SELECT COUNT(*) FROM grants WHERE revoked=0").fetchone()[0] < 16, "REVOKE_UNUSED_GRANT_FIRST")
                grant_id = existing["id"] if existing else uuid.uuid4().hex
                self.db.execute("INSERT INTO grants(id,scope_hash,scope,policy_hash,created) VALUES (?,?,?,?,?) ON CONFLICT(scope_hash) DO UPDATE SET revoked=0,policy_hash=excluded.policy_hash,created=excluded.created",
                                (grant_id, scope_hash, canonical(scope), row["policy_hash"], time.time()))
            changed = self.db.execute("UPDATE approvals SET status=?,approved_until=?,grant_id=? WHERE id=? AND status='PENDING' AND expires>?",
                ("DENIED" if decision == "deny" else "APPROVED", time.time() + policy["approval_ttl_seconds"], grant_id, identifier, time.time())).rowcount
            require(changed == 1, "APPROVAL_STALE")
            self.audit(identifier, decision.upper())
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return self.get(identifier)

    def claim(self, identifier, policy):
        row = self.get(identifier)
        require(row["status"] == "APPROVED" and row["policy_hash"] == fingerprint(policy), "OWNER_APPROVAL_REQUIRED")
        if row["grant_id"]:
            require(self.db.execute("SELECT id FROM grants WHERE id=? AND revoked=0 AND policy_hash=?", (row["grant_id"], row["policy_hash"])).fetchone(), "GRANT_REVOKED")
        require(self.db.execute("UPDATE approvals SET status='RUNNING' WHERE id=? AND status='APPROVED' AND approved_until>?", (identifier, time.time())).rowcount == 1, "APPROVAL_ALREADY_CONSUMED")
        self.audit(identifier, "EXECUTION_STARTED")
        return row

    def finish(self, identifier, result, status=None):
        state = status or ("COMPLETED" if result.get("ok") else "FAILED")
        self.db.execute("UPDATE approvals SET status=?,result=?,finished=? WHERE id=? AND status='RUNNING'", (state, canonical(result), time.time(), identifier))
        self.audit(identifier, state)

    def cancel_pending(self, identifier):
        self.get(identifier)
        self.db.execute("UPDATE approvals SET status='CANCELLED',finished=? WHERE id=? AND status IN ('PENDING','APPROVED')", (time.time(), identifier))
        self.audit(identifier, "CANCEL_REQUESTED")

    def list(self):
        # Summary only: fifty file contents/logs must not overflow the IPC frame.
        ids = [row[0] for row in self.db.execute("SELECT id FROM approvals ORDER BY created DESC LIMIT 50")]
        result = []
        for identifier in ids:
            row = self.get(identifier)
            result.append({key: row[key] for key in ("id", "action", "status", "created", "expires", "approved_until")})
        return result

    def grants(self):
        return [{**dict(row), "scope": json.loads(row["scope"])} for row in self.db.execute("SELECT * FROM grants WHERE revoked=0 ORDER BY created DESC LIMIT 16")]

    def revoke(self, identifier):
        self.db.execute("UPDATE grants SET revoked=1 WHERE id=?", (identifier,))
        self.db.execute("UPDATE approvals SET status='CANCELLED',finished=? WHERE grant_id=? AND status='APPROVED'", (time.time(), identifier))
        self.audit(None, "GRANT_REVOKED")
