"""Offline registration and multi-device dispatch checks for Windows outbound bridge."""
import asyncio
import json
import tempfile
import time
from unittest.mock import patch
import unittest
from pathlib import Path

from homemcp.windows_bridge import WindowsHub


class Request:
    def __init__(self, device, token, data=None):
        self.headers = {"x-windows-device": device, "authorization": "Bearer " + token}
        self._data = json.dumps(data or {}).encode()
        self.headers["content-length"] = str(len(self._data))

    async def body(self):
        return self._data


class WindowsBridgeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.hub = WindowsHub(Path(self.temp.name) / "bridge.sqlite3")
        self.home = self.hub.enroll("home-desktop")
        self.office = self.hub.enroll("office-desktop")

    def tearDown(self):
        self.temp.cleanup()

    async def test_isolation_and_dispatch(self):
        # Only the enrolled device with the correct token may fetch its own job.
        self.hub._seen("home-desktop")
        task = asyncio.create_task(
            self.hub.invoke("home-desktop", "windows_run", {"command": "hostname"}))
        await asyncio.sleep(0.1)
        unauthorized = await self.hub.poll(Request("home-desktop", self.office))
        self.assertEqual(unauthorized.status_code, 401)
        response = await self.hub.poll(Request("home-desktop", self.home))
        job = json.loads(response.body)["job"]
        self.assertEqual(job["action"], "windows_run")
        self.assertEqual(job["arguments"]["command"], "hostname")
        self.assertEqual(job["id"], job["id"].lower())
        payload = {"id": job["id"], "result": {
            "isError": False, "structuredContent": {"ok": True, "stdout": "DESKTOP"},
        }}
        denied = await self.hub.result(Request("office-desktop", self.office, payload))
        self.assertEqual(denied.status_code, 404)
        accepted = await self.hub.result(Request("home-desktop", self.home, payload))
        self.assertEqual(accepted.status_code, 200)
        value = await asyncio.wait_for(task, timeout=3)
        self.assertEqual(value["structuredContent"]["stdout"], "DESKTOP")
        result = self.hub.request_status("home-desktop", job["id"])
        self.assertEqual(result["state"], "DONE")

    async def test_offline_and_revoke(self):
        offline = await self.hub.invoke("office-desktop", "windows_info", {})
        self.assertEqual(offline["error"], "DEVICE_OFFLINE")
        self.hub.revoke("office-desktop")
        self.assertFalse(self.hub.devices()[1]["online"])
        rejected = await self.hub.poll(Request("office-desktop", self.office))
        self.assertEqual(rejected.status_code, 401)

    async def test_unicode_dispatch_and_late_result_after_timeout(self):
        # Unicode must reach the Windows poll response as valid UTF-8.
        self.hub._seen("home-desktop")
        payload_text = "ASCII 가나다 é Ω 😀"
        with patch("homemcp.windows_bridge.MAX_TOOL_WAIT", 1):
            waiting = asyncio.create_task(
                self.hub.invoke("home-desktop", "windows_files_write",
                                {"path": "C:\\\\tmp\\\\utf8.txt", "content": payload_text}))
            await asyncio.sleep(0.1)
            response = await self.hub.poll(Request("home-desktop", self.home))
            self.assertIn("charset=utf-8", response.headers["content-type"])
            job = json.loads(response.body.decode("utf-8"))
            self.assertEqual(job["job"]["arguments"]["content"], payload_text)
            timeout = await asyncio.wait_for(waiting, timeout=3)
            self.assertEqual(timeout["error"], "WINDOWS_RESULT_TIMEOUT")
            self.assertTrue(timeout["effects_unknown"])
            self.assertFalse(timeout["auto_retried"])
        identifier = job["job"]["id"]
        self.assertEqual(self.hub.request_status("home-desktop", identifier)["state"],
                         "UNKNOWN")
        result_payload = {"id": identifier, "result": {
            "isError": False, "structuredContent": {"ok": True, "content": payload_text},
        }}
        accepted = await self.hub.result(Request("home-desktop", self.home, result_payload))
        self.assertEqual(accepted.status_code, 200)
        state = self.hub.request_status("home-desktop", identifier)
        self.assertEqual(state["state"], "DONE")
        self.assertEqual(state["result"]["content"], payload_text)

    async def test_stale_running_request_reports_unknown_without_mutation(self):
        self.hub._seen("home-desktop")
        waiter = asyncio.create_task(
            self.hub.invoke("home-desktop", "windows_info", {}))
        await asyncio.sleep(0.1)
        response = await self.hub.poll(Request("home-desktop", self.home))
        identifier = json.loads(response.body)["job"]["id"]
        with self.hub._connect() as db:
            db.execute("UPDATE requests SET updated=? WHERE id=?",
                       (time.time() - 1000, identifier))
        status = self.hub.request_status("home-desktop", identifier)
        self.assertEqual(status["state"], "UNKNOWN")
        self.assertEqual(status["recorded_state"], "RUNNING")
        self.assertTrue(status["effects_unknown"])
        # The status lookup must not prevent a subsequently delivered result.
        with self.hub._connect() as db:
            state = db.execute("SELECT state FROM requests WHERE id=?",
                               (identifier,)).fetchone()["state"]
        self.assertEqual(state, "RUNNING")
        accepted = await self.hub.result(Request("home-desktop", self.home, {
            "id": identifier, "result": {
                "isError": False, "structuredContent": {"ok": True}}}))
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual((await asyncio.wait_for(waiter, timeout=2))
                         ["structuredContent"]["ok"], True)

    async def test_validation(self):
        with self.assertRaises(ValueError):
            self.hub.enroll("../evil")
        with self.assertRaises(ValueError):
            self.hub.enroll("home-desktop")


if __name__ == "__main__":
    unittest.main()
