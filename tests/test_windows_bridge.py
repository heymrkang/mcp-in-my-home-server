"""Offline registration and multi-device dispatch checks for Windows outbound bridge."""
import asyncio
import json
import tempfile
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

    async def test_validation(self):
        with self.assertRaises(ValueError):
            self.hub.enroll("../evil")
        with self.assertRaises(ValueError):
            self.hub.enroll("home-desktop")


if __name__ == "__main__":
    unittest.main()
