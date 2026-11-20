"""PNG read operation and IPC payload regression tests (no live services needed)."""
import base64
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from homemcp import operation


def chunk(name, payload):
    return (struct.pack(">I", len(payload)) + name + payload
            + struct.pack(">I", zlib.crc32(name + payload) & 0xffffffff))


def png(width=1, height=1):
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
            + chunk(b"IEND", b""))


class ImageContentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patch_root = patch.object(operation, "ROOT", str(self.root))
        self.patch_root.start()

    def tearDown(self):
        self.patch_root.stop()
        self.tmp.cleanup()

    def test_png_roundtrip(self):
        content = png()
        (self.root / "screen.png").write_bytes(content)
        result = operation.read_image({"path": "screen.png"}, [])
        self.assertEqual(base64.b64decode(result["data"]), content)
        self.assertEqual(result["mime_type"], "image/png")
        self.assertEqual((result["width"], result["height"]), (1, 1))
        self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())

    def test_invalid_extension_signature_and_crc(self):
        (self.root / "wrong.jpg").write_bytes(png())
        with self.assertRaises(operation.Denied):
            operation.read_image({"path": "wrong.jpg"}, [])
        (self.root / "fake.png").write_bytes(b"not a png" * 10)
        with self.assertRaises(operation.Denied):
            operation.read_image({"path": "fake.png"}, [])
        tampered = bytearray(png())
        tampered[29] ^= 1
        (self.root / "broken.png").write_bytes(tampered)
        with self.assertRaises(operation.Denied):
            operation.read_image({"path": "broken.png"}, [])

    def test_size_and_dimensions(self):
        (self.root / "huge.png").write_bytes(png() + b"x" * (operation.MAX_IMAGE + 1))
        with self.assertRaises(operation.Denied):
            operation.read_image({"path": "huge.png"}, [])
        (self.root / "wide.png").write_bytes(png(width=5000, height=1))
        with self.assertRaises(operation.Denied):
            operation.read_image({"path": "wide.png"}, [])

    def test_reject_links_and_path_escape(self):
        (self.root / "screen.png").write_bytes(png())
        os.symlink(self.root / "screen.png", self.root / "link.png")
        os.link(self.root / "screen.png", self.root / "hard.png")
        for name in ("link.png", "hard.png", "../escape.png"):
            with self.assertRaises((operation.Denied, OSError)):
                operation.read_image({"path": name}, [])

    def test_argument_validation(self):
        (self.root / "screen.png").write_bytes(png())
        for args in ({}, {"path": "screen.png", "limit": 10}, {"path": 5}):
            with self.assertRaises(operation.Denied):
                operation.read_image(args, [])


if __name__ == "__main__":
    unittest.main()
