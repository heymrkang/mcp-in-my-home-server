"""Offline helper cases only. These do not certify a host installation."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from installer.common import InstallError, ENV
from installer.dependencies import lock_wheels
from installer.proxy import nginx_config, valid_origin, inspect_proxy

class InstallerHelpers(unittest.TestCase):
    def test_origin_rejects_credentials_paths_and_injection(self):
        for value in ['http://example.com', 'https://u:p@example.com', 'https://example.com/path',
                      'https://example.com?x=1', 'https://example.com#x', 'https://example.com:444',
                      'https://example.com;return 200;']:
            with self.subTest(value=value), self.assertRaises((InstallError, ValueError)):
                valid_origin(value)
        self.assertEqual(valid_origin('https://mcp.example.com'), 'mcp.example.com')

    def test_relay_has_no_retries_and_separate_owner_route(self):
        config = nginx_config('mcp.example.com')
        self.assertIn('server unix:/run/home-mcp-http/gateway.sock', config)
        self.assertIn('server unix:/run/home-mcp-http/owner.sock', config)
        self.assertIn('location ^~ /approval/', config)
        self.assertIn('proxy_next_upstream off', config)
        self.assertIn('access_log off', config)
        self.assertIn('listen 8080', config)
        for directive in ('client_body_temp_path', 'proxy_temp_path', 'fastcgi_temp_path',
                          'uwsgi_temp_path', 'scgi_temp_path'):
            self.assertIn(directive + ' /tmp/', config)
        self.assertNotIn('/var/cache/nginx', config)
        self.assertNotIn('listen 443', config)
        self.assertNotIn('docker.sock', config)
        self.assertEqual(ENV['DOCKER_HOST'], 'unix:///var/run/docker.sock')

    def test_wheel_hash_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            wheel = Path(folder) / 'mcp-1.30.0-py3-none-any.whl'
            with zipfile.ZipFile(wheel, 'w') as archive:
                archive.writestr('mcp-1.30.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: mcp\nVersion: 1.30.0\n')
            rows = lock_wheels(folder)
            self.assertEqual(rows[0]['name'], 'mcp')
            self.assertEqual(rows[0]['sha256'], hashlib.sha256(wheel.read_bytes()).hexdigest())
            (Path(folder) / 'package.tar.gz').write_bytes(b'not a wheel')
            with self.assertRaises(InstallError): lock_wheels(folder)

    def test_missing_mcp_wheel_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(InstallError): lock_wheels(folder)

if __name__ == '__main__':
    unittest.main()
