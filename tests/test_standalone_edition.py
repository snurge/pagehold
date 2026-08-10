"""End-to-end checks for a fresh local PageHold installation."""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app.py"


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LocalInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pagehold-local-")
        self.data_dir = Path(self.temporary.name) / "data"
        self.port = unused_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.log_path = Path(self.temporary.name) / "service.log"
        self.log_file = self.log_path.open("w+", encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "WEBSNAPSHOT_DATA_DIR": str(self.data_dir),
                "WEBSNAPSHOT_BIND": "127.0.0.1",
                "PORT": str(self.port),
                "WEBSNAPSHOT_SECRET": "local-test-secret-that-is-not-production",
                "WEBSNAPSHOT_BROWSER_RENDERING": "0",
                "WEBSNAPSHOT_MIN_FREE_DISK_BYTES": "0",
            }
        )
        self.process = subprocess.Popen(
            [sys.executable, str(APP)],
            cwd=ROOT,
            env=environment,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self.wait_until_healthy()

    def tearDown(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.log_file.close()
        self.temporary.cleanup()

    def wait_until_healthy(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail(self.service_log())
            try:
                with urllib.request.urlopen(f"{self.base_url}/health", timeout=1) as response:
                    payload = json.load(response)
                self.assertEqual("local", payload["mode"])
                return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        self.fail(f"PageHold did not become healthy:\n{self.service_log()}")

    def service_log(self):
        self.log_file.flush()
        return self.log_path.read_text(encoding="utf-8")

    def request(self, path, data=None, opener=None):
        client = opener or self.opener
        encoded = urllib.parse.urlencode(data).encode("utf-8") if data is not None else None
        request = urllib.request.Request(f"{self.base_url}{path}", data=encoded)
        try:
            with client.open(request, timeout=5) as response:
                return response.status, response.geturl(), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.geturl(), exc.read().decode("utf-8")

    @staticmethod
    def csrf(body):
        match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        if not match:
            raise AssertionError("No form security token was rendered.")
        return match.group(1)

    def test_first_setup_creates_the_only_account(self):
        status, _, landing = self.request("/")
        self.assertEqual(200, status)
        self.assertIn("Set up PageHold", landing)
        self.assertIn("One local account controls the archive", landing)

        status, _, setup = self.request("/signup")
        self.assertEqual(200, status)
        status, final_url, dashboard = self.request(
            "/signup",
            {
                "csrf_token": self.csrf(setup),
                "name": "Local Owner",
                "email": "owner@example.test",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(200, status)
        self.assertTrue(final_url.endswith("/dashboard"), final_url)
        self.assertIn("Your archived sites", dashboard)

        database = sqlite3.connect(self.data_dir / "websnapshot.sqlite3")
        try:
            user = database.execute("SELECT email,role FROM users").fetchone()
            self.assertEqual(("owner@example.test", "user"), user)
            self.assertEqual(1, database.execute("SELECT COUNT(*) FROM users").fetchone()[0])
        finally:
            database.close()

        anonymous = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        status, final_url, login = self.request("/signup", opener=anonymous)
        self.assertEqual(200, status)
        self.assertTrue(final_url.startswith(f"{self.base_url}/login"), final_url)
        self.assertIn("Setup is complete", login)


if __name__ == "__main__":
    unittest.main()
