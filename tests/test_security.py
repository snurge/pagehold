import io
import os
import tempfile
import unittest
import urllib.parse
from email.message import Message
from pathlib import Path
from unittest import mock

import app
from security import OutboundAddressError, RateLimiter, validate_outbound_url
from service_runner import executable_path, load_environment


class OutboundPolicyTests(unittest.TestCase):
    def resolved(self, address):
        return mock.patch(
            "security.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", (address, 443))],
        )

    def test_public_address_is_allowed(self):
        with self.resolved("93.184.216.34"):
            self.assertEqual(
                validate_outbound_url("https://example.com/page"),
                "https://example.com/page",
            )

    def test_private_and_shared_addresses_require_explicit_policy(self):
        for address in ("10.0.0.8", "100.64.0.8"):
            with self.subTest(address=address), self.resolved(address):
                with self.assertRaises(OutboundAddressError):
                    validate_outbound_url("https://internal.example/")
                self.assertEqual(
                    validate_outbound_url("https://internal.example/", allow_private_networks=True),
                    "https://internal.example/",
                )

    def test_loopback_and_link_local_are_always_blocked(self):
        for address in ("127.0.0.1", "169.254.169.254", "::1"):
            with self.subTest(address=address), self.resolved(address):
                with self.assertRaises(OutboundAddressError):
                    validate_outbound_url("http://blocked.example/", allow_private_networks=True)

    def test_credentials_in_url_are_rejected(self):
        credential_url = "https" + "://user:placeholder@example.com/"
        with self.assertRaises(OutboundAddressError):
            validate_outbound_url(credential_url)


class AuthenticationSecurityTests(unittest.TestCase):
    def test_password_policy(self):
        for password in ("short", "admin123", "x" * 257):
            with self.subTest(password=password[:12]), self.assertRaises(ValueError):
                app.validate_new_password(password)
        app.validate_new_password("a suitably long password")

    def test_rate_limiter_uses_sliding_window(self):
        limiter = RateLimiter(2, 10)
        self.assertTrue(limiter.allow("client", now=0))
        self.assertTrue(limiter.allow("client", now=1))
        self.assertFalse(limiter.allow("client", now=2))
        self.assertTrue(limiter.allow("client", now=11))

    def test_production_rejects_default_secret(self):
        document = {
            "users": [{"role": "user", "password": app.hash_password("strong local password")}]
        }
        with (
            mock.patch.object(app, "PRODUCTION", True),
            mock.patch.object(app, "SECRET", "change-me-before-production"),
            mock.patch.object(app, "ALLOWED_HOSTS", {"archive.example.com"}),
            mock.patch.object(app, "BIND", "127.0.0.1"),
            self.assertRaises(RuntimeError),
        ):
            app.validate_production_configuration(document)

    def test_production_container_bind_requires_explicit_isolation_profile(self):
        document = {
            "users": [{"role": "user", "password": app.hash_password("strong local password")}]
        }
        with (
            mock.patch.object(app, "PRODUCTION", True),
            mock.patch.object(app, "SECRET", "a" * 40),
            mock.patch.object(app, "ALLOWED_HOSTS", {"archive.example.com"}),
            mock.patch.object(app, "BIND", "0.0.0.0"),
            mock.patch.object(app, "CONTAINER_NETWORK", False),
            self.assertRaises(RuntimeError),
        ):
            app.validate_production_configuration(document)
        with (
            mock.patch.object(app, "PRODUCTION", True),
            mock.patch.object(app, "SECRET", "a" * 40),
            mock.patch.object(app, "ALLOWED_HOSTS", {"archive.example.com"}),
            mock.patch.object(app, "BIND", "0.0.0.0"),
            mock.patch.object(app, "CONTAINER_NETWORK", True),
        ):
            app.validate_production_configuration(document)

    def test_csrf_token_is_injected_and_bound_to_cookie(self):
        handler = object.__new__(app.Handler)
        handler.headers = Message()
        handler.headers["Host"] = "localhost:18765"
        handler.client_address = ("127.0.0.1", 12345)
        handler.wfile = io.BytesIO()
        response_headers = []
        handler.send_response = mock.Mock()
        handler.send_header = lambda name, value: response_headers.append((name, value))
        handler.end_headers = mock.Mock()

        handler.html('<form method="post" action="/login"><button>Go</button></form>')

        body = handler.wfile.getvalue().decode("utf-8")
        self.assertIn('name="csrf_token"', body)
        cookie = next(value for name, value in response_headers if name == "Set-Cookie")
        token = urllib.parse.unquote(cookie.split(";", 1)[0].split("=", 1)[1])
        self.assertIn(token, body)


class HealthEndpointTests(unittest.TestCase):
    def test_head_health_check_has_get_headers_without_a_body(self):
        handler = object.__new__(app.Handler)
        handler.command = "HEAD"
        handler.path = "/health"
        handler.headers = Message()
        handler.headers["Host"] = "localhost:18765"
        handler.client_address = ("127.0.0.1", 12345)
        handler.wfile = io.BytesIO()
        response_headers = []
        handler.send_response = mock.Mock()
        handler.send_header = lambda name, value: response_headers.append((name, value))
        handler.end_headers = mock.Mock()
        handler.valid_request_host = mock.Mock(return_value=True)
        storage = {"ok": True, "schema_version": 12, "integrity": "ok"}

        with mock.patch.object(app.METADATA_STORE, "storage_health", return_value=storage):
            handler.do_HEAD()

        handler.send_response.assert_called_once_with(200)
        self.assertEqual(
            next(value for name, value in response_headers if name == "Content-Type"),
            "application/json",
        )
        self.assertGreater(
            int(next(value for name, value in response_headers if name == "Content-Length")),
            0,
        )
        self.assertEqual(handler.wfile.getvalue(), b"")


class ProtectedEnvironmentTests(unittest.TestCase):
    def test_environment_file_must_be_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "archive.env"
            path.write_text("WEBSNAPSHOT_ENV=production\n", encoding="utf-8")
            os.chmod(path, 0o644)
            with self.assertRaises(PermissionError):
                load_environment(path)
            os.chmod(path, 0o600)
            self.assertEqual(load_environment(path)["WEBSNAPSHOT_ENV"], "production")

    def test_executable_path_preserves_virtual_environment_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter = root / "python-real"
            interpreter.touch()
            virtual_python = root / "venv" / "bin" / "python"
            virtual_python.parent.mkdir(parents=True)
            virtual_python.symlink_to(interpreter)

            selected = executable_path(str(virtual_python))

            self.assertEqual(selected, str(virtual_python))
            self.assertNotEqual(selected, str(interpreter))


if __name__ == "__main__":
    unittest.main()
