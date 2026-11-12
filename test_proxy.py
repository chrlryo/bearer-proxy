import json
import os
import threading
import unittest
import urllib.error
import urllib.parse
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import proxy


class TokenHandler(BaseHTTPRequestHandler):
    issued = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        params = urllib.parse.parse_qs(self.rfile.read(length).decode())
        if params.get("grant_type") != ["client_credentials"]:
            self._reply(400, {"error": "unsupported_grant_type"})
            return
        if params.get("client_id") != ["test-client"] or params.get("client_secret") != ["test-secret"]:
            self._reply(401, {"error": "invalid_client"})
            return
        TokenHandler.issued += 1
        self._reply(200, {"access_token": f"token-{TokenHandler.issued}", "expires_in": 3600})

    def _reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class UpstreamHandler(BaseHTTPRequestHandler):
    seen = []

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        auth = self.headers.get("Authorization", "")
        UpstreamHandler.seen.append((self.command, self.path, auth, body))
        if auth == "Bearer token-stale":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = json.dumps({"ok": True, "auth": auth, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Upstream", "yes")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle

    def log_message(self, fmt, *args):
        pass


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class BearerProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.token_url = start_server(TokenHandler)
        _, cls.upstream_url = start_server(UpstreamHandler)
        os.environ.update(
            UPSTREAM_URL=cls.upstream_url,
            OAUTH_TOKEN_URL=cls.token_url,
            OAUTH_CLIENT_ID="test-client",
            OAUTH_CLIENT_SECRET="test-secret",
            BIND_HOST="127.0.0.1",
            PORT="0",
        )
        cls.cfg = proxy.Config()
        cls.tokens = proxy.TokenManager(cls.cfg)
        cls.proxy = ThreadingHTTPServer(("127.0.0.1", 0), proxy.ProxyHandler)
        cls.proxy.cfg = cls.cfg
        cls.proxy.tokens = cls.tokens
        threading.Thread(target=cls.proxy.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.proxy.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.proxy.shutdown()

    def request(self, path, method="GET", data=None):
        req = urllib.request.Request(self.base + path, data=data, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def test_injects_bearer_token(self):
        status, headers, body = self.request("/hello?x=1")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Upstream"), "yes")
        payload = json.loads(body)
        self.assertTrue(payload["auth"].startswith("Bearer token-"))
        self.assertEqual(payload["path"], "/hello?x=1")

    def test_forwards_post_body(self):
        status, _, body = self.request("/submit", method="POST", data=b"payload=1")
        self.assertEqual(status, 200)
        command, _, _, sent = UpstreamHandler.seen[-1]
        self.assertEqual(command, "POST")
        self.assertEqual(sent, b"payload=1")

    def test_retry_on_401_with_new_token(self):
        self.tokens._token = "token-stale"
        self.tokens._expires_at = time.time() + 3600
        status, _, body = self.request("/after-expiry")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertNotEqual(payload["auth"], "Bearer token-stale")
        self.assertTrue(payload["auth"].startswith("Bearer token-"))

    def test_upstream_failure_returns_502(self):
        os.environ["UPSTREAM_URL"] = "http://127.0.0.1:1"
        self.proxy.cfg = proxy.Config()
        try:
            status, _, _ = self.request("/down")
            self.assertEqual(status, 502)
        finally:
            os.environ["UPSTREAM_URL"] = self.upstream_url
            self.proxy.cfg = proxy.Config()


if __name__ == "__main__":
    unittest.main()
