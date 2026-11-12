#!/usr/bin/env python3
"""Local HTTP proxy that injects an OAuth2 Bearer token into forwarded requests.

Configuration comes from environment variables (or a local `.env` file):

    UPSTREAM_URL          Base URL of the target API (e.g. https://api.example.com)
    OAUTH_TOKEN_URL       OAuth2 token endpoint (e.g. https://auth.example.com/oauth/token)
    OAUTH_CLIENT_ID       OAuth2 client id
    OAUTH_CLIENT_SECRET   OAuth2 client secret
    OAUTH_SCOPE           Optional space-separated scopes
    OAUTH_REFRESH_TOKEN   Optional refresh token (refresh_token grant instead of client_credentials)
    OAUTH_AUTH_METHOD     How to send client credentials: "body" (default) or "basic"
    BIND_HOST             Listen address, default 127.0.0.1 (keep it local)
    PORT                  Listen port, default 8080
    UPSTREAM_TIMEOUT      Upstream timeout in seconds, default 60

The token is cached and refreshed before expiry; a 401 from the upstream
triggers a forced refresh and a single retry.
"""

import base64
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


def load_env_file(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip("'\"")
            os.environ.setdefault(key, value)


class Config:
    def __init__(self, env=None):
        env = env if env is not None else os.environ
        self.upstream = env.get("UPSTREAM_URL", "").rstrip("/")
        self.token_url = env.get("OAUTH_TOKEN_URL", "")
        self.client_id = env.get("OAUTH_CLIENT_ID", "")
        self.client_secret = env.get("OAUTH_CLIENT_SECRET", "")
        self.scope = env.get("OAUTH_SCOPE", "")
        self.refresh_token = env.get("OAUTH_REFRESH_TOKEN", "")
        self.auth_method = env.get("OAUTH_AUTH_METHOD", "body").lower()
        self.bind_host = env.get("BIND_HOST", "127.0.0.1")
        self.port = int(env.get("PORT", "8080"))
        self.timeout = int(env.get("UPSTREAM_TIMEOUT", "60"))

    def validate(self):
        missing = []
        if not self.upstream:
            missing.append("UPSTREAM_URL")
        if not self.token_url:
            missing.append("OAUTH_TOKEN_URL")
        if not self.client_id and not self.refresh_token:
            missing.append("OAUTH_CLIENT_ID or OAUTH_REFRESH_TOKEN")
        if missing:
            raise SystemExit(
                "Missing configuration: " + ", ".join(missing)
                + " (set them in the environment or in a .env file)"
            )


class TokenManager:
    def __init__(self, cfg):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._token = None
        self._expires_at = 0.0

    def get(self, force=False):
        with self._lock:
            if not force and self._token and time.time() < self._expires_at:
                return self._token
            self._fetch(force_refresh=force)
            return self._token

    def _fetch(self, force_refresh=False):
        cfg = self.cfg
        data = {}
        use_refresh = bool(cfg.refresh_token) and (force_refresh or not cfg.client_id)
        if use_refresh:
            data["grant_type"] = "refresh_token"
            data["refresh_token"] = cfg.refresh_token
        else:
            data["grant_type"] = "client_credentials"
        if cfg.scope:
            data["scope"] = cfg.scope

        headers = {"Accept": "application/json"}
        if cfg.auth_method == "basic" and cfg.client_id and cfg.client_secret:
            creds = f"{cfg.client_id}:{cfg.client_secret}"
            headers["Authorization"] = "Basic " + base64.b64encode(creds.encode()).decode()
        else:
            if cfg.client_id:
                data["client_id"] = cfg.client_id
            if cfg.client_secret:
                data["client_secret"] = cfg.client_secret

        req = urllib.request.Request(
            cfg.token_url,
            data=urllib.parse.urlencode(data).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"OAuth2 token request failed ({exc.code}): {detail}") from None
        token = payload.get("access_token")
        if not token:
            raise RuntimeError(f"OAuth2 response has no access_token: {payload}")
        expires_in = payload.get("expires_in", 3600)
        self._token = token
        self._expires_at = time.time() + max(60, int(expires_in) - 60)
        rotated = payload.get("refresh_token")
        if rotated:
            self.cfg.refresh_token = rotated


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "BearerProxy/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_PATCH(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def do_HEAD(self):
        self._proxy()

    def do_OPTIONS(self):
        self._proxy()

    def _proxy(self):
        cfg = self.server.cfg
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP
        }
        self._forward(cfg, headers, body, retried=False)

    def _forward(self, cfg, headers, body, retried):
        headers["Authorization"] = "Bearer " + self.server.tokens.get()
        url = cfg.upstream + self.path
        req = urllib.request.Request(url, data=body, headers=headers, method=self.command)
        try:
            with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
                self._send(resp.status, list(resp.headers.items()), resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and not retried:
                exc.read()
                self.server.tokens.get(force=True)
                self._forward(cfg, headers, body, retried=True)
                return
            self._send(exc.code, list(exc.headers.items()), exc.read())
        except urllib.error.URLError as exc:
            self._send(502, [("Content-Type", "text/plain; charset=utf-8")],
                       f"Upstream error: {exc.reason}".encode())

    def _send(self, status, header_pairs, payload):
        self.send_response(status)
        for key, value in header_pairs:
            if key.lower() in HOP_BY_HOP:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload or b"")))
        self.end_headers()
        if self.command != "HEAD" and payload:
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    load_env_file()
    cfg = Config()
    cfg.validate()
    tokens = TokenManager(cfg)
    tokens.get()

    server = ThreadingHTTPServer((cfg.bind_host, cfg.port), ProxyHandler)
    server.cfg = cfg
    server.tokens = tokens
    print(f"Proxy listening on http://{cfg.bind_host}:{cfg.port} -> {cfg.upstream}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
