#!/usr/bin/env python3
"""Mock A2A agent for the OIDC demo, standard library only.

It mirrors a managed agent whose card is login-only (as on Vertex AI Agent Engine): the
agent card and the JSON-RPC endpoint both need a bearer token issued by the agent's own
authorization server. The token is checked by asking Hydra's admin API to introspect it,
which validates the signature, expiry and revocation of a JWT access token.

The card carries its own `securitySchemes` and a dummy `signatures` entry, so a gateway
that rewrites the card has something to replace and remove.

Endpoints
  GET  /.well-known/agent-card.json, /v1/card   the card (token required unless --open)
  POST /, /v1/message:send                      JSON-RPC message/send (token required unless --open)
  GET  /_demo/log                               requests seen since the last reset (no tokens)
  POST /_demo/reset                             clear that log
  GET  /_demo/state                             {"refuse": bool}, whether the agent is refusing
  POST /_demo/refuse                            {"refuse": true} makes the agent answer 401 to every
                                                card and JSON-RPC request, whatever token it carries;
                                                {"refuse": false} restores normal checks
"""

import argparse
import json
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CARD_PATHS = ("/.well-known/agent-card.json", "/v1/card")
RPC_PATHS = ("/", "/v1/message:send")


def build_card(agent_url: str) -> dict:
    return {
        "protocolVersion": "0.3.0",
        "name": "OIDC Demo Mock Agent",
        "description": "Echo agent behind a login-only card.",
        "url": agent_url,
        "preferredTransport": "JSONRPC",
        "version": "1.0.0",
        "capabilities": {"streaming": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "echo", "name": "Echo", "description": "Repeats the message.",
                    "tags": ["demo"]}],
        "securitySchemes": {
            "agent_own_oauth": {
                "type": "oauth2",
                "flows": {"clientCredentials": {
                    "tokenUrl": "https://agent-as.internal.example/oauth2/token",
                    "scopes": {"agent.invoke": "Invoke the agent"}}},
            }
        },
        "security": [{"agent_own_oauth": ["agent.invoke"]}],
        "signatures": [{"protected": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpPU1QifQ",
                        "signature": "ZHVtbXktc2lnbmF0dXJlLWRvZXMtbm90LXZlcmlmeQ"}],
    }


class State:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.log = []
        self.refuse = False

    def record(self, method, path, authenticated, client_id, status):
        with self.lock:
            self.log.append({"method": method, "path": path, "authenticated": authenticated,
                             "client_id": client_id, "status": status})

    def introspect(self, token):
        body = urllib.parse.urlencode({"token": token}).encode()
        request = urllib.request.Request(self.args.introspect_url, data=body, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        request.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.load(response)
        except (OSError, ValueError):
            return {"active": False}

    def check(self, header):
        if not header or not header.lower().startswith("bearer "):
            return None
        info = self.introspect(header[7:].strip())
        if not info.get("active"):
            return None
        scopes = info.get("scope", "").split()
        if self.args.scope not in scopes or info.get("iss") != self.args.issuer:
            return None
        return info.get("client_id", "")


def make_handler(state: State):
    card = build_card(state.args.public_url)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def send_json(self, status, payload, extra=None):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def guard(self, method, path):
            with state.lock:
                refusing = state.refuse
            if refusing:
                state.record(method, path, False, "", 401)
                self.send_json(401, {"error": "invalid_token"},
                               {"WWW-Authenticate": 'Bearer realm="mock-agent"'})
                return False, ""
            if state.args.open:
                return True, ""
            client_id = state.check(self.headers.get("Authorization"))
            if client_id is None:
                state.record(method, path, False, "", 401)
                self.send_json(401, {"error": "invalid_token"},
                               {"WWW-Authenticate": 'Bearer realm="mock-agent"'})
                return False, ""
            return True, client_id

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == "/_demo/log":
                with state.lock:
                    return self.send_json(200, state.log)
            if path == "/_demo/state":
                with state.lock:
                    return self.send_json(200, {"refuse": state.refuse})
            if path in CARD_PATHS:
                ok, client_id = self.guard("GET", path)
                if ok:
                    state.record("GET", path, bool(client_id), client_id, 200)
                    self.send_json(200, card)
                return
            self.send_json(404, {"error": "not_found"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if path == "/_demo/reset":
                with state.lock:
                    state.log.clear()
                return self.send_json(200, {"reset": True})
            if path == "/_demo/refuse":
                try:
                    refuse = json.loads(raw or b"{}").get("refuse") is True
                except (ValueError, AttributeError):
                    refuse = False
                with state.lock:
                    state.refuse = refuse
                return self.send_json(200, {"refuse": refuse})
            if path in RPC_PATHS:
                ok, client_id = self.guard("POST", path)
                if not ok:
                    return
                try:
                    request = json.loads(raw or b"{}")
                except ValueError:
                    request = {}
                state.record("POST", path, bool(client_id), client_id, 200)
                return self.send_json(200, {
                    "jsonrpc": "2.0", "id": request.get("id"),
                    "result": {"kind": "message", "role": "agent", "messageId": "mock-reply-1",
                               "parts": [{"kind": "text", "text": "mock agent reply"}]}})
            self.send_json(404, {"error": "not_found"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--introspect-url", required=True)
    parser.add_argument("--issuer", required=True, help="issuer the agent's tokens must carry")
    parser.add_argument("--scope", default="agent.invoke")
    parser.add_argument("--open", action="store_true",
                        help="accept the card fetch and the calls without a token")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(State(args)))
    server.serve_forever()


if __name__ == "__main__":
    main()
