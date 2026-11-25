"""A loopback stand-in for the Direct Line service behind the gateway's A2A proxy.

It serves the three calls the A2A proxy makes: start a conversation, post the
caller's text as an activity, and poll the conversation for the reply. The
reply repeats the text after REPLY_PREFIX, so a result can be told from an
empty success.

Usage: directline.py --port <port>
"""

import argparse
import json
import re
import threading
import uuid

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_PATH = '/v3/directline'
REPLY_PREFIX = 'conformance reply: '
BOT_ID = 'conformance-bot'
ACTIVITIES = re.compile(rf'^{BASE_PATH}/conversations/([^/]+)/activities$')

conversations: dict[str, list[dict]] = {}
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def answer(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def read_json(self) -> dict:
        length = int(self.headers.get('Content-Length') or 0)
        try:
            body = json.loads(self.rfile.read(length) or b'{}')
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}

    def do_POST(self) -> None:
        path = self.path.split('?', 1)[0]
        body = self.read_json()
        if path == f'{BASE_PATH}/conversations':
            conversation = str(uuid.uuid4())
            with lock:
                conversations[conversation] = []
            self.answer(201, {'conversationId': conversation})
            return
        match = ACTIVITIES.match(path)
        with lock:
            activities = conversations.get(match.group(1)) if match else None
            if activities is not None:
                activities.append({'type': 'message', 'from': {'id': BOT_ID}, 'text': f'{REPLY_PREFIX}{body.get("text", "")}'})
        if activities is None:
            self.answer(404, {'error': f'unknown Direct Line path {path}'})
        else:
            self.answer(200, {'id': str(uuid.uuid4())})

    def do_GET(self) -> None:
        match = ACTIVITIES.match(self.path.split('?', 1)[0])
        with lock:
            activities = list(conversations.get(match.group(1), [])) if match else None
        if activities is None:
            self.answer(404, {'error': f'unknown Direct Line path {self.path}'})
        else:
            self.answer(200, {'activities': activities, 'watermark': str(len(activities))})

    def log_message(self, format: str, *args: object) -> None:
        print(f'{self.command} {self.path.split("?", 1)[0]} {args[1] if len(args) > 1 else ""}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--port', required=True, type=int)
    port = parser.parse_args().port
    print(f'Direct Line stand-in on http://127.0.0.1:{port}{BASE_PATH}', flush=True)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
