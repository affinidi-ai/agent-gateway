"""Self-tests for directline.py; run.sh runs them before it starts the stand-in."""

import http.client
import json
import threading
import unittest

from http.server import ThreadingHTTPServer
from unittest import mock

import directline

CONVERSATIONS = f'{directline.BASE_PATH}/conversations'
MAX_BODY = directline.MAX_BODY
GATEWAY_REQUEST_LIMIT = 10 * 1024 * 1024


class StandIn(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(directline.Handler, 'log_message', lambda *args: None))
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), directline.Handler)
        self.addCleanup(self.server.server_close)
        threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.limit = 4096
        self.enterContext(mock.patch.object(directline, 'MAX_BODY', self.limit))

    def request(self, method: str, path: str, body: bytes = b'', length: str | None = None) -> tuple[int, dict]:
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        self.addCleanup(connection.close)
        connection.putrequest(method, path)
        connection.putheader('Content-Length', str(len(body)) if length is None else length)
        connection.endheaders(body)
        response = connection.getresponse()
        return response.status, json.loads(response.read())

    def conversation(self) -> str:
        status, body = self.request('POST', CONVERSATIONS)
        self.assertEqual(status, 201)
        return f'{CONVERSATIONS}/{body["conversationId"]}/activities'

    def test_a_conversation_answers_the_posted_text_with_one_reply(self):
        activities = self.conversation()
        status, _ = self.request('POST', activities, json.dumps({'type': 'message', 'text': 'hello'}).encode())
        self.assertEqual(status, 200)
        status, body = self.request('GET', activities)
        self.assertEqual(status, 200)
        self.assertEqual([activity['text'] for activity in body['activities']], [f'{directline.REPLY_PREFIX}hello'])
        self.assertEqual(body['watermark'], '1')

    def test_a_body_that_is_not_a_json_object_is_answered_as_an_empty_text(self):
        activities = self.conversation()
        for text in (b'not json', b'[1]'):
            self.assertEqual(self.request('POST', activities, text)[0], 200)
        _, body = self.request('GET', activities)
        self.assertEqual([activity['text'] for activity in body['activities']], [directline.REPLY_PREFIX] * 2)

    def test_an_unknown_path_or_conversation_is_not_found(self):
        for method, path in (('GET', '/v3/other'), ('POST', '/v3/other'), ('POST', f'{CONVERSATIONS}/unknown/activities')):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path)[0], 404)

    def test_a_body_at_the_limit_is_read(self):
        activities = self.conversation()
        padding = self.limit - len(json.dumps({'text': ''}))
        body = json.dumps({'text': 'x' * padding}).encode()
        self.assertEqual(len(body), self.limit)
        self.assertEqual(self.request('POST', activities, body)[0], 200)
        self.assertEqual(len(self.request('GET', activities)[1]['activities'][0]['text']), len(directline.REPLY_PREFIX) + padding)

    def test_a_body_declared_longer_than_the_limit_is_refused_without_being_read(self):
        activities = self.conversation()
        status, body = self.request('POST', activities, length=str(self.limit + 1))
        self.assertEqual(status, 413)
        self.assertIn(str(self.limit), body['error'])
        self.assertEqual(self.request('GET', activities)[1]['activities'], [])

    def test_the_limit_is_above_what_the_gateway_accepts_from_its_caller(self):
        self.assertGreater(MAX_BODY, GATEWAY_REQUEST_LIMIT)

    def test_a_length_that_is_not_a_number_is_refused(self):
        activities = self.conversation()
        for length in ('abc', '-1', '1.5'):
            with self.subTest(length=length):
                self.assertEqual(self.request('POST', activities, length=length)[0], 400)
        self.assertEqual(self.request('GET', activities)[1]['activities'], [])


if __name__ == '__main__':
    unittest.main()
