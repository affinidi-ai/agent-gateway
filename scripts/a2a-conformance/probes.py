"""Checks the suite does not make, written to probes.json next to its results.

  entry_point::accepts_trailing_slash
      The interface URL answers JSON-RPC with and without a trailing slash.
      The suite always calls it with one, so an entry point that refuses the
      slash fails every test for that single reason.
  agent_card::interfaces_are_served
      Every interface the agent card lists answers in the binding it names.
      The suite is run on JSON-RPC only, so it never calls the other two.

check_results.py scores these with the suite's own results. Run with the
TCK's interpreter: it needs httpx and grpcio. --a2a-version picks the method
name, the version header and the agent card shape of that A2A version.
"""

import argparse
import json
import uuid

from pathlib import Path

import grpc
import httpx

TIMEOUT = httpx.Timeout(5.0)
GRPC_READY_SECONDS = 3
# A2A 0.3 callers send no A2A-Version header and spell the method tasks/get.
DIALECTS = {
    '1.0': {'headers': {'A2A-Version': '1.0'}, 'get_task': 'GetTask'},
    '0.3': {'headers': {}, 'get_task': 'tasks/get'},
}
dialect = DIALECTS['1.0']


def json_object(response: httpx.Response) -> dict:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def get_task(url: str) -> tuple[bool, str]:
    """Ask for a task that does not exist; a JSON-RPC answer with HTTP 200 shows the binding is served.

    An agent answers a JSON-RPC error with HTTP 200. The gateway answers a
    request it refuses itself with HTTP 4xx, which must not count as the agent.
    """
    body = {'jsonrpc': '2.0', 'id': 1, 'method': dialect['get_task'], 'params': {'id': str(uuid.uuid4())}}
    try:
        response = httpx.post(url, json=body, headers=dialect['headers'], timeout=TIMEOUT)
    except httpx.HTTPError as error:
        return False, type(error).__name__
    served = response.status_code == 200 and json_object(response).get('jsonrpc') == '2.0'
    return served, f'HTTP {response.status_code}' + ('' if served else ', not a JSON-RPC answer from the agent')


def rest_get_task(url: str) -> tuple[bool, str]:
    """HTTP+JSON answers a missing task with an error object, never a JSON-RPC envelope."""
    try:
        response = httpx.get(f'{url.rstrip("/")}/tasks/{uuid.uuid4()}', headers=dialect['headers'], timeout=TIMEOUT)
    except httpx.HTTPError as error:
        return False, type(error).__name__
    body = json_object(response)
    served = isinstance(body.get('error'), dict) and 'jsonrpc' not in body
    return served, f'HTTP {response.status_code}' + ('' if served else ', not an HTTP+JSON answer')


def grpc_ready(url: str) -> tuple[bool, str]:
    channel = grpc.insecure_channel(url)
    try:
        grpc.channel_ready_future(channel).result(timeout=GRPC_READY_SECONDS)
    except grpc.FutureTimeoutError:
        return False, 'no gRPC server answered'
    finally:
        channel.close()
    return True, 'ready'


BINDINGS = {'JSONRPC': get_task, 'HTTP+JSON': rest_get_task, 'GRPC': grpc_ready}


def interfaces(card: dict) -> list[tuple[str, str]]:
    """Each (binding, url) the card lists: a 1.0 card in supportedInterfaces, a 0.3 card in url and additionalInterfaces."""
    if 'supportedInterfaces' in card:
        return [(entry.get('protocolBinding', ''), entry.get('url', '')) for entry in card['supportedInterfaces']]
    listed = [(card.get('preferredTransport', 'JSONRPC'), card.get('url', ''))]
    listed += [(entry.get('transport', ''), entry.get('url', '')) for entry in card.get('additionalInterfaces', [])]
    return list(dict.fromkeys(listed))


def trailing_slash(card: dict) -> tuple[bool, str]:
    urls = [url for binding, url in interfaces(card) if binding == 'JSONRPC']
    if not urls:
        return False, 'the agent card lists no JSONRPC interface'
    bare = urls[0].rstrip('/')
    plain, with_slash = get_task(bare), get_task(f'{bare}/')
    return plain[0] and with_slash[0], f'without slash: {plain[1]}; with slash: {with_slash[1]}'


def interfaces_served(card: dict) -> tuple[bool, str]:
    refused = []
    for binding, url in interfaces(card):
        probe = BINDINGS.get(binding)
        served, detail = probe(url) if probe else (False, 'unknown binding')
        if not served:
            refused.append(f'{binding} at {url} ({detail})')
    return not refused, 'not served: ' + '; '.join(refused) if refused else 'every listed interface answered'


PROBES = {
    'harness.entry_point::accepts_trailing_slash': trailing_slash,
    'harness.agent_card::interfaces_are_served': interfaces_served,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', required=True, help='Base URL the suite is pointed at')
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--a2a-version', choices=sorted(DIALECTS), default='1.0')
    args = parser.parse_args()
    global dialect
    dialect = DIALECTS[args.a2a_version]

    card = httpx.get(f'{args.url.rstrip("/")}/.well-known/agent-card.json', timeout=TIMEOUT).raise_for_status().json()
    results = []
    for test, probe in PROBES.items():
        passed, message = probe(card)
        results.append({'test': test, 'outcome': 'pass' if passed else 'fail', 'message': message})
        print(f'{"pass" if passed else "FAIL"}  {test}: {message}')
    args.out.write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
