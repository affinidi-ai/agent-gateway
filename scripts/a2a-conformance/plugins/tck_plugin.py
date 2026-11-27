"""pytest plugin the harness loads into the A2A TCK.

--strip-trailing-slash makes the TCK's JSON-RPC client call the interface URL
exactly as the agent card gives it. The TCK always appends "/" to that URL; a
gateway entry point that refuses the extra slash would otherwise fail every
test for that one reason. probes.py probes the slash itself and reports it as
its own check.
"""

import httpx
import pytest

from tck.transport.jsonrpc_client import JsonRpcClient


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.getgroup('a2a-harness', 'Agent Gateway harness options').addoption(
        '--strip-trailing-slash',
        action='store_true',
        default=False,
        help='Send JSON-RPC requests to the interface URL without the trailing slash the TCK adds.',
    )


def _without_trailing_slash(request: httpx.Request) -> None:
    path = request.url.path
    if len(path) > 1 and path.endswith('/'):
        request.url = request.url.copy_with(path=path.rstrip('/'))


def pytest_configure(config: pytest.Config) -> None:
    if not config.getoption('--strip-trailing-slash'):
        return
    original_init = JsonRpcClient.__init__

    def init(self: JsonRpcClient, base_url: str) -> None:
        original_init(self, base_url)
        self._client.event_hooks['request'].append(_without_trailing_slash)

    JsonRpcClient.__init__ = init
