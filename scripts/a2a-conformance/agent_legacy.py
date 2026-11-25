"""Start the A2A 0.3 TCK's bundled test agent on loopback, on a chosen port.

The bundled agent listens on every interface at port 9999 and names that port
in its agent card. This launcher loads it unchanged and replaces the address
it listens on and the URL in its card.

The agent also reads SDK fields by their camelCase names (`task.contextId`),
which the a2a-sdk 0.3 line no longer offers as attributes, so every request
would end in an internal error. The launcher restores that one spelling.

Usage: agent_legacy.py <path to tck_core_agent>, with SUT_HOST=127.0.0.1:<port>
in the environment.
"""

import os
import re
import runpy
import sys

import uvicorn

import a2a.types

from a2a._base import A2ABaseModel

LOOPBACK = '127.0.0.1'
CAMEL_BOUNDARY = re.compile(r'(?<!^)(?=[A-Z])')


def read_fields_by_camel_case() -> None:
    model_getattr = A2ABaseModel.__getattr__

    def getattr_by_either_name(self, name: str):
        snake = CAMEL_BOUNDARY.sub('_', name).lower()
        if snake != name and snake in type(self).model_fields:
            return getattr(self, snake)
        return model_getattr(self, name)

    A2ABaseModel.__getattr__ = getattr_by_either_name


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    agent_dir = sys.argv[1]
    port = int(os.environ['SUT_HOST'].rsplit(':', 1)[-1])

    agent_card = a2a.types.AgentCard

    def card(**fields):
        fields['url'] = f'http://{LOOPBACK}:{port}/'
        return agent_card(**fields)

    uvicorn_run = uvicorn.run

    def run(app, **options):
        options.update(host=LOOPBACK, port=port)
        return uvicorn_run(app, **options)

    a2a.types.AgentCard = card
    uvicorn.run = run
    read_fields_by_camel_case()
    sys.path.insert(0, agent_dir)
    runpy.run_path(os.path.join(agent_dir, '__main__.py'), run_name='__main__')


if __name__ == '__main__':
    main()
