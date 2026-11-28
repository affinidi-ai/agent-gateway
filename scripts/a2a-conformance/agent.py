"""Start the A2A TCK's generated test agent on loopback only.

The generated agent listens on every interface. This launcher loads it
unchanged and narrows its HTTP and gRPC listeners to 127.0.0.1.

Usage: agent.py <path to sut_agent.py>, with SUT_HOST=127.0.0.1:<port> and
GRPC_PORT=<port> in the environment.
"""

import asyncio
import importlib.util
import sys

import grpc.aio
import uvicorn

LOOPBACK = '127.0.0.1'


def load_agent(path: str):
    spec = importlib.util.spec_from_file_location('tck_sut_agent', path)
    if spec is None or spec.loader is None:
        raise SystemExit(f'agent.py: cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bind_loopback() -> None:
    uvicorn_config = uvicorn.Config

    def config(app, *args, **kwargs):
        kwargs['host'] = LOOPBACK
        return uvicorn_config(app, *args, **kwargs)

    uvicorn.Config = config

    grpc_server = grpc.aio.server

    def server(*args, **kwargs):
        created = grpc_server(*args, **kwargs)
        add_insecure_port = created.add_insecure_port

        def add_loopback_port(address: str) -> int:
            return add_insecure_port(f'{LOOPBACK}:{address.rsplit(":", 1)[-1]}')

        created.add_insecure_port = add_loopback_port
        return created

    grpc.aio.server = server


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    bind_loopback()
    asyncio.run(load_agent(sys.argv[1]).main())
