"""Write a fresh, disposable gateway environment for one harness phase.

Nothing is copied from a developer env: the bootstrap config comes from the
binary's own --generate-bootstrap, the certificate is generated, and the backup
key is supplied by run.sh at start-up through the environment only. Next to the
config it writes targets.json, naming every base URL the suite is pointed at.
"""

import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROUTE = '/conformance/a2a'
FULL_VALIDATION_ROUTE = '/conformance/a2a-full'
PROXY_ROUTE = '/conformance/a2a-proxy'
PROXY_ID = 'conformance-a2a-proxy'
DIRECT_LINE_SECRET_ID = 'conformance-direct-line'
TRANSIT_ALIAS = 'conformance-a2a'
TRANSIT_PATH = f'/transit/{TRANSIT_ALIAS}'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--inbound-port', required=True, type=int)
    parser.add_argument('--outbound-port', required=True, type=int)
    parser.add_argument('--agent-url', required=True)
    parser.add_argument('--accepted-versions', required=True, help='Comma-separated, e.g. 1.0 or 0.3,1.0')
    parser.add_argument('--direct-line-url', required=True, help='Base URL of the Direct Line stand-in')
    return parser.parse_args()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def write_bootstrap(env_dir: Path, config_dir: Path, binary: Path) -> None:
    bootstrap = subprocess.run(
        [binary.resolve(), '--generate-bootstrap'],
        cwd=env_dir, check=True, text=True, stdout=subprocess.PIPE,
    ).stdout
    backup_key = re.search(r'^backup_encryption_key = "env://([A-Za-z_][A-Za-z0-9_]*)"$', bootstrap, re.MULTILINE)
    if backup_key is None:
        sys.exit('env.py: generated bootstrap does not read the backup key from the environment')
    (env_dir / 'backup-key-var').write_text(backup_key.group(1))
    (config_dir / 'config.toml').write_text(bootstrap)
    subprocess.run(
        [REPO / 'scripts' / 'certs' / 'generate-cert.sh'],
        cwd=env_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def listener(kind: str, port: int, url: str) -> dict:
    return {
        'id': f'conformance-{kind}',
        'name': f'Conformance {kind}',
        'bind_address': '127.0.0.1',
        'port': port,
        'protocol': 'http',
        'external_urls': [url],
        'listener_type': kind,
    }


def gateway_config(args: argparse.Namespace, inbound: str, outbound: str) -> dict:
    gateway = json.loads((REPO / 'config' / 'examples' / 'gateway.example.json').read_text())
    gateway['did'] = {'domain': 'localhost'}
    gateway['webauthn'] = {'rp_id': 'localhost', 'external_origin': f'http://localhost:{args.inbound_port}'}
    gateway['cors'] = [inbound]
    gateway['listeners'] = [
        listener('inbound', args.inbound_port, inbound),
        listener('outbound', args.outbound_port, outbound),
    ]
    gateway['channels'] = [{'id': 'conformance', 'name': 'conformance', 'prefix': '/conformance'}]
    gateway['routes'] = {
        'connection_points_did': gateway['routes']['connection_points_did'],
        'api': gateway['routes']['api'],
    }
    return gateway


NO_VP = {'inject_vp': False}


def access_point(args: argparse.Namespace, inbound: str, route: str, validation: str) -> dict:
    return {
        'listen_address': inbound,
        'route': route,
        'protocol': 'a2a',
        'public': True,
        'publish_to_did_document': False,
        'terminate_trace_id': False,
        'a2a': {'accepted_versions': args.accepted_versions.split(','), 'validation': validation},
    }


def forwarding_surface(args: argparse.Namespace, inbound: str, outbound: str) -> dict:
    return {
        'surface_id': 'conformance-a2a',
        'name': 'Conformance A2A',
        'description': 'A2A Access Point and Transit Point fronting the suite test agent',
        'status': 'active',
        'access_point': access_point(args, inbound, ROUTE, 'envelope'),
        'target': {'endpoint': args.agent_url, 'identity_injection': NO_VP},
        'transit': {
            'points': [
                {
                    'id': 'conformance-a2a-transit',
                    'name': 'Conformance A2A Transit',
                    'alias': TRANSIT_ALIAS,
                    'target_endpoint': args.agent_url,
                    'protocol': 'a2a',
                    'identity_injection': NO_VP,
                    'listen_path': TRANSIT_PATH,
                    'require_transit_token': False,
                    'allow_unauthenticated_callers': True,
                },
            ],
            'outbound_listen_address': outbound,
            'transit_token_mode': 'embedded',
        },
    }


def full_validation_surface(args: argparse.Namespace, inbound: str) -> dict:
    return {
        'surface_id': 'conformance-a2a-full',
        'name': 'Conformance A2A full validation',
        'description': 'A2A Access Point that also checks the A2A request shape before forwarding',
        'status': 'active',
        'access_point': access_point(args, inbound, FULL_VALIDATION_ROUTE, 'full'),
        'target': {'endpoint': args.agent_url, 'identity_injection': NO_VP},
    }


def proxy_surface(args: argparse.Namespace, inbound: str) -> dict:
    return {
        'surface_id': 'conformance-a2a-proxy',
        'name': 'Conformance A2A proxy',
        'description': 'A2A Access Point answered by the gateway-owned A2A proxy',
        'status': 'active',
        'access_point': access_point(args, inbound, PROXY_ROUTE, 'envelope'),
        'target': {'endpoint': f'a2a-proxy://{PROXY_ID}', 'a2a_proxy_id': PROXY_ID, 'identity_injection': NO_VP},
    }


def proxy_records(args: argparse.Namespace, now: str) -> dict[str, dict]:
    """The A2A proxy and the secret its Direct Line backend names, by storage path."""
    return {
        f'a2a_proxies/{PROXY_ID}.json': {
            'id': PROXY_ID,
            'name': 'Conformance A2A proxy',
            'description': 'A2A proxy over the Direct Line stand-in',
            'status': 'active',
            'backend': {
                'kind': 'copilot_direct_line',
                'secret_id': DIRECT_LINE_SECRET_ID,
                'credential_mode': 'secret',
                'base_url': args.direct_line_url,
                'timeout_secs': 5,
                'poll_interval_ms': 100,
                'max_poll_attempts': 10,
            },
            'agent_card': {'name': 'Conformance A2A proxy', 'description': 'A2A proxy over the Direct Line stand-in'},
            'created_at': now,
            'updated_at': now,
        },
        f'secrets/{DIRECT_LINE_SECRET_ID}.json': {
            'id': DIRECT_LINE_SECRET_ID,
            'name': 'Conformance Direct Line',
            'secret_id': DIRECT_LINE_SECRET_ID,
            'description': 'Placeholder the Direct Line stand-in never checks',
            'value': 'not-a-real-credential',
            'secret_type': 'ApiKey',
            'tags': ['conformance'],
            'created_at': now,
            'updated_at': now,
        },
    }


def main() -> None:
    args = parse_args()
    env_dir = args.dir.resolve()
    config_dir = env_dir / 'config'
    inbound = f'http://127.0.0.1:{args.inbound_port}'
    outbound = f'http://127.0.0.1:{args.outbound_port}'

    shutil.rmtree(env_dir, ignore_errors=True)
    config_dir.mkdir(parents=True)
    write_bootstrap(env_dir, config_dir, args.binary)
    write_json(config_dir / 'gateway.json', gateway_config(args, inbound, outbound))

    storage = config_dir / '_storage'
    surfaces = (forwarding_surface(args, inbound, outbound), full_validation_surface(args, inbound), proxy_surface(args, inbound))
    for surface in surfaces:
        write_json(storage / 'agent_surfaces' / f'{surface["surface_id"]}.json', surface)
    now = datetime.datetime.now(datetime.UTC).isoformat()
    for path, record in proxy_records(args, now).items():
        write_json(storage / path, record)
    write_json(env_dir / 'targets.json', {
        'access-point': f'{inbound}{ROUTE}',
        'access-point-full': f'{inbound}{FULL_VALIDATION_ROUTE}',
        'transit': f'{outbound}{TRANSIT_PATH}',
        'a2a-proxy': f'{inbound}{PROXY_ROUTE}',
    })
    print(f'env written to {env_dir}')


if __name__ == '__main__':
    main()
