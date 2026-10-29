#!/usr/bin/env python3
"""Fetches an agent card with the a2a-python card resolver and prints one JSON result line.

Run with the interpreter of the virtualenv that holds the SDK under test (a2a-sdk 0.3.x or 1.x).
Usage: check_py.py CARD_URL
The optional SDK_CHECK_BEARER environment variable is sent as a bearer token and never printed.
"""

import asyncio
import importlib.metadata
import json
import os
import sys
from urllib.parse import urlsplit

import httpx
from a2a.client.card_resolver import A2ACardResolver


def split_url(card_url):
    parts = urlsplit(card_url)
    return f"{parts.scheme}://{parts.netloc}", parts.path + (f"?{parts.query}" if parts.query else "")


def camel(snake):
    head, *tail = snake.split("_")
    return head + "".join(part.title() for part in tail)


def scheme_summary_v03(card):
    schemes = {}
    for name, scheme in (card.security_schemes or {}).items():
        body = scheme.root
        kind = getattr(body.type, "value", body.type)
        flows = getattr(body, "flows", None)
        present = [k for k in ("authorization_code", "client_credentials", "implicit", "password") if flows and getattr(flows, k, None)]
        scopes = sorted({s for k in present for s in getattr(flows, k).scopes})
        flow_names = sorted(camel(k) for k in present)
        schemes[name] = {"type": kind, "metadataUrl": getattr(body, "oauth2_metadata_url", None), "flows": flow_names, "scopes": scopes}
    return {
        "name": card.name,
        "interfaces": [card.url],
        "schemes": schemes,
        "requirements": [{k: sorted(v) for k, v in req.items()} for req in (card.security or [])],
    }


def scheme_summary_v1(card):
    from google.protobuf.json_format import MessageToDict

    data = MessageToDict(card)
    schemes = {}
    for name, wrapper in data.get("securitySchemes", {}).items():
        (kind_key, body), = wrapper.items()
        flows = body.get("flows", {})
        schemes[name] = {
            "type": kind_key.removesuffix("SecurityScheme"),
            "metadataUrl": body.get("oauth2MetadataUrl"),
            "flows": sorted(flows),
            "scopes": sorted({s for f in flows.values() for s in f.get("scopes", {})}),
        }
    requirements = [
        {k: sorted(v.get("list", [])) for k, v in req.get("schemes", {}).items()}
        for req in data.get("securityRequirements", [])
    ]
    return {
        "name": data.get("name"),
        "interfaces": [i.get("url") for i in data.get("supportedInterfaces", [])],
        "schemes": schemes,
        "requirements": requirements,
    }


async def fetch(card_url):
    base, path = split_url(card_url)
    token = os.environ.get("SDK_CHECK_BEARER")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(headers=headers, timeout=15) as client:
        return await A2ACardResolver(client, base, path).get_agent_card()


def main():
    version = importlib.metadata.version("a2a-sdk")
    result = {"sdk": "a2a-python", "version": version, "mode": "default"}
    try:
        card = asyncio.run(fetch(sys.argv[1]))
        summarize = scheme_summary_v1 if version.startswith("1.") else scheme_summary_v03
        result.update(ok=True, summary=summarize(card))
    except Exception as exc:
        result.update(ok=False, error=f"{type(exc).__name__}: {exc}"[:600])
    print(json.dumps(result))


if __name__ == "__main__":
    main()
