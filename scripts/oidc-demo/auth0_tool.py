#!/usr/bin/env python3
"""Reads the Auth0 values file for the OIDC demo, standard library only.

  auth0_tool.py check FILE                  prints how many of the six keys are set; exit 1 unless all are
  auth0_tool.py get FILE KEY                prints AUTH0_DOMAIN or AUTH0_API_IDENTIFIER (the other keys are refused)
  auth0_tool.py token-body FILE m2m|noscope JSON request body for the token endpoint, on stdout
  auth0_tool.py redact FILE                 copies stdin to stdout with every value in the file, every JWT and
                                            every Hydra token masked

The file must be readable by its owner only (mode 600). The client secrets only ever leave this process
on stdout of token-body, which callers pipe to curl on standard input, so a secret is never part of a
command line, an environment variable or a log.
"""

import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from report_secret_scan import PATTERNS  # noqa: E402

KEYS = (
    "AUTH0_DOMAIN",
    "AUTH0_API_IDENTIFIER",
    "AUTH0_M2M_CLIENT_ID",
    "AUTH0_M2M_CLIENT_SECRET",
    "AUTH0_NO_SCOPE_CLIENT_ID",
    "AUTH0_NO_SCOPE_CLIENT_SECRET",
)
PUBLIC_KEYS = ("AUTH0_DOMAIN", "AUTH0_API_IDENTIFIER")
LABELS = {
    "AUTH0_DOMAIN": "<auth0-domain>",
    "AUTH0_API_IDENTIFIER": "<api-identifier>",
    "AUTH0_M2M_CLIENT_ID": "<client-id>",
    "AUTH0_M2M_CLIENT_SECRET": "<redacted>",
    "AUTH0_NO_SCOPE_CLIENT_ID": "<client-id>",
    "AUTH0_NO_SCOPE_CLIENT_SECRET": "<redacted>",
}
CLIENTS = {"m2m": ("AUTH0_M2M_CLIENT_ID", "AUTH0_M2M_CLIENT_SECRET"),
           "noscope": ("AUTH0_NO_SCOPE_CLIENT_ID", "AUTH0_NO_SCOPE_CLIENT_SECRET")}
TOKEN_PATTERNS = ((PATTERNS["JWT"], b"<jwt>"), (PATTERNS["Hydra access token"], b"<hydra-token>"))


class ValuesFileError(Exception):
    pass


def load(path: str) -> dict[str, str]:
    file = pathlib.Path(path)
    try:
        mode = file.stat().st_mode
        text = file.read_text()
    except OSError as exc:
        raise ValuesFileError("the Auth0 values file cannot be read") from exc
    if mode & 0o077:
        raise ValuesFileError("the Auth0 values file must be readable by its owner only: chmod 600 it")
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*?)\s*$", line)
        if not match or match.group(1) not in KEYS:
            continue
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value:
            values[match.group(1)] = value
    return values


def redact(values: dict[str, str]) -> None:
    ordered = sorted(values, key=lambda k: -len(values[k]))
    for line in sys.stdin.buffer:
        for key in ordered:
            line = line.replace(values[key].encode(), LABELS[key].encode())
        for pattern, label in TOKEN_PATTERNS:
            line = pattern.sub(label, line)
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    command, path = argv[1], argv[2]
    try:
        values = load(path)
    except ValuesFileError as exc:
        print(exc, file=sys.stderr)
        return 1
    if command == "check":
        print(f"{len(values)} of {len(KEYS)} keys set")
        missing = [key for key in KEYS if key not in values]
        if missing:
            print("missing: " + ", ".join(missing), file=sys.stderr)
            return 1
        return 0
    if command == "get" and len(argv) == 4 and argv[3] in PUBLIC_KEYS and argv[3] in values:
        print(values[argv[3]])
        return 0
    if command == "token-body" and len(argv) == 4 and argv[3] in CLIENTS:
        id_key, secret_key = CLIENTS[argv[3]]
        if id_key not in values or secret_key not in values or "AUTH0_API_IDENTIFIER" not in values:
            print("the Auth0 values file is incomplete", file=sys.stderr)
            return 1
        if sys.stdout.isatty():
            print("token-body writes a client secret: pipe it to curl, never to a terminal", file=sys.stderr)
            return 1
        sys.stdout.write(json.dumps({"client_id": values[id_key], "client_secret": values[secret_key],
                                     "audience": values["AUTH0_API_IDENTIFIER"], "grant_type": "client_credentials"}))
        return 0
    if command == "redact" and len(argv) == 3:
        redact(values)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
