#!/usr/bin/env python3
"""Counts the Auth0 values file's values and the secret material that report_secret_scan.py looks for.

Usage: auth0_scan.py VALUES_FILE TARGET...   (a target is a file, a directory scanned recursively,
                                              or - for standard input)

Prints one line per target with counts only, never a match: the values of the file, PEM private keys,
JWTs and Hydra access tokens. Exits 1 when any count is not zero, except that the tenant domain and
the API identifier are reported separately as identifiers and do not fail the run.
"""

import pathlib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import auth0_tool  # noqa: E402
from report_secret_scan import PATTERNS  # noqa: E402

IDENTIFIERS = auth0_tool.PUBLIC_KEYS


def read(target: str) -> bytes:
    if target == "-":
        return sys.stdin.buffer.read()
    path = pathlib.Path(target)
    if path.is_dir():
        return b"\n".join(file.read_bytes() for file in sorted(path.rglob("*")) if file.is_file())
    return path.read_bytes()


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        values = auth0_tool.load(argv[1])
    except auth0_tool.ValuesFileError as exc:
        print(exc, file=sys.stderr)
        return 2
    failed = False
    for target in argv[2:]:
        try:
            data = read(target)
        except OSError:
            print(f"{target}: cannot be read", file=sys.stderr)
            return 2
        secrets = sum(data.count(v.encode()) for k, v in values.items() if k not in IDENTIFIERS)
        ids = sum(data.count(values[k].encode()) for k in IDENTIFIERS if k in values)
        kinds = {kind: len(pattern.findall(data)) for kind, pattern in PATTERNS.items()}
        counts = " ".join(f"{kind.lower().replace(' ', '-')}={count}" for kind, count in kinds.items())
        print(f"{target}: secret-and-client-id values={secrets} identifiers={ids} {counts}")
        failed = failed or bool(secrets or any(kinds.values()))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
