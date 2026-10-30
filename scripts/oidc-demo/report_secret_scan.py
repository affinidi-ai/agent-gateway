"""Fails when a live UI test result holds secret material.

Usage: report_secret_scan.py <result dir> <world file> <secrets dir>

Searches every file under the result directory, and the zip archives that the Playwright HTML
report embeds in its pages, for PEM private keys, bearer tokens, and the run's own secrets: the
client secrets and signing key in the world file and the harness secrets in the secrets dir.
Prints only file names and the kind of match, never a value.
"""

import base64
import io
import json
import pathlib
import re
import sys
import zipfile

PATTERNS = {
    "PEM private key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\[nr]|\s)*[A-Za-z0-9+/]{16}"),
    "JWT": re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "Hydra access token": re.compile(rb"ory_(?:at|rt|ac)_[A-Za-z0-9_.-]{8,}"),
}
EMBEDDED_ZIP = re.compile(rb"data:application/zip;base64,([A-Za-z0-9+/=]+)")
MIN_SECRET_LENGTH = 12


def run_secrets(world_file: pathlib.Path, secrets_dir: pathlib.Path) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    if world_file.is_file():
        world = json.loads(world_file.read_text())
        for name, entry in world.items():
            if isinstance(entry, dict) and isinstance(entry.get("secret"), str):
                found[f"client secret of {name}"] = entry["secret"].encode()
        pem = world.get("key", {}).get("privatePem", "")
        body = [line for line in pem.splitlines() if line and not line.startswith("-----")]
        for index, line in enumerate(body):
            found[f"signing key line {index + 1}"] = line.encode()
    if secrets_dir.is_dir():
        for path in sorted(secrets_dir.iterdir()):
            if path.is_file():
                found[f"harness secret {path.name}"] = path.read_bytes().strip()
    return {label: value for label, value in found.items() if len(value) >= MIN_SECRET_LENGTH}


def blobs(result_dir: pathlib.Path):
    for path in sorted(result_dir.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        yield str(path.relative_to(result_dir)), data
        for match in EMBEDDED_ZIP.finditer(data):
            with zipfile.ZipFile(io.BytesIO(base64.b64decode(match.group(1)))) as archive:
                for member in archive.namelist():
                    yield f"{path.relative_to(result_dir)}!{member}", archive.read(member)


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    result_dir, world_file, secrets_dir = (pathlib.Path(arg) for arg in sys.argv[1:])
    secrets = run_secrets(world_file, secrets_dir)
    hits = []
    scanned = 0
    for name, data in blobs(result_dir):
        scanned += 1
        kinds = [kind for kind, pattern in PATTERNS.items() if pattern.search(data)]
        kinds += [label for label, value in secrets.items() if value in data]
        hits += [f"{name}: {kind}" for kind in kinds]
    if hits:
        print("secret material found in the test results:", file=sys.stderr)
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        return 1
    print(f"secret scan: {scanned} result files clean, {len(secrets)} run secrets checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
