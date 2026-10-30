#!/usr/bin/env python3
"""JWT helpers for the OIDC demo, standard library plus the openssl binary.

  jwt_tools.py jwk PUBLIC_KEY_PEM KID          RSA public key as a JWK (JSON on stdout)
  jwt_tools.py assertion KEY_PEM KID ISS SUB AUD SCOPE   RS256 JWT bearer assertion on stdout
  jwt_tools.py decode JWT|-                    payload claims as JSON; the signature is not checked
  jwt_tools.py header JWT|-                    header as JSON; the signature is not checked

A JWT argument of - reads the token from standard input, which keeps a live token out of a command line.

Nothing here prints key material. An assertion is a credential: callers keep it off the terminal.
"""

import base64
import json
import re
import subprocess
import sys
import time
import uuid


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwk_from_public_pem(path: str, kid: str) -> dict:
    out = subprocess.run(
        ["openssl", "rsa", "-pubin", "-in", path, "-noout", "-modulus"],
        check=True, capture_output=True, text=True,
    ).stdout
    match = re.search(r"Modulus=([0-9A-Fa-f]+)", out)
    if not match:
        raise SystemExit("could not read the RSA modulus")
    modulus = bytes.fromhex(match.group(1))
    modulus = modulus.lstrip(b"\x00")
    return {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
            "n": b64url(modulus), "e": "AQAB"}


def sign_assertion(key_path: str, kid: str, iss: str, sub: str, aud: str, scope: str) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = {"iss": iss, "sub": sub, "aud": aud, "iat": now - 30, "exp": now + 300,
              "jti": str(uuid.uuid4())}
    if scope:
        claims["scope"] = scope
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + b64url(json.dumps(claims, separators=(",", ":")).encode()))
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key_path],
        input=signing_input.encode(), check=True, capture_output=True,
    ).stdout
    return signing_input + "." + b64url(signature)


def decode_part(token: str, index: int) -> dict:
    if token == "-":
        token = sys.stdin.read()
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise SystemExit("not a compact JWT")
    return json.loads(b64url_decode(parts[index]))


def main(argv: list) -> int:
    if len(argv) >= 4 and argv[1] == "jwk":
        print(json.dumps(jwk_from_public_pem(argv[2], argv[3])))
    elif len(argv) == 8 and argv[1] == "assertion":
        print(sign_assertion(*argv[2:8]))
    elif len(argv) == 3 and argv[1] == "decode":
        print(json.dumps(decode_part(argv[2], 1)))
    elif len(argv) == 3 and argv[1] == "header":
        print(json.dumps(decode_part(argv[2], 0)))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
