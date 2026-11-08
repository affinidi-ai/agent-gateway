# MCP authorization server discovery demo

Runs MCP authorization server discovery end to end against a real
authorization server: Ory Hydra in Docker, a login and consent app, an MCP
server, and the gateway with an MCP surface that publishes protected resource
metadata naming Hydra. The gateway-side contract is in
[docs/MCP_METADATA.md](../../docs/MCP_METADATA.md#authorization-server-discovery-for-caller-authentication).

## Running it

```sh
./scripts/mcp-discovery/run.sh          # build, start, check, stop
./scripts/mcp-discovery/run.sh --keep   # leave it running for MCP Inspector
./scripts/mcp-discovery/run.sh --help
```

Requires Docker, Node.js 22 or later with npm, Cargo, openssl, and
[mkcert](https://github.com/FiloSottile/mkcert) with its local CA installed
(`mkcert -install`). The certificate for `localhost` comes from that CA, so the
gateway, Node and the browser all trust Hydra and the gateway without
disabling TLS checks. The first run pulls `oryd/hydra:v26.2.0` and installs the
pinned MCP client SDK (`npm ci --ignore-scripts`). Everything the run writes is
under `target/mcp-discovery/`, logs in `target/mcp-discovery/logs/`.

| Process | Address |
| --- | --- |
| Gateway, MCP surface `/demo/mcp` | `https://localhost:18643` |
| Ory Hydra, public and admin | `https://localhost:4444`, `https://localhost:4445` |
| Login and consent app | `http://localhost:18644` |
| MCP server | `http://127.0.0.1:18645/mcp` |

`MCP_DISCOVERY_PORT_BASE`, `MCP_DISCOVERY_HYDRA_PUBLIC_PORT` and
`MCP_DISCOVERY_HYDRA_ADMIN_PORT` move the ports. The run stops if one is in use.

## What it checks

`check.mjs` does what an MCP client does, step by step:

1. A call without a token gets `401` with
   `WWW-Authenticate: Bearer resource_metadata="…"`.
2. The protected resource metadata names the URL that was called as its
   `resource`, Hydra as the authorization server, and the `tools` scope, and a
   browser client on another origin may read it.
3. Hydra's own metadata (RFC 8414) names the same issuer and supports PKCE.
4. A sign-in as `demo-user` with PKCE and the RFC 8707 `resource` returns a
   token whose `aud` is the resource, and the retry succeeds.
5. The MCP server lists its tools, and its `whoami` tool shows that no
   `Authorization` header reached it.
6. The surface policy admits only `demo-user`, so a valid token for another
   subject is refused with `403`: the caller's identity reaches policy.
7. The gateway log records the authenticated subject.

`sdk-check.mjs` repeats the flow with the official MCP client SDK
(`@modelcontextprotocol/client`, the library MCP Inspector is built on). The SDK
finds Hydra on its own from the `401` challenge; only the browser sign-in is
scripted.

## Checking with MCP Inspector

Start the demo with `--keep`, then in another terminal:

```sh
NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem" npx @modelcontextprotocol/inspector@2.12.0
```

In Inspector, connect with transport Streamable HTTP to
`https://localhost:18643/demo/mcp`, with OAuth client ID `mcp-discovery-demo`
and scope `tools`. Inspector follows the challenge to Hydra and opens the
login page: sign in as `demo-user` to reach the tools, or as any other name to
see the surface policy refuse the call. The client is registered for the
redirect URIs `http://localhost:6274/oauth/callback` and
`http://localhost:6274/oauth/callback/debug`; set
`MCP_DISCOVERY_INSPECTOR_ORIGIN` if Inspector runs on another origin.

## Hydra and the resource parameter

Hydra ignores the RFC 8707 `resource` parameter that MCP clients send, and the
gateway accepts only tokens whose `aud` names the resource. `login-consent.mjs`
bridges the two: on consent it grants every requested `resource` as the access
token audience. Hydra still checks each granted audience against the client's
allowed audiences, so the demo client lists the resource. A production
deployment on Hydra needs the same step in its consent app.
