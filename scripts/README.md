# Scripts

Please use `make`.

## Management multi-tenancy demo

Start a local gateway with `make run-debug`. For manual setup, open **Secrets →
Access Tokens**, choose **New Access Token**, add scopes from the **Available
permissions** pills, and configure the header and canonical resource pattern
shown by `./scripts/demo-multi-tenancy.sh --help`. Copy each one-time secret,
then run:

```bash
make demo-multi-tenancy
```

The script securely prompts for both PATs, creates isolated tenant resources,
checks foreign read/write behavior, feature-scope narrowing, and reference
integrity, then removes everything it created.

To provision one-day temporary PATs from an administrator session and revoke
them after the demo, run:

```bash
make demo-multi-tenancy ARGS="--provision-pats"
```

The administrator session token is requested through a hidden prompt. Add
`ARGS="--keep"` to retain resources, or combine flags in the same `ARGS` value.

## MCP conformance harness

```bash
make mcp-conformance
```

Runs the published MCP conformance suite and the legacy compatibility checks
against the gateway. See
[mcp-conformance/README.md](mcp-conformance/README.md) for options, outputs and
baseline maintenance.
