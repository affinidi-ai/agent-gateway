# Repository Documentation

The documents here explain what Agent Gateway does, how it is built, and how to change it,
without needing to leave the repository. They describe the checked-out revision exactly,
including implementation details and limitations.

The hosted [Agent Gateway documentation](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/)
adds procedures for deploying and operating an appliance, operator guides, and FAQs.

## Start Here

| Document                                            | Scope                                                                     |
| --------------------------------------------------- | ------------------------------------------------------------------------- |
| [Capabilities](CAPABILITIES.md)                     | What Agent Gateway can do, in detail                                      |
| [Architecture](../ARCHITECTURE.md)                  | How the system is put together and where in `src/` each part lives        |
| [Build From Source](development/GETTING_STARTED.md) | Build and run this source tree locally                                    |
| [Development Guide](development/DEVELOPMENT.md)     | Debugging, Docker-from-source, tests, and development workflows           |
| [Making Changes](development/MAKING_CHANGES.md)     | Recipes for the recurring change shapes, organised by what you want to do |
| [Testing](development/TESTING.md)                   | The four test layers, what belongs in each, and how to run them           |
| [Contributing](../CONTRIBUTING.md)                  | Contribution process and required checks                                  |
| [Project glossary](../CONTEXT.md)                   | Canonical terminology for source, tests, and repository documentation     |
| [Security policy](../SECURITY.md)                   | Private vulnerability reporting                                           |

## Configuration

| Document                                              | Scope                                                                                    |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| [Configuration files](CONFIGURATION_REFERENCE.md)     | What each configuration file controls and the effect of its fields                       |
| [Configuration reload](CONFIGURATION_RELOAD.md)       | Reload locking, listener lifecycle, server mode, fallback behavior, and `[a2a]` settings |
| [Example configuration](../config/examples/README.md) | The example files, what each maps to, and which are record fragments                     |

## Implementation References

| Document                                           | Revision-specific scope                                                                                                     |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| [Policy planes and egress](POLICY.md)              | OPA packages, versioned policy definitions, appliance-wide enforcement, and SSRF/egress controls                            |
| [Fabric internals](FABRIC.md)                      | DIDComm listener lifecycle, legacy wire names, and receive pipeline                                                         |
| [Protocol behavior](PROTOCOLS.md)                  | Active revisions, validation boundaries, compatibility, and limitations                                                     |
| [MCP tool gating](MCP_TOOL_GATING.md)              | MCP metadata contract, request-boundary invariant, and the tool-gating firewall                                             |
| [Source auth and managed identity](SOURCE_AUTH.md) | Inbound authentication methods, agent-DID derivation, and the Trust Recorder                                                |
| [Credential delegation](CREDENTIAL_DELEGATION.md)  | Credential providers, surface bindings, consent modes, the OAuth flow, and the delegation vault                             |
| [Terms and consent](TERMS_AND_CONSENT.md)          | Terms documents and versions, who must accept what, acceptance records, and consent-pending sessions                        |
| [Integrations](INTEGRATIONS.md)                    | Email, Slack, webhook, and stream publishers, the event catalogue, trigger configuration, and template variables            |
| [MCP metadata and 2026-07-28](MCP_METADATA.md)     | Metadata aliases, modern MCP admission, protocol modes, and the conformance harness                                         |
| [Observability internals](OBSERVABILITY.md)        | Dashboard event contracts, buffering, request correlation, governance audit forwarding, and the A2A protocol-version metric |
| [Management RBAC](RBAC.md)                         | Middleware enforcement and permissions response contract                                                                    |
| [Management access tokens](ACCESS_TOKENS.md)       | PAT contract, resource-pattern grammar, delegation, and tenant ownership                                                    |
| [Security Token Service](STS.md)                   | RFC 8693 token exchange, ID-JAG issuance/redemption, and issuance gates                                                     |
| [Onboarding capture](AGENT_ONBOARDING_CAPTURE.md)  | Capture security boundary, lifetime, and emitted events                                                                     |
| [Rust design patterns](DESIGN_PATTERNS.md)         | Internal concurrency, lifecycle, and storage patterns                                                                       |

## Coverage

The [module map in `ARCHITECTURE.md`](../ARCHITECTURE.md#module-map) is the single record of
what documents each part of the source. Every top-level module in `src/` has a row, naming
either the document that covers it or, where there is none, the file to start reading.

For product tasks, start with the hosted [Quickstart](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/get-started/), [Guides](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/how-to-guides/), or [Reference](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/reference/).
