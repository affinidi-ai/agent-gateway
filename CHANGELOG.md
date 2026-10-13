# Changelog

All notable changes to Affinidi Agent Gateway will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Deny fabric requests to a surface that has OPA enabled but no compiled policy, as the direct path already did; they were let through.
- Enforce the appliance-wide surface policy on every fabric request; it ran only when the surface had its own compiled policy.
- Stop returning OPA engine error text to callers when a policy cannot decide; callers get the generic denial and the detail stays in the gateway log.

### Fixed

- Send `Retry-After` when an Access Point rate limit refuses a request with 429; it was never set.

## [1.0.0]

### Added

- Introduce Agent Surfaces for routing and protecting managed agents.
- Support HTTP, A2A, MCP, DIDComm, and Gateway-to-Gateway Fabric communication.
- Support JWT, API key, DID Auth, mTLS, and TLS authentication.
- Support DID-based identity with Verifiable Credentials and Presentations.
- Support caller-context and workload-binding identity propagation.
- Support gateway and surface OPA/Rego policy enforcement.
- Support Trust Registry recognition and authorization checks through TRQP.
- Support MCP and A2A (customised per Copilot) proxy integrations.
- Support x402 and MPP protocol based payment controls.
- Support rate limiting, timeouts, retries, and circuit breakers.
- Support encrypted storage, encrypted backups, and secret management.
- Support real-time dashboard monitoring and hot configuration reload.
- Support Prometheus, OpenTelemetry, structured logging, and security audit events.
- Support replay protection for security tokens and payment authorization.
- Support admin RBAC, scoped access tokens, and tenant-aware authorization.
- Support authenticated and encrypted DIDComm Fabric communication.
- Redact sensitive credentials from logs and telemetry.
