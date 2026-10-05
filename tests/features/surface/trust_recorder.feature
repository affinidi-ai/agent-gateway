Feature: Trust Recorder on the Access Point response edge
  The Trust Recorder creates recognition records about the managed agent
  in one or more configured trust registries. It runs on every successful
  response on the Access Point response edge (Managed Agent → Access Point).

  Recording is non-blocking: a trust registry failure never affects the
  caller response.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  # ── Recording ──────────────────────────────────────────────────────

  @wip
  Scenario: Trust Recorder registers the managed agent on a successful response
    Given the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    When the caller sends a request to the surface
    Then the response status is 200
    And the response body matches managed agent "bravo" response
    And trust registry "alpha-registry" received a recognition record for the managed agent as an owned agent of issuer "did:web:example.com:issuer"

  # ── Custom actions ─────────────────────────────────────────────────

  @wip
  Scenario: Trust Recorder registers a custom action alongside the default owned agent record
    Given the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    And the Trust Recorder for trust registry "alpha-registry" has custom action "is" with resource "threatSignalReceiver"
    When the caller sends a request to the surface
    Then the response status is 200
    And trust registry "alpha-registry" received a recognition record for the managed agent as an owned agent of issuer "did:web:example.com:issuer"
    And trust registry "alpha-registry" received a record for the managed agent with action "is" and resource "threatSignalReceiver"

  # ── Multiple trust registries ──────────────────────────────────────

  @wip
  Scenario: Trust Recorder creates records in multiple trust registries independently
    Given the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:alpha.com:issuer"
    And the surface has a Trust Recorder for trust registry "beta-registry" with issuer "did:web:beta.com:issuer"
    When the caller sends a request to the surface
    Then the response status is 200
    And trust registry "alpha-registry" received a recognition record for the managed agent as an owned agent of issuer "did:web:alpha.com:issuer"
    And trust registry "beta-registry" received a recognition record for the managed agent as an owned agent of issuer "did:web:beta.com:issuer"

  # ── Non-blocking ───────────────────────────────────────────────────

  @wip
  Scenario: Trust Recorder does not block the response when the trust registry is unreachable
    Given the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    And trust registry "alpha-registry" is unreachable
    When the caller sends a request to the surface
    Then the response status is 200
    And the response body matches managed agent "bravo" response

  @wip
  Scenario: Trust Recorder does not block the response when one of multiple trust registries is unreachable
    Given the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:alpha.com:issuer"
    And the surface has a Trust Recorder for trust registry "beta-registry" with issuer "did:web:beta.com:issuer"
    And trust registry "alpha-registry" is unreachable
    When the caller sends a request to the surface
    Then the response status is 200
    And trust registry "alpha-registry" was not called
    And trust registry "beta-registry" received a recognition record for the managed agent as an owned agent of issuer "did:web:beta.com:issuer"

  @wip
  Scenario: Trust Recorder does not fire when the managed agent returns an error
    Given the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    And managed agent "bravo" is failing with status 503
    When the caller sends a request to the surface
    Then the response status is 503
    And trust registry "alpha-registry" was not called
