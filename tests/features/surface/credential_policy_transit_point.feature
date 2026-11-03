Feature: Credential policy on a Transit Point
  A Transit Point that authenticates its target, or injects a delegated credential,
  with a stored credential provider is held to the bootstrap credential policy like
  the Access Point. In warn mode the call is forwarded with the provider's token; in
  enforce mode the credential is refused before any token request and the Transit
  Point's target is not called.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog

  Scenario: A Transit Point uses a provider with an http token endpoint in warn mode
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the credential provider has a plain http token endpoint
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 200
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario: A Transit Point cannot use a provider with an http token endpoint when https is enforced
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 502
    And the credential provider received 0 token requests
    And MCP server "bravo" was not called

  Scenario: A tenant surface's Transit Point uses a global credential provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    And the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 200
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario: A tenant surface's Transit Point cannot use a global credential provider when tenant isolation is enforced
    Given the surface belongs to tenant "tenant-a"
    And the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway enforces the credential rule "tenant_credential_isolation"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 502
    And the credential provider received 0 token requests
    And MCP server "bravo" was not called

  Scenario: A tenant surface's Transit Point injects a delegated credential from a global provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    And Transit Point "alpha" requires a transit token
    And Transit Point "alpha" injects delegated credentials from a client credentials provider
    And managed agent "example-agent" holds a transit token naming caller "alice"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 200
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario: A tenant surface's Transit Point cannot inject a delegated credential from a global provider when tenant isolation is enforced
    Given the surface belongs to tenant "tenant-a"
    And Transit Point "alpha" requires a transit token
    And Transit Point "alpha" injects delegated credentials from a client credentials provider
    And the gateway enforces the credential rule "tenant_credential_isolation"
    And managed agent "example-agent" holds a transit token naming caller "alice"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 503
    And the credential provider received 0 token requests
    And MCP server "bravo" was not called
