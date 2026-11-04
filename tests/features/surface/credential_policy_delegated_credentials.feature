Feature: Credential policy on delegated credentials
  A surface that injects a delegated credential from a stored client credentials
  provider is held to the bootstrap credential policy. In warn mode the provider's
  token is injected and the request forwarded; in enforce mode the delegated
  credential is unavailable before any token request and the Target is not called.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface requires delegated credentials from a client credentials provider

  Scenario: A delegated credential from a provider with an http token endpoint is injected in warn mode
    Given the credential provider has a plain http token endpoint
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario: A delegated credential from a provider with an http token endpoint is refused when https is enforced
    Given the credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller sends a request to the surface with a valid token
    Then the response status is 503
    And the credential provider received 0 token requests
    And managed agent "bravo" was not called

  Scenario: A tenant surface injects a delegated credential from a global provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario: A tenant surface cannot inject a delegated credential from a global provider when tenant isolation is enforced
    Given the surface belongs to tenant "tenant-a"
    And the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller sends a request to the surface with a valid token
    Then the response status is 503
    And the credential provider received 0 token requests
    And managed agent "bravo" was not called
