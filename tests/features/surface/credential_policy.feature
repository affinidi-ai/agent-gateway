Feature: Credential policy on the request path
  The bootstrap credential policy decides whether a stored credential provider that
  breaks a credential rule still authenticates the Target. In warn mode the request
  is forwarded with the provider's token; in enforce mode target authentication
  fails before any token request and the Target is not called.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a client credentials provider

  Scenario: A provider with an http token endpoint authenticates the Target in warn mode
    Given the target's credential provider has a plain http token endpoint
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the target's credential provider received 1 token request

  Scenario: A provider with an http token endpoint is refused when https token endpoints are enforced
    Given the target's credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller sends a request to the surface
    Then the response status is 502
    And the target's credential provider received 0 token requests
    And managed agent "bravo" was not called

  Scenario: A tenant surface uses a global credential provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the target's credential provider received 1 token request

  Scenario: A tenant surface cannot use a global credential provider when tenant isolation is enforced
    Given the surface belongs to tenant "tenant-a"
    And the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller sends a request to the surface
    Then the response status is 502
    And the target's credential provider received 0 token requests
    And managed agent "bravo" was not called

  Scenario: A global surface uses a global credential provider when tenant isolation is enforced
    Given the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
