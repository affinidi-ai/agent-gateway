Feature: Credential policy on the request path
  The bootstrap credential policy decides whether a stored credential provider that
  breaks a credential rule still authenticates the Target. In warn mode the request
  is forwarded with the provider's token; in enforce mode target authentication
  fails before any token request and the Target is not called.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a client credentials provider
    And the gateway keeps its log of warnings

  Scenario: A provider with an http token endpoint authenticates the Target in warn mode
    Given the target's credential provider has a plain http token endpoint
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the target's credential provider received 1 token request
    And the gateway log has a warning containing "Credential provider token endpoint is not https; it will be refused once credential_policy.token_endpoint_https is enforce"
    And the gateway log shows no credential provider secret or token

  Scenario: A provider with an http token endpoint is refused when https token endpoints are enforced
    Given the target's credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller sends a request to the surface
    Then the response status is 502
    And the target's credential provider received 0 token requests
    And managed agent "bravo" was not called
    And the gateway log has a warning containing "Refusing a credential provider token endpoint that is not https"
    And the gateway log has no warning containing "it will be refused once credential_policy.token_endpoint_https is enforce"
    And the gateway log shows no credential provider secret or token

  Scenario: A tenant surface uses a global credential provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the target's credential provider received 1 token request
    And the gateway log has a warning containing "Target auth provider is appliance-wide on a tenant surface; refused once tenant_credential_isolation is enforce"
    And the gateway log shows no credential provider secret or token

  Scenario: A tenant surface cannot use a global credential provider when tenant isolation is enforced
    Given the surface belongs to tenant "tenant-a"
    And the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller sends a request to the surface
    Then the response status is 502
    And the target's credential provider received 0 token requests
    And managed agent "bravo" was not called
    And the gateway log has no warning containing "refused once tenant_credential_isolation is enforce"

  Scenario: A global surface uses a global credential provider when tenant isolation is enforced
    Given the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the gateway log has no warning containing "appliance-wide on a tenant surface"

  Scenario: The startup report names a provider with an http token endpoint in warn mode
    Given the target's credential provider has a plain http token endpoint
    When the caller sends a request to the surface
    Then the startup report names the credential_provider "bdd-target-provider" as breaking the rule "token_endpoint_https" in warn mode
    And the gateway log shows no credential provider secret or token

  Scenario: The startup report marks a provider with an http token endpoint as enforced
    Given the target's credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller sends a request to the surface
    Then the startup report names the credential_provider "bdd-target-provider" as breaking the rule "token_endpoint_https" in enforce mode

  Scenario: The startup report names a tenant surface that uses a global credential provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    When the caller sends a request to the surface
    Then the startup report names the surface "bdd-surface" as breaking the rule "tenant_credential_isolation" in warn mode

  Scenario: The startup report stays silent when no stored rule is broken
    When the caller sends a request to the surface
    Then the gateway log has no warning containing "Stored configuration breaks a credential policy rule"

  Scenario: The agent card is fetched with a provider that has an http token endpoint in warn mode
    Given the target's credential provider has a plain http token endpoint
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the target's credential provider received 1 token request

  Scenario: The agent card fails when https token endpoints are enforced and the provider's is http
    Given the target's credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And the target's credential provider received 0 token requests
    And managed agent "bravo" was not called

  Scenario: A tenant surface's agent card is fetched with a global credential provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the target's credential provider received 1 token request

  Scenario: A tenant surface's agent card fails when tenant isolation is enforced
    Given the surface belongs to tenant "tenant-a"
    And the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And the target's credential provider received 0 token requests
    And managed agent "bravo" was not called
