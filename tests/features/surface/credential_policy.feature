Feature: Credential policy on the request path
  The bootstrap credential policy decides whether a stored credential provider that
  breaks a credential rule still authenticates the Target. In warn mode the request
  is forwarded with the provider's token; in enforce mode target authentication
  fails before any token request and the Target is not called. The same holds for a
  Target credential sent to a Target that is not https, or for callers the surface
  does not authenticate. When a caller asks for the agent card, the gateway fetches it
  from the managed agent on its own behalf, so the card fetch is held to the https rule
  but not to the caller rule.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" is reached over plain http
    And the surface's Access Point does not check its callers
    And the gateway authenticates to the managed agent with a client credentials provider
    And the gateway keeps its log of warnings

  Scenario: A provider with an http token endpoint authenticates the Target in warn mode
    Given the credential provider has a plain http token endpoint
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request
    And the gateway log has a warning containing "Credential provider token endpoint is not https; it will be refused once credential_policy.token_endpoint_https is enforce"
    And the gateway log shows no credential provider secret or token

  Scenario: A provider with an http token endpoint is refused when https token endpoints are enforced
    Given the credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller sends a request to the surface
    Then the response status is 502
    And the credential provider received 0 token requests
    And the token request metric counts no requests
    And managed agent "bravo" was not called
    And the gateway log has a warning containing "Refusing a credential provider token endpoint that is not https"
    And the gateway log has no warning containing "it will be refused once credential_policy.token_endpoint_https is enforce"
    And the gateway log shows no credential provider secret or token

  Scenario: A tenant surface uses a global credential provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request
    And the gateway log has a warning containing "Target auth provider is appliance-wide on a tenant surface; refused once tenant_credential_isolation is enforce"
    And the gateway log shows no credential provider secret or token

  Scenario: A tenant surface cannot use a global credential provider when tenant isolation is enforced
    Given the surface belongs to tenant "tenant-a"
    And the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller sends a request to the surface
    Then the response status is 502
    And the credential provider received 0 token requests
    And managed agent "bravo" was not called
    And the gateway log has no warning containing "refused once tenant_credential_isolation is enforce"

  Scenario: A global surface uses a global credential provider when tenant isolation is enforced
    Given the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the gateway log has no warning containing "appliance-wide on a tenant surface"

  Scenario: The startup report names a provider with an http token endpoint in warn mode
    Given the credential provider has a plain http token endpoint
    When the caller sends a request to the surface
    Then the startup report names the credential_provider "bdd-target-provider" as breaking the rule "token_endpoint_https" in warn mode
    And the gateway log shows no credential provider secret or token

  Scenario: The startup report marks a provider with an http token endpoint as enforced
    Given the credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller sends a request to the surface
    Then the startup report names the credential_provider "bdd-target-provider" as breaking the rule "token_endpoint_https" in enforce mode

  Scenario: The startup report names a tenant surface that uses a global credential provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    When the caller sends a request to the surface
    Then the startup report names the surface "bdd-surface" as breaking the rule "tenant_credential_isolation" in warn mode

  Scenario: The startup report names a surface that sends a Target credential to a plain http Target
    When the caller sends a request to the surface
    Then the startup report names the surface "bdd-surface" as breaking the rule "target_https" in warn mode

  Scenario: The startup report marks a surface that sends a Target credential to a plain http Target as enforced
    Given the gateway enforces the credential rule "target_https"
    When the caller sends a request to the surface
    Then the startup report names the surface "bdd-surface" as breaking the rule "target_https" in enforce mode

  Scenario: The startup report names a surface that sends a Target credential without checking callers
    When the caller sends a request to the surface
    Then the startup report names the surface "bdd-surface" as breaking the rule "target_source_auth" in warn mode

  Scenario: The startup report does not name a surface whose callers are checked for source authentication
    Given the surface requires "API Key" source authentication
    When the caller sends a request to the surface
    Then the startup report does not name the surface "bdd-surface" as breaking the rule "target_source_auth"

  Scenario: The startup report does not name a surface whose callers are checked by two source authentication methods
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    When the caller sends a request to the surface
    Then the startup report does not name the surface "bdd-surface" as breaking the rule "target_source_auth"

  Scenario: The startup report stays silent about the credential provider and tenant rules when none is broken
    When the caller sends a request to the surface
    Then the startup report does not name the credential_provider "bdd-target-provider" as breaking the rule "token_endpoint_https"
    And the startup report does not name the surface "bdd-surface" as breaking the rule "tenant_credential_isolation"

  Scenario: A Target credential goes to a plain http Target in warn mode
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the gateway log has a warning containing "Target credential sent to an endpoint that is not https; it will be withheld once credential_policy.target_https is enforce"
    And the gateway log shows no credential provider secret or token

  Scenario: A Target credential is withheld from a plain http Target when https Targets are enforced
    Given the gateway enforces the credential rule "target_https"
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface
    Then the response status is 502
    And the credential provider received 0 token requests
    And the token request metric counts no requests
    And managed agent "bravo" was not called
    And the gateway log has no warning containing "it will be withheld once credential_policy.target_https is enforce"
    And the gateway log has no warning containing "Target credential sent"
    And the VP Audit Log records a Target credential that was not sent, with outcome "rejected" and no OAuth error

  Scenario: A Target credential withheld from a plain http Target is left out when fallback is passthrough
    Given the gateway's authentication to the managed agent falls back to "passthrough"
    And the gateway enforces the credential rule "target_https"
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" did not receive header "authorization"
    And the credential provider received 0 token requests
    And the token request metric counts no requests
    And the VP Audit Log records a Target credential that was not sent, with outcome "passthrough" and no OAuth error

  Scenario: A Target credential goes out for callers the surface does not check in warn mode
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the gateway log has a warning containing "Target credential sent for callers the surface does not authenticate; it will be withheld once credential_policy.target_source_auth is enforce"

  Scenario: A Target credential is withheld for unchecked callers when Target source authentication is enforced
    Given the gateway enforces the credential rule "target_source_auth"
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface
    Then the response status is 502
    And the credential provider received 0 token requests
    And the token request metric counts no requests
    And managed agent "bravo" was not called
    And the gateway log has no warning containing "it will be withheld once credential_policy.target_source_auth is enforce"
    And the gateway log has no warning containing "Target credential sent"
    And the VP Audit Log records a Target credential that was not sent, with outcome "rejected" and no OAuth error

  Scenario: A Target credential withheld for unchecked callers is left out when fallback is passthrough
    Given the gateway's authentication to the managed agent falls back to "passthrough"
    And the gateway enforces the credential rule "target_source_auth"
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" did not receive header "authorization"
    And the credential provider received 0 token requests
    And the token request metric counts no requests
    And the VP Audit Log records a Target credential that was not sent, with outcome "passthrough" and no OAuth error

  Scenario: A Target credential goes out for authenticated callers when Target source authentication is enforced
    Given the surface requires "API Key" source authentication
    And the gateway enforces the credential rule "target_source_auth"
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the gateway log has no warning containing "credential_policy.target_source_auth is enforce"

  Scenario Outline: A Target credential goes out for a caller verified by either of two methods when Target source authentication is enforced
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    And the gateway enforces the credential rule "target_source_auth"
    When the caller sends a request to the surface <credential condition>
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And managed agent "bravo" did not receive header "x-api-key"
    And the credential provider received 1 token request

    Examples:
      | credential condition |
      | with a valid token   |
      | with a valid API key |

  Scenario Outline: A Target credential goes out for a caller verified by either of two methods in warn mode without a warning
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    And the gateway only warns on the credential rule "target_source_auth"
    When the caller sends a request to the surface <credential condition>
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the gateway log has no warning containing "credential_policy.target_source_auth is enforce"

    Examples:
      | credential condition |
      | with a valid token   |
      | with a valid API key |

  Scenario Outline: A caller carrying credentials for two source authentication methods gets no Target credential
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    And the gateway <rule mode> the credential rule "target_source_auth"
    When the caller sends a request to the surface with a valid token and a valid API key
    Then the response status is 200
    And managed agent "bravo" did not receive header "authorization"
    And managed agent "bravo" did not receive header "x-api-key"
    And the credential provider received 0 token requests
    And the gateway log has no warning containing "credential_policy.target_source_auth is enforce"

    Examples:
      | rule mode     |
      | enforces      |
      | only warns on |

  Scenario: The agent card fetch keeps the Target credential when Target source authentication is enforced
    Given the gateway enforces the credential rule "target_source_auth"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"

  Scenario: The agent card fails when https Targets are enforced and the Target is plain http
    Given the gateway enforces the credential rule "target_https"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And the credential provider received 0 token requests
    And managed agent "bravo" was not called

  Scenario: The agent card is fetched with a provider that has an http token endpoint in warn mode
    Given the credential provider has a plain http token endpoint
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario: The agent card fails when https token endpoints are enforced and the provider's is http
    Given the credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And the credential provider received 0 token requests
    And managed agent "bravo" was not called

  Scenario: A tenant surface's agent card is fetched with a global credential provider in warn mode
    Given the surface belongs to tenant "tenant-a"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario: A tenant surface's agent card fails when tenant isolation is enforced
    Given the surface belongs to tenant "tenant-a"
    And the gateway enforces the credential rule "tenant_credential_isolation"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And the credential provider received 0 token requests
    And managed agent "bravo" was not called

  Scenario: A Target that refuses a freshly issued token as invalid does not make the gateway request another
    Given managed agent "bravo" is failing with status 401
    And managed agent "bravo" responds with header "WWW-Authenticate" set to "Bearer error=invalid_token"
    And the caller has sent a request to the surface and received status 401
    When the caller sends a request to the surface
    Then the response status is 401
    And the credential provider received 1 token request
    And the token request metric counts 1 "success" request for provider type "oauth2_client_credentials"
    And the gateway log shows no credential provider secret or token

  Scenario: A Target that answers 401 without invalid_token keeps the provider's token
    Given managed agent "bravo" is failing with status 401
    And managed agent "bravo" responds with header "WWW-Authenticate" set to "Bearer realm=api"
    And the caller has sent a request to the surface and received status 401
    And the gateway's token from the credential provider has aged 31 seconds
    And the caller has sent a request to the surface and received status 401
    When the caller sends a request to the surface
    Then the response status is 401
    And the credential provider received 1 token request

  Scenario: A Target that answers 403 keeps the provider's token
    Given managed agent "bravo" is failing with status 403
    And managed agent "bravo" responds with header "WWW-Authenticate" set to "Bearer error=invalid_token"
    And the caller has sent a request to the surface and received status 403
    And the gateway's token from the credential provider has aged 31 seconds
    And the caller has sent a request to the surface and received status 403
    When the caller sends a request to the surface
    Then the response status is 403
    And the credential provider received 1 token request

  Scenario: A Target that refuses a token older than 30 seconds as invalid makes the next request get a new one
    Given managed agent "bravo" is failing with status 401
    And managed agent "bravo" responds with header "WWW-Authenticate" set to "Bearer error=invalid_token"
    And the caller has sent a request to the surface and received status 401
    And the gateway's token from the credential provider has aged 31 seconds
    And the caller has sent a request to the surface and received status 401
    When the caller sends a request to the surface
    Then the response status is 401
    And the credential provider received 2 token requests
    And the token request metric counts 2 "success" requests for provider type "oauth2_client_credentials"

  Scenario: A Target credential that is sent leaves no refusal in the VP Audit Log
    Given the VP Audit Log keeps every audit event
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the VP Audit Log records no Target credential that was not sent

  Scenario: A refused token request records its registered OAuth error code in the VP Audit Log
    Given the VP Audit Log keeps every audit event
    And the credential provider refuses token requests with error "invalid_client" and description "bdd-description"
    When the caller sends a request to the surface
    Then the response status is 502
    And managed agent "bravo" was not called
    And the VP Audit Log records a Target credential that was not sent, with outcome "rejected" and OAuth error "invalid_client"

  Scenario: A refused token request records an unregistered OAuth error code as other in the VP Audit Log
    Given the VP Audit Log keeps every audit event
    And the credential provider refuses token requests with error "bdd_unlisted_error" and description "bdd-description"
    When the caller sends a request to the surface
    Then the response status is 502
    And managed agent "bravo" was not called
    And the VP Audit Log records a Target credential that was not sent, with outcome "rejected" and OAuth error "other"
