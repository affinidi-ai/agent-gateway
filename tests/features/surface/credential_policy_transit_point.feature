Feature: Credential policy on a Transit Point
  A Transit Point that authenticates to its target endpoint, or injects a delegated
  credential, with a stored credential provider is held to the bootstrap credential policy
  like the Access Point. In warn mode the call is forwarded with the provider's token; in
  enforce mode the credential is withheld before any token request, and the fallback
  decides whether the call fails or goes on without it. A Transit Point checks its callers
  when it requires a transit token or has its own source authentication; one that checks
  callers' MCP authorization is covered by the save rules and unit tests. A target endpoint
  that refuses the Transit Point's token as invalid does not make the gateway drop it. A
  managed agent header named like the Transit Point's credential header never reaches the
  target endpoint.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"
    And Transit Point "alpha" is an Open Transit Point
    And MCP server "bravo" is reached over plain http
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

  Scenario: A Transit Point sends its Target credential to a plain http target endpoint in warn mode
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway keeps its log of warnings
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 200
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the gateway log has a warning containing "Target credential sent to an endpoint that is not https; it will be withheld once credential_policy.target_https is enforce"

  Scenario: A Transit Point withholds its Target credential from a plain http target endpoint when https Targets are enforced
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway enforces the credential rule "target_https"
    And the gateway keeps its log of warnings
    And the VP Audit Log keeps every audit event
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 502
    And the credential provider received 0 token requests
    And MCP server "bravo" was not called
    And the gateway log has no warning containing "it will be withheld once credential_policy.target_https is enforce"
    And the VP Audit Log records a Target credential of Transit Point "alpha" that was not sent, with outcome "rejected"

  Scenario: A Transit Point leaves out its Target credential for a plain http target endpoint when fallback is passthrough
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway's authentication to the destination of Transit Point "alpha" falls back to "passthrough"
    And the gateway enforces the credential rule "target_https"
    And the VP Audit Log keeps every audit event
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 200
    And MCP server "bravo" did not receive header "authorization"
    And the credential provider received 0 token requests
    And the VP Audit Log records a Target credential of Transit Point "alpha" that was not sent, with outcome "passthrough"

  Scenario: A Transit Point sends its Target credential for callers it does not check in warn mode
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway keeps its log of warnings
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 200
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the gateway log has a warning containing "Target credential sent for callers Transit Point 'alpha' does not authenticate; it will be withheld once credential_policy.target_source_auth is enforce"

  Scenario: A Transit Point withholds its Target credential for callers it does not check when Target source authentication is enforced
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway enforces the credential rule "target_source_auth"
    And the gateway keeps its log of warnings
    And the VP Audit Log keeps every audit event
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 502
    And the credential provider received 0 token requests
    And MCP server "bravo" was not called
    And the gateway log has no warning containing "it will be withheld once credential_policy.target_source_auth is enforce"
    And the VP Audit Log records a Target credential of Transit Point "alpha" that was not sent, with outcome "rejected"

  Scenario: An Access Point with two source authentication methods does not check a Transit Point's callers
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    And the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway enforces the credential rule "target_source_auth"
    And the VP Audit Log keeps every audit event
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 502
    And the credential provider received 0 token requests
    And MCP server "bravo" was not called
    And the VP Audit Log records a Target credential of Transit Point "alpha" that was not sent, with outcome "rejected"

  Scenario: A Transit Point that requires a transit token sends its Target credential when Target source authentication is enforced
    Given Transit Point "alpha" requires a transit token
    And the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway enforces the credential rule "target_source_auth"
    And managed agent "example-agent" holds a transit token naming caller "alice"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 200
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"

  Scenario: A Transit Point with its own source authentication sends its Target credential when Target source authentication is enforced
    Given the gateway enforces the credential rule "target_source_auth"
    And the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And Transit Point "alpha" authenticates its callers with API key "caller-key-1"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with header "x-api-key" set to "caller-key-1"
    Then the response status is 200
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And MCP server "bravo" did not receive header "x-api-key"

  Scenario: A Transit Point whose target endpoint refuses its token as invalid keeps the stored token
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And MCP server "bravo" refuses every request with status 401 and the challenge "Bearer error=invalid_token"
    And managed agent "example-agent" has asked for available tools through Transit Point "alpha" and received status 401
    And the gateway's token from the credential provider has aged 31 seconds
    And managed agent "example-agent" has asked for available tools through Transit Point "alpha" and received status 401
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 401
    And MCP server "bravo" received 3 requests
    And the credential provider received 1 token request

  Scenario: The startup report names a surface whose Transit Point sends a Target credential to a plain http target endpoint
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway keeps its log of warnings
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the startup report names the surface "bdd-surface" as breaking the rule "target_https" in warn mode

  Scenario: The startup report stays silent when no Transit Point or Target sends a credential
    Given the gateway keeps its log of warnings
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 200
    And the gateway log has no warning containing "Stored configuration breaks a credential policy rule"

  Scenario: A Transit Point request below its target endpoint's base path carries the Target credential
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the target endpoint of Transit Point "alpha" has the base path "/base"
    When managed agent "example-agent" asks for available tools through the Transit Point path "/transit/alpha/rpc" exactly as written
    Then the response status is 200
    And MCP server "bravo" received the forwarded path "/base/rpc"
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"

  Scenario Outline: A Transit Point request whose path leaves its target endpoint's base path is refused before the target endpoint
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the target endpoint of Transit Point "alpha" has the base path "/base"
    When managed agent "example-agent" asks for available tools through the Transit Point path "<path>" exactly as written
    Then the response status is 502
    And the response mentions "Target authentication credentials unavailable"
    And MCP server "bravo" was not called

    Examples:
      | path                               |
      | /transit/alpha/../admin            |
      | /transit/alpha/%2e%2e/admin        |
      | /transit/alpha/%2E%2E/%2e%2e/admin |
      | /transit/alpha/..;/admin           |

  Scenario: A Transit Point target endpoint's redirect is returned to the managed agent instead of being followed with the credential
    Given the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And MCP server "bravo" answers every request with a redirect to its path "/elsewhere"
    When managed agent "example-agent" asks for available tools through the Transit Point path "/transit/alpha/rpc" exactly as written
    Then the response status is 302
    And MCP server "bravo" received 1 request
    And MCP server "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"

  Scenario Outline: A Transit Point drops a managed agent header named like its Target credential header
    Given the gateway authenticates to the destination of Transit Point "alpha" with missing secret "bdd-missing-target-secret" in header "X-Target-Api-Key", falling back to "passthrough"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with header "<header>" set to "agent-chosen-value"
    Then the response status is 200
    And MCP server "bravo" did not receive header "<header>"

    Examples:
      | header           |
      | X-TARGET-API-KEY |
      | x_target_api_key |

  Scenario: A managed agent header with another name reaches the Transit Point's target endpoint
    Given the gateway authenticates to the destination of Transit Point "alpha" with missing secret "bdd-missing-target-secret" in header "X-Target-Api-Key", falling back to "passthrough"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with header "X-Agent-Note" set to "agent-chosen-value"
    Then the response status is 200
    And MCP server "bravo" received header "x-agent-note" with value "agent-chosen-value"
    And MCP server "bravo" did not receive header "x-target-api-key"
