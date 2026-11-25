Feature: Source authentication and target authentication over fabric
  Scenario: Source authentication allows a valid caller over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    When the caller asks gateway 1 MCP surface "charlie" for available tools with a valid API key
    Then MCP server "bravo" received the forwarded MCP request with the original body
    And MCP server "bravo" did not receive header "x-api-key"
    And the response status is 200
    And the MCP response result matches MCP server "bravo" response result

  Scenario: Target authentication is injected over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then MCP server "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And the response status is 200
    And the MCP response result matches MCP server "bravo" response result

  Scenario: gateway 1 refuses a caller without an API key before forwarding over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    When the caller asks gateway 1 MCP surface "charlie" for available tools without an API key
    Then the response status is 401
    And the MCP response is a JSON-RPC error with code -32603
    And MCP server "bravo" was not called

  Scenario: a public surface on gateway 2 withholds target authentication from a caller whose source authentication failed
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" is stored with a public Access Point
    When the caller asks gateway 1 MCP surface "charlie" for available tools without an API key
    Then MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive header "x-target-api-key"
    And the response status is 200

  Scenario: gateway 2 sends target authentication for a caller it authenticated
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools with a valid API key
    Then MCP server "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And the response status is 200

  Scenario: gateway 2 refuses a caller whose source authentication failed on an MCP proxy endpoint
    Given a fabric with 2 gateways
    And gateway 2 exposes MCP surface "alpha" backed by REST API "bravo" through an MCP proxy endpoint
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller invokes MCP tool "ping" through gateway 1 surface "charlie"
    Then the response status is 401
    And REST API "bravo" was not called

  Scenario: gateway 2 sends target authentication on an MCP proxy endpoint when the surface requires no caller authentication
    Given a fabric with 2 gateways
    And gateway 2 exposes MCP surface "alpha" backed by REST API "bravo" through an MCP proxy endpoint
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller invokes MCP tool "ping" through gateway 1 surface "charlie"
    Then the response status is 200
    And REST API "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: gateway 1 refuses a caller whose source authentication failed before sending its target authentication
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    And surface "charlie" injects target authentication from secret "bdd-sender-auth-secret" with value "bdd-sender-secret" as header "x-sender-api-key"
    When the caller asks gateway 1 MCP surface "charlie" for available tools without an API key
    Then the response status is 401
    And MCP server "bravo" was not called

  Scenario: gateway 1 sends its target authentication for an authenticated caller
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    And surface "charlie" injects target authentication from secret "bdd-sender-auth-secret" with value "bdd-sender-secret" as header "x-sender-api-key"
    When the caller asks gateway 1 MCP surface "charlie" for available tools with a valid API key
    Then MCP server "bravo" received header "x-sender-api-key" with value "bdd-sender-secret"
    And the response status is 200

  Scenario: gateway 2 sends target authentication when gateway 1 fetches the agent card over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller fetches the agent card from gateway 1 surface "charlie"
    Then managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: a public surface on gateway 1 blocks unverified callers when a gateway-level policy denies them
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    And gateway 1 has a Gateway-level policy that denies unverified callers
    And surface "charlie" is stored with a public Access Point
    When the caller asks gateway 1 MCP surface "charlie" for available tools without an API key
    Then the response status is 403
    And MCP server "bravo" was not called

  Scenario: gateway 1 reports a Target credential that gateway 2 refuses
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" requires "API Key" source authentication
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" injects target authentication from secret "bdd-gateway-1-key" with value "bdd-key-gateway-2-refuses" as header "x-api-key"
    And the VP Audit Log of gateway 1 keeps every audit event
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 500
    And the response says "target_auth_rejected"
    And MCP server "bravo" was not called
    And the VP Audit Log of gateway 1 records the Target credential as refused by the target

  Scenario: a 401 from gateway 2's Target reaches the caller unchanged
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" refuses every request with status 401
    And surface "alpha" requires "API Key" source authentication
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" injects target authentication from secret "bdd-gateway-1-key" with value "bdd-source-api-key" as header "x-api-key"
    And the VP Audit Log of gateway 1 keeps every audit event
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 401
    And the VP Audit Log of gateway 1 records no Target credential refused by the target

  Scenario: gateway 2 rejects forwarding when target authentication credentials are missing
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback reject
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 500
    And the response says "Target authentication failed"
    And the response reason is "target_auth_misconfigured"
    And MCP server "bravo" was not called

  Scenario: gateway 2 forwards over fabric when missing target authentication fallback is passthrough
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback passthrough
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive header "x-target-api-key"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result

  Scenario: gateway 1 sends no identity proof of a caller whose API key failed on a public Access Point deriving the inbound identity from it
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    And surface "charlie" derives the inbound identity from the API key the caller presents
    And surface "charlie" is stored with a public Access Point
    When the caller sends a Fabric A2A request with an invalid API key and an identity proof of its own through gateway 1 surface "charlie"
    Then the response status is 200
    And managed agent "bravo" received the forwarded message with no caller identity
