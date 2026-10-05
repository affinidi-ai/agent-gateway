Feature: Source authentication and target authentication over fabric
  Scenario: Source authentication allows a valid caller over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    When the caller asks gateway 1 surface "charlie" for available MCP tools with a valid API key
    Then MCP server "bravo" received the forwarded MCP request with the original body
    And MCP server "bravo" did not receive header "x-api-key"
    And the response status is 200
    And the MCP response result matches MCP server "bravo" response result

  Scenario: Target authentication is injected over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools
    Then MCP server "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And the response status is 200
    And the MCP response result matches MCP server "bravo" response result

  Scenario: gateway 1 forwards callers without source authentication when no blocking policy is configured
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    When the caller asks gateway 1 surface "charlie" for available MCP tools without an API key
    Then MCP server "bravo" received the forwarded MCP request
    And the response status is 200

  Scenario: gateway 1 blocks unverified callers when a gateway-level policy denies them
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires "API Key" source authentication
    And gateway 1 has a Gateway-level policy that denies unverified callers
    When the caller asks gateway 1 surface "charlie" for available MCP tools without an API key
    Then the response status is 403
    And MCP server "bravo" was not called

  Scenario: gateway 2 rejects forwarding when target authentication credentials are missing
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback reject
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools
    Then the response status is 502
    And MCP server "bravo" was not called

  Scenario: gateway 2 forwards over fabric when missing target authentication fallback is passthrough
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback passthrough
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive header "x-target-api-key"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result
