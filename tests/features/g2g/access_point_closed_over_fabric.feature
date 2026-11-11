Feature: Closed Access Points over fabric
  A closed or legacy Access Point refuses a caller whose credential is
  missing or invalid when the request arrives over fabric, as it does on
  direct inbound.
  A closed Access Point without source authentication is not ready and refuses
  every caller.

  Scenario: gateway 2 refuses every caller on a closed Access Point without source authentication
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the operator has closed the Access Point of surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools without an API key
    Then the response status is 503
    And the MCP response is a JSON-RPC error with code -32603
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: gateway 2 refuses a caller without an API key on a closed Access Point
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" requires "API Key" source authentication
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the operator has closed the Access Point of surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools without an API key
    Then the response status is 401
    And the MCP response is a JSON-RPC error with code -32603
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: gateway 2 admits a caller with a valid API key on a closed Access Point
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" requires "API Key" source authentication
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the operator has closed the Access Point of surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools with a valid API key
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive header "x-api-key"

  Scenario: gateway 2 refuses a caller without an API key on a legacy Access Point
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" is stored as a legacy surface
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools without an API key
    Then the response status is 401
    And the MCP response is a JSON-RPC error with code -32603
    And the MCP response id matches the request id
    And MCP server "bravo" was not called
