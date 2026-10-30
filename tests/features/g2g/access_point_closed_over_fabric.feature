Feature: Closed Access Points over fabric
  A closed Access Point refuses a caller whose credential is missing or
  invalid when the request arrives over fabric, as it does on direct inbound.

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
