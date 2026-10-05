Feature: Gateway-level policies control fabric callers
  Scenario: Gateway-level policy blocks a fabric caller before the MCP server is reached
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 2 has a Gateway-level policy that rejects all fabric callers
    When the caller asks gateway 1 surface "charlie" for available MCP tools
    Then the response status is 403
    And MCP server "bravo" was not called

  Scenario: Gateway-level policy rejects gateway 3 when only gateway 1 is allowed
    Given a fabric with 3 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 3 has an MCP surface "delta" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 2 has a Gateway-level policy that accepts fabric calls only from gateway 1
    When the caller asks gateway 3 surface "delta" for available MCP tools
    Then the response status is 403
    And MCP server "bravo" was not called

  Scenario: Gateway-level policy accepts gateway 1 when only gateway 1 is allowed
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 2 has a Gateway-level policy that accepts fabric calls only from gateway 1
    When the caller asks gateway 1 surface "charlie" for available MCP tools
    Then MCP server "bravo" received the forwarded MCP request with the original body
    And the response status is 200
    And the MCP response result matches MCP server "bravo" response result
