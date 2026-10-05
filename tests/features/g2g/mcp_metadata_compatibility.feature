Feature: Canonical MCP metadata over Fabric
  Receiving gateways apply their metadata output preference independently.

  Scenario: A canonical receiving surface migrates historical metadata from a compatibility sender
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 2 surface "alpha" uses "canonical" MCP metadata output
    When the caller asks gateway 1 surface "charlie" for available MCP tools with top-level metadata key "tenant" value "acme"
    Then the response status is 200
    And MCP server "bravo" received MCP metadata key "tenant" only in "params._meta"
    And MCP server "bravo" received MCP _meta key "tenant" with value "acme"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP surface returns MCP server "bravo" tool catalog unchanged