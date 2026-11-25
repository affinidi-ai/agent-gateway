Feature: Surface response policies over Fabric
  A gateway evaluates the response policy of the surface a peer gateway reaches over
  Fabric on every answer its Target gives, as it does for a direct caller, and records
  each decision.

  Scenario: A response policy refuses an A2A answer to a Fabric caller
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a request policy that allows all requests
    And surface "alpha" has a response policy that denies every response
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 403
    And the response says "response_policy_denied"
    And managed agent "bravo" received one forwarded message
    And the VP Audit Log of gateway 2 records a response policy "deny" on the Fabric request under the trace id of its request policy decision

  Scenario: A response policy lets an A2A answer through to a Fabric caller
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that allows every response
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And the A2A response result matches managed agent "bravo" response result
    And the VP Audit Log of gateway 2 records a response policy "allow" on the Fabric request

  Scenario: A response policy does not refuse an agent card fetched over Fabric
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" serves an agent card
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has a response policy that denies every response
    When the caller fetches the agent card from gateway 1 surface "charlie"
    Then the response status is 200
    And the agent card points callers at gateway 1 surface "charlie"

  Scenario: A response policy refuses a legacy MCP answer to a Fabric caller
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that denies every response
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 403
    And the response says "response_policy_denied"
    And MCP server "bravo" received the forwarded MCP request
    And the VP Audit Log of gateway 2 records a response policy "deny" on the Fabric request

  Scenario: A response policy over Fabric sees the tool list after MCP tool gating hid a tool
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" lists only MCP tool "get_news"
    And surface "alpha" has a response policy that denies a tool list naming tool "summarize"
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 200
    And the MCP response tool catalog includes a tool named "get_news"
    And the response does not say "summarize"
    And the VP Audit Log of gateway 2 records a response policy "allow" on the Fabric request

  Scenario: A response policy refuses a modern MCP answer to a Fabric caller
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" serves a modern MCP tool catalog
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that denies every response
    When the caller asks gateway 1 MCP surface "charlie" for available tools using protocol version "2026-07-28"
    Then the response status is 502
    And the caller receives no result from MCP server "bravo"
    And MCP server "bravo" received the forwarded MCP request
    And the VP Audit Log of gateway 2 records a response policy "deny" on the Fabric request

  Scenario: A response policy refuses an MCP Proxy answer to a Fabric caller
    Given a fabric with 2 gateways
    And gateway 2 exposes MCP surface "alpha" backed by REST API "bravo" through an MCP proxy endpoint
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that denies every response
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32000
    And the VP Audit Log of gateway 2 records a response policy "deny" on the Fabric request
