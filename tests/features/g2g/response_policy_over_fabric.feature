Feature: Surface response policies over Fabric
  A gateway evaluates the response policy of the surface a peer gateway reaches over
  Fabric on its Target's answers as it does for a direct caller (the complete result of
  a modern MCP response, and every answer other than the public agent card), and records
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

  Scenario: A response policy checks each event of a streamed A2A answer to a Fabric caller
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" answers with an event stream whose last event names a secret
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that denies an answer naming a secret
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 403
    And the response says "response_policy_denied"
    And the VP Audit Log of gateway 2 records a response policy "deny" on the Fabric request

  Scenario: A comment in a streamed A2A answer does not reach a Fabric caller past the response policy
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" answers with an event stream carrying the comment "unchecked-note"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has a response policy that allows every response
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And the response says "delivered"
    And the response does not say "unchecked-note"

  Scenario: The response policy of a surface with a fabric:// Target refuses the answer it gets back
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 1 keeps every audit event
    And surface "charlie" has a response policy that denies every response
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 403
    And the response says "response_policy_denied"
    And managed agent "bravo" received one forwarded message
    And the VP Audit Log of gateway 1 records a response policy "deny" on surface "charlie"

  Scenario: The response policy of a surface with a fabric:// Target lets a plain answer through
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 1 keeps every audit event
    And surface "charlie" has a response policy that denies an answer naming a secret
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And the A2A response result matches managed agent "bravo" response result
    And the VP Audit Log of gateway 1 records a response policy "allow" on surface "charlie"

  Scenario: The response policy of a surface with a fabric:// Target refuses an answer naming a secret
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" answers naming a secret
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 1 keeps every audit event
    And surface "charlie" has a response policy that denies an answer naming a secret
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 403
    And the response says "response_policy_denied"
    And managed agent "bravo" received one forwarded message
    And the VP Audit Log of gateway 1 records a response policy "deny" on surface "charlie"

  Scenario: A response policy does not refuse an agent card fetched over Fabric
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" serves an agent card
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that denies every response
    When the caller fetches the agent card from gateway 1 surface "charlie"
    Then the response status is 200
    And the agent card points callers at gateway 1 surface "charlie"
    And the VP Audit Log of gateway 2 records no response policy decision

  Scenario: A response policy refuses a discovery document other than the agent card fetched over Fabric
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that denies every response
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/ucp"
    Then the response status is 403
    And the response says "response_policy_denied"
    And the VP Audit Log of gateway 2 records a response policy "deny" on the Fabric request

  Scenario: A response policy refuses an answer to a path that only names the agent card in its query, fetched over Fabric
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that denies every response
    When the caller sends a GET request to gateway 1 surface "charlie" path "/x?y=/.well-known/agent.json"
    Then the response status is 403
    And the response says "response_policy_denied"
    And the VP Audit Log of gateway 2 records a response policy "deny" on the Fabric request

  Scenario: A response policy refuses an A2A proxy answer to a Fabric caller
    Given a fabric with 2 gateways
    And gateway 2 exposes A2A surface "alpha" backed by non-A2A managed agent "bravo" through an A2A proxy endpoint
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    And surface "alpha" has a response policy that denies every response
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 403
    And the response says "response_policy_denied"
    And non-A2A managed agent "bravo" received text "g2g-bdd"
    And the VP Audit Log of gateway 2 records a response policy "deny" on the Fabric request

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

  Scenario: MCP tool gating hides a tool from an MCP Proxy's tool list sent over Fabric
    Given a fabric with 2 gateways
    And gateway 2 exposes MCP surface "alpha" backed by REST API "bravo" through an MCP proxy endpoint
    And the MCP proxy of surface "alpha" offers the weather tools
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" lists only MCP tool "get_weather"
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 200
    And the MCP response tool catalog includes a tool named "get_weather"
    And the response does not say "get_forecast"

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
