Feature: MCP requests travel across gateways over fabric
  Scenario: MCP tools/list reaches the remote MCP server over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools
    Then MCP server "bravo" received the forwarded MCP request with the original body
    And the response status is 200
    And the MCP response result matches MCP server "bravo" response result

  Scenario: MCP tool catalog is proxied over fabric without mutation
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools
    Then MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/list"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And MCP server "bravo" received the original MCP request body
    And MCP server "bravo" received the forwarded MCP request with content type "application/json"
    And the response status is 200
    And the response content type is "application/json"
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario: MCP initialize handshake is forwarded over fabric and proxied back intact
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" supports initialization
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends an MCP initialize request to gateway 1 surface "charlie"
    Then MCP server "bravo" received MCP method "initialize"
    And the response status is 200
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response preserves MCP server "bravo" field "result.serverInfo.name"
    And the MCP response preserves MCP server "bravo" field "result.capabilities"
    And the MCP response result matches MCP server "bravo" response result

  Scenario: MCP tools/call request and result pass through fabric intact
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller invokes MCP tool "search" with a result limit of 3 through gateway 1 surface "charlie"
    Then MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received forwarded MCP field "params.name" unchanged
    And MCP server "bravo" received forwarded MCP field "params.arguments.limit" unchanged
    And the response status is 200
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result

  Scenario: MCP requests with unsupported content type are rejected before reaching the remote MCP server
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" supports initialization
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends an MCP initialize request with content type "text/plain" to gateway 1 surface "charlie"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32600
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: Malformed MCP request bodies are rejected as parse errors before reaching the remote MCP server
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a malformed MCP request to gateway 1 surface "charlie"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32700
    And MCP server "bravo" was not called

  Scenario: MCP requests without a method are rejected as invalid before reaching the remote MCP server
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends an MCP request without a method to gateway 1 surface "charlie"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32600
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: MCP notifications are acknowledged before reaching the remote MCP server
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends an MCP notification to gateway 1 surface "charlie"
    Then the response status is 204
    And MCP server "bravo" was not called

  Scenario: MCP tool policy denies an unlisted tool before reaching the remote MCP server
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" enforces an MCP tool policy allowing only tool "get_news"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller invokes MCP tool "delete_everything" through gateway 1 surface "charlie"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32000
    And MCP server "bravo" was not called

  Scenario: Source MCP tool policy denies an unlisted tool before fabric forwarding
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" enforces an MCP tool policy allowing only tool "get_news"
    When the caller invokes MCP tool "delete_everything" through gateway 1 surface "charlie"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32000
    And MCP server "bravo" was not called
    And gateway 2 did not receive a fabric forward request

  Scenario: Source MCP tool policy does not gate a notification before fabric forwarding
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" enforces an MCP tool policy allowing only tool "get_news"
    When the caller sends an MCP notification to gateway 1 surface "charlie"
    Then the response status is 204
    And MCP server "bravo" was not called
    And gateway 2 did not receive a fabric forward request

  Scenario: Unsupported modern MCP requests do not enter the fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools using protocol version "2025-11-25"
    Then the response status is 400
    And the MCP response is a JSON-RPC error with code -32022
    And the MCP response id matches the request id
    And the MCP unsupported-version error requests "2025-11-25" and supports only "2024-11-05, 2026-07-28"
    And MCP server "bravo" was not called
    And gateway 2 did not receive a fabric forward request

  Scenario: A modern sender talking to a legacy-only receiver fails fast
    Given a fabric with 2 gateways
    And gateway 2 admits only MCP protocol version "2024-11-05" over Fabric
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools using protocol version "2026-07-28"
    Then the response status is 400
    And the MCP response is a JSON-RPC error with code -32022
    And the MCP response id matches the request id
    And the MCP unsupported-version error requests "2026-07-28" and supports only "2024-11-05"
    And the response arrives in under 5 seconds
    And MCP server "bravo" was not called

  Scenario: Source MCP tool policy does not gate a request without a method before fabric forwarding
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" enforces an MCP tool policy allowing only tool "get_news"
    When the caller sends an MCP request without a method to gateway 1 surface "charlie"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32600
    And MCP server "bravo" was not called
    And gateway 2 did not receive a fabric forward request

  Scenario: MCP tool policy forwards an allowed tool to the remote MCP server
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And surface "alpha" enforces an MCP tool policy allowing only tool "get_news"
    And MCP server "bravo" supports tool invocation
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller invokes MCP tool "get_news" through gateway 1 surface "charlie"
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received forwarded MCP field "params.name" unchanged
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result

  Scenario: MCP proxy endpoint exposes REST operations as tools over fabric
    Given a fabric with 2 gateways
    And gateway 2 exposes MCP surface "alpha" backed by REST API "bravo" through an MCP proxy endpoint
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools
    Then the response status is 200
    And the MCP response tool catalog includes a tool named "ping"
    And REST API "bravo" was not called

  Scenario: The caller's bearer token does not travel over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools with bearer token "caller-only-secret"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive header "authorization"

  Scenario: A Legacy SSE session on gateway 1 reaches the remote MCP server over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools twice over one Legacy SSE session
    Then MCP server "bravo" received 2 forwarded MCP requests
    And each Legacy SSE reply answers its own request with MCP server "bravo" response result

  Scenario: A modern MCP request crosses fabric between MCP surfaces
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" serves a modern MCP tool catalog
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools using protocol version "2026-07-28"
    Then the response status is 200
    And the MCP response id matches the request id
    And the MCP response tool catalog includes a tool named "echo"
    And MCP server "bravo" received MCP _meta key "io.modelcontextprotocol/protocolVersion" with value "2026-07-28"

  Scenario: SSE MCP requests over fabric are answered as JSON
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller asks gateway 1 surface "charlie" for available MCP tools over SSE
    Then the response status is 200
    And the response content type is "application/json"
    And the MCP response result matches MCP server "bravo" response result
    And the MCP response includes fabric gateway DID metadata for MCP server "bravo"

  Scenario: Concurrent MCP requests keep their responses over fabric
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo" with 50-100 ms response delay
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends 50 concurrent MCP Echo calls to gateway 1 surface "charlie"
    Then all 50 responses have status 200
    And each MCP response matches the request that produced it
    And MCP server "bravo" received 50 forwarded MCP requests
