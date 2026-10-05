Feature: HTTP MCP surface forwarding
  The gateway proxies MCP requests through MCP surfaces to their targets.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"

  Scenario: MCP tool catalog is proxied without mutation
    Given MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools
    Then MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/list"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And MCP server "bravo" received the original MCP request body
    And MCP server "bravo" received the forwarded MCP request with content type "application/json"
    And the response status is 200
    And the response content type is "application/json"
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario: MCP target authentication injects the configured header
    Given the surface injects target authentication from secret "bdd-target-api-key" with value "bdd-target-secret" as header "x-target-api-key"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: Missing MCP target authentication secret rejects the request when fallback is reject
    Given the surface injects target authentication from missing secret "bdd-missing-target-secret" as header "x-target-api-key" with fallback "reject"
    When the caller asks the MCP surface for available tools
    Then the response status is 502
    And MCP server "bravo" was not called

  Scenario: Missing MCP target authentication secret passes through when fallback is passthrough
    Given the surface injects target authentication from missing secret "bdd-missing-target-secret" as header "x-target-api-key" with fallback "passthrough"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive header "x-target-api-key"

  Scenario: MCP initialize handshake is forwarded and proxied back intact
    Given MCP server "bravo" supports initialization
    When the caller sends an MCP initialize request
    Then MCP server "bravo" received MCP method "initialize"
    And the response status is 200
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response preserves MCP server "bravo" field "result.serverInfo.name"
    And the MCP response preserves MCP server "bravo" field "result.capabilities"
    And the MCP response result matches MCP server "bravo" response result

  Scenario: MCP tools/call request and result pass through intact
    Given MCP server "bravo" supports tool invocation
    When the caller invokes the MCP tool "search" with a result limit of 3
    Then MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received forwarded MCP field "params.name" unchanged
    And MCP server "bravo" received forwarded MCP field "params.arguments.limit" unchanged
    And the response status is 200
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result

  Scenario: MCP requests with unsupported content type are rejected before reaching the MCP server
    Given MCP server "bravo" supports initialization
    When the caller sends an MCP initialize request with content type "text/plain"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32600
    And the MCP response id matches the request id

  Scenario: Malformed MCP request bodies are rejected as parse errors before reaching the MCP server
    When the caller sends a malformed MCP request
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32700
    And MCP server "bravo" was not called

  Scenario: MCP requests without a method are rejected as invalid before reaching the MCP server
    When the caller sends an MCP request without a method
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32600
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: MCP notifications are acknowledged without reaching the MCP server
    When the caller sends an MCP notification
    Then the response status is 204
    And MCP server "bravo" was not called

  Scenario: Unsupported modern MCP requests do not enter legacy processing
    When the caller asks the MCP surface for available tools using protocol version "2026-07-28"
    Then the response status is 400
    And the MCP response is a JSON-RPC error with code -32022
    And the MCP response id matches the request id
    And the MCP unsupported-version error requests "2026-07-28" and supports only "2024-11-05"
    And MCP server "bravo" was not called

  Scenario: Mismatched modern MCP method metadata is rejected
    When the caller sends a modern MCP tool catalog request with mirrored method "tools/call"
    Then the response status is 400
    And the MCP response is a JSON-RPC error with code -32020
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: Modern MCP requests require per-request capabilities
    When the caller asks the MCP surface for available tools using protocol version "2026-07-28" without per-request capabilities
    Then the response status is 400
    And the MCP response is a JSON-RPC error with code -32602
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: Modern MCP requests carrying a batch of messages are rejected before reaching the MCP server
    When the caller sends a batch of modern MCP tool catalog requests
    Then the response status is 400
    And the MCP response is a JSON-RPC error with code -32600
    And MCP server "bravo" was not called

  Scenario: Tool parameter headers are forwarded to the MCP server unchanged
    When the caller asks the MCP surface for available tools with header "Mcp-Param-Region" set to "eu-west-1"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received header "Mcp-Param-Region" with value "eu-west-1"

  Scenario: Authenticated MCP requests are forwarded with the source credential stripped
    Given the surface requires "API Key" source authentication
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive header "X-API-Key"

  Scenario Outline: An MCP request to a discovery-like path still runs source authentication and policy
    Given the surface requires "API Key" source authentication
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface path "<path>"
    Then the response status is 403
    And MCP server "bravo" was not called

    Examples:
      | path              |
      | /smoke/agent.json |
      | /smoke/discovery  |

  Scenario: MCP tool policy denies an unlisted tool before reaching the MCP server
    Given the MCP surface enforces a tool policy allowing only tool "get_news"
    When the caller invokes MCP tool "delete_everything"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32000
    And MCP server "bravo" was not called

  Scenario: MCP tool policy forwards an allowed tool to the MCP server
    Given the MCP surface enforces a tool policy allowing only tool "get_news"
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "get_news"
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received forwarded MCP field "params.name" unchanged

  Scenario: Wildcard default tool policy allows any tool without an explicit per-tool entry
    Given the MCP surface enforces a wildcard default tool policy that allows all tools
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "any_tool"
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/call"

  Scenario: Wildcard default tool policy denies any tool when it is a deny policy
    Given the MCP surface enforces a wildcard default tool policy that denies all tools
    When the caller invokes MCP tool "any_tool"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32000
    And MCP server "bravo" was not called

  Scenario: Explicit per-tool entry allows the named tool when wildcard default denies
    Given the MCP surface enforces a tool policy allowing only tool "get_news" with a wildcard deny default
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "get_news"
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/call"

  Scenario: Wildcard deny default blocks a tool not covered by an explicit per-tool entry
    Given the MCP surface enforces a tool policy allowing only tool "get_news" with a wildcard deny default
    When the caller invokes MCP tool "delete_everything"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32000
