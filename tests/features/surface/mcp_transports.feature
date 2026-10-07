Feature: MCP transport contracts
  The gateway correctly implements Legacy SSE, proxy:// target routing, and
  Streamable HTTP transport behaviors for MCP surfaces.

  Scenario: Legacy SSE endpoint returns text/event-stream and emits an endpoint event
    Given REST API "bravo" exposes a Weather OpenAPI
    And MCP surface "alpha" exists for route "/example" targeting an MCP proxy endpoint backed by REST API "bravo"
    When the caller connects to the Legacy SSE endpoint
    Then the response content type is "text/event-stream"
    And the SSE stream emits an endpoint event with a session message URL

  Scenario: Legacy SSE stream delivers message events and remains stable across repeated calls
    Given REST API "bravo" exposes a Weather OpenAPI
    And MCP surface "alpha" exists for route "/example" targeting an MCP proxy endpoint backed by REST API "bravo"
    When the caller sends two MCP tool calls over Legacy SSE on the same session
    Then both calls receive a reply as an SSE message event
    And REST API "bravo" received exactly 2 requests

  Scenario: Streamable HTTP initialize response is SSE-wrapped and carries Mcp-Session-Id
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports initialization
    When the caller sends an MCP initialize request over Streamable HTTP
    Then the response status is 200
    And the response content type is "text/event-stream"
    And the response carries a non-empty "mcp-session-id" header

  Scenario Outline: A modern tool call completes without a protocol session
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports modern tool invocation with "<content_type>" responses
    When the caller invokes MCP tool "echo" using protocol version "2026-07-28" without a protocol session
    Then the response status is 200
    And the response content type is "<content_type>"
    And the response does not include header "mcp-session-id"
    And MCP server "bravo" did not receive header "mcp-session-id"
    And MCP server "bravo" received header "mcp-protocol-version" with value "2026-07-28"
    And MCP server "bravo" received header "mcp-method" with value "tools/call"
    And MCP server "bravo" received header "mcp-name" with value "echo"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result

    Examples:
      | content_type      |
      | application/json  |
      | text/event-stream |

  Scenario: Modern progress reaches the caller before the tool completes
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" reports progress while MCP tool "echo" is still running
    When the caller invokes MCP tool "echo" using protocol version "2026-07-28" without a protocol session
    Then the response status is 200
    And the response content type is "text/event-stream"
    And the caller receives MCP progress before MCP server "bravo" completes the tool
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result
    And the MCP response stream closes after the final response

  Scenario: An untrusted Origin cannot invoke a tool on an MCP surface
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface accepts MCP Origin "https://allowed.example"
    And MCP server "bravo" supports modern tool invocation with "application/json" responses
    When the caller invokes MCP tool "echo" using protocol version "2026-07-28" with Origin "https://untrusted.example"
    Then the response status is 403
    And MCP server "bravo" was not called

  Scenario: Disconnecting a quiet modern response cancels tool work
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" keeps MCP tool "echo" running without progress messages
    And the caller has an open modern MCP response stream for tool "echo"
    When the caller closes the MCP response stream
    Then MCP server "bravo" stops processing the cancelled tool call
    And the MCP response stream is closed
