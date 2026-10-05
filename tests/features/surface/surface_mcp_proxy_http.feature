Feature: Routing through a proxy:// MCP target
  An MCP surface whose target endpoint is proxy://{id} answers MCP requests
  through the named MCP proxy. The proxy advertises its dashboard-configured
  name on initialize and translates tool invocations into REST calls against
  its configured backend.

  Background:
    Given REST API "bravo" exposes a Weather OpenAPI
    And MCP surface "alpha" exists for route "/example" targeting an MCP proxy endpoint backed by REST API "bravo"

  Scenario: Initialize reports the proxy's dashboard-configured name
    When the caller sends an MCP initialize request
    Then the response status is 200
    And the MCP response carries the proxy server info name "bravo"
    And REST API "bravo" was not called

  Scenario: Tools list returns the proxy's OpenAPI-derived catalog
    When the caller sends an MCP tools/list request
    Then the response status is 200
    And the MCP response tool catalog includes a tool named "get_weather"
    And the MCP response tool catalog includes a tool named "get_forecast"
    And REST API "bravo" was not called

  Scenario: Tool calls are translated into REST requests and the REST response flows back
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And the MCP tool result matches REST API "bravo" response

  Scenario: Calling an unknown tool returns a JSON-RPC error and does not contact the REST backend
    When the caller invokes the MCP tool "make_coffee" for city "Paris"
    Then the response status is 200
    And the MCP response carries a JSON-RPC error for an unknown tool
    And REST API "bravo" was not called

  Scenario: Calling a disabled MCP proxy returns a JSON-RPC error and does not contact the REST backend
    Given the MCP proxy backing REST API "bravo" is disabled
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And the MCP response carries a JSON-RPC error for a disabled proxy
    And REST API "bravo" was not called

  Scenario: A configured tool policy denies an unlisted tool on a proxy:// MCP target
    Given the MCP surface enforces a tool policy allowing only tool "get_forecast"
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32000
    And REST API "bravo" was not called

  Scenario: A configured tool policy forwards an allowed tool on a proxy:// MCP target
    Given the MCP surface enforces a tool policy allowing only tool "get_weather"
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And the MCP tool result matches REST API "bravo" response

  Scenario: Tool calls over Legacy SSE reach the REST backend
    When the caller invokes the MCP tool "get_weather" for city "Paris" over Legacy SSE
    Then REST API "bravo" received "GET /weather/Paris"
    And the MCP tool result matches REST API "bravo" response

  Scenario: Calling a disabled MCP proxy over Legacy SSE returns a JSON-RPC error and does not contact the REST backend
    Given the MCP proxy backing REST API "bravo" is disabled
    When the caller invokes the MCP tool "get_weather" for city "Paris" over Legacy SSE
    Then the MCP response carries a JSON-RPC error for a disabled proxy
    And REST API "bravo" was not called

  Scenario: Tool calls over Streamable HTTP reach the REST backend
    When the caller invokes the MCP tool "get_weather" for city "Paris" over Streamable HTTP
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And the MCP tool result matches REST API "bravo" response

  Scenario: Calling a disabled MCP proxy over Streamable HTTP returns a JSON-RPC error and does not contact the REST backend
    Given the MCP proxy backing REST API "bravo" is disabled
    When the caller invokes the MCP tool "get_weather" for city "Paris" over Streamable HTTP
    Then the response status is 200
    And the MCP response carries a JSON-RPC error for a disabled proxy
    And REST API "bravo" was not called

  # ── MCP tool gating on proxy:// targets ────────────────────────────────

  Scenario: A tool the surface gates out is hidden from tools/list on a proxy:// MCP target
    Given the MCP surface gates out tool "get_weather"
    When the caller sends an MCP tools/list request
    Then the response status is 200
    And the MCP response tool catalog does not include a tool named "get_weather"
    And the MCP response tool catalog includes a tool named "get_forecast"

  Scenario: A tool the surface gates out cannot be called on a proxy:// MCP target
    Given the MCP surface gates out tool "get_weather"
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32001
    And REST API "bravo" was not called

  Scenario: A tool the surface gates out cannot be called over Streamable HTTP on a proxy:// MCP target
    Given the MCP surface gates out tool "get_weather"
    When the caller invokes the MCP tool "get_weather" for city "Paris" over Streamable HTTP
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32001
    And REST API "bravo" was not called

  Scenario: A conditional gate sees the caller's agent context on a proxy:// MCP target
    Given the MCP surface gates out tool "get_weather" when the caller's agent context is present
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32001
    And REST API "bravo" was not called

  Scenario: An allow-list gate forwards the allowed tool and hides the rest on a proxy:// MCP target
    Given the MCP surface gating allows only tool "get_weather"
    When the caller sends an MCP tools/list request
    Then the response status is 200
    And the MCP response tool catalog includes a tool named "get_weather"
    And the MCP response tool catalog does not include a tool named "get_forecast"

  Scenario: An allow-list gate still forwards the allowed tool call on a proxy:// MCP target
    Given the MCP surface gating allows only tool "get_weather"
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And the MCP tool result matches REST API "bravo" response

  # ── OPA policy enforcement on proxy:// targets ─────────────────────────

  Scenario: Surface OPA policy denies an MCP proxy request
    Given the MCP surface has a request policy that denies all requests
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32001
    And REST API "bravo" was not called

  Scenario: Surface OPA policy denies an MCP proxy request over Streamable HTTP
    Given the MCP surface has a request policy that denies all requests
    When the caller invokes the MCP tool "get_weather" for city "Paris" over Streamable HTTP
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32001
    And REST API "bravo" was not called

  Scenario: Surface OPA policy allows an MCP proxy request when the policy passes
    Given the MCP surface has a request policy that allows all requests
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And the MCP tool result matches REST API "bravo" response
