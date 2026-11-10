Feature: Routing through a proxy:// MCP target
  An MCP surface whose target endpoint is proxy://{id} answers MCP requests
  through the named MCP proxy. The proxy advertises its dashboard-configured
  name on initialize and translates tool invocations into REST calls against
  its configured backend. A Target credential on a proxy:// target goes to the
  MCP proxy's base URL, so that URL is held to the target_https credential rule on
  save and on every tool call.

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

  Scenario: Calling an unknown tool returns a JSON-RPC error and does not contact the REST API
    When the caller invokes the MCP tool "make_coffee" for city "Paris"
    Then the response status is 200
    And the MCP response carries a JSON-RPC error for an unknown tool
    And REST API "bravo" was not called

  Scenario: Calling a disabled MCP proxy returns a JSON-RPC error and does not contact the REST API
    Given the MCP proxy backing REST API "bravo" is disabled
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And the MCP response carries a JSON-RPC error for a disabled proxy
    And REST API "bravo" was not called

  Scenario: A configured tool policy denies an unlisted tool on a proxy:// MCP target
    Given the MCP surface enforces a tool policy allowing only tool "get_forecast"
    And the VP Audit Log keeps every audit event
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32000
    And REST API "bravo" was not called
    And the VP Audit Log's MCP tool policy decisions name the surface by its id

  Scenario: A configured tool policy forwards an allowed tool on a proxy:// MCP target
    Given the MCP surface enforces a tool policy allowing only tool "get_weather"
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And the MCP tool result matches REST API "bravo" response

  Scenario Outline: Tool calls over <transport> reach the REST API
    When the caller invokes the MCP tool "get_weather" for city "Paris" over <transport>
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And the MCP tool result matches REST API "bravo" response

    Examples:
      | transport       |
      | Legacy SSE      |
      | Streamable HTTP |

  Scenario Outline: Calling a disabled MCP proxy over <transport> returns a JSON-RPC error and does not contact the REST API
    Given the MCP proxy backing REST API "bravo" is disabled
    When the caller invokes the MCP tool "get_weather" for city "Paris" over <transport>
    Then the response status is 200
    And the MCP response carries a JSON-RPC error for a disabled proxy
    And REST API "bravo" was not called

    Examples:
      | transport       |
      | Legacy SSE      |
      | Streamable HTTP |

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

  Scenario: A caller whose source authentication failed does not get the target credential on a proxy:// MCP target
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller invokes the MCP tool "get_weather" for city "Paris"
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And REST API "bravo" did not receive header "x-target-api-key"

  Scenario: An authenticated caller gets the target credential on a proxy:// MCP target
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid API key
    Then the response status is 200
    And REST API "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A legacy MCP proxy tool call answers the same tool result with and without the Target credential
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller invokes the MCP tool "get_weather" for city "Paris" once without and once with a valid API key
    Then the response status is 200
    And the MCP tool result matches REST API "bravo" response
    And REST API "bravo" answered the same MCP tool result with and without the Target credential

  Scenario: A credentialed tool call returns a file the REST API answers as an embedded resource
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And REST API "bravo" answers a PDF document
    When the caller invokes the MCP tool "get_weather_map" for city "Paris" with a valid API key
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris/map"
    And the MCP tool result is REST API "bravo"'s file as an embedded "application/pdf" resource

  Scenario: A 2026-07-28 tool call returns a file the REST API answers as an embedded resource
    Given REST API "bravo" answers a PDF document
    When the caller invokes the MCP tool "get_weather_map" for city "Paris" using protocol version "2026-07-28"
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris/map"
    And the MCP tool result is REST API "bravo"'s file as an embedded "application/pdf" resource

  Scenario: A 2026-07-28 tool call returns JSON the REST API serves under a non-JSON content type as text
    Given REST API "bravo" answers its weather as "application/octet-stream"
    When the caller invokes the MCP tool "get_weather" for city "Paris" using protocol version "2026-07-28"
    Then the response status is 200
    And the MCP tool result matches REST API "bravo" response

  Scenario: A 2026-07-28 tool call refuses a file that does not fit the response limit once base64-encoded
    Given the surface limits MCP responses to 4096 bytes
    And REST API "bravo" answers a file of 3200 bytes
    When the caller invokes the MCP tool "get_weather_map" for city "Paris" using protocol version "2026-07-28"
    Then the response status is 502
    And the MCP response is a JSON-RPC error with code -32603

  Scenario: A credentialed tool call returns JSON the REST API serves under a non-JSON content type as text
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And REST API "bravo" answers its weather as "application/octet-stream"
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid API key
    Then the response status is 200
    And the MCP tool result matches REST API "bravo" response

  Scenario: A legacy MCP proxy tool call answers the same failed tool result with and without the Target credential
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And REST API "bravo" is failing with status 503
    When the caller invokes the MCP tool "get_weather" for city "Paris" once without and once with a valid API key
    Then the response status is 200
    And the MCP tool result is marked as an error
    And the MCP tool result matches REST API "bravo" response
    And REST API "bravo" answered the same MCP tool result with and without the Target credential

  Scenario: Only a legacy MCP proxy tool call with the Target credential checks the REST response against the tool's output schema
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And REST API "bravo" answers a weather report whose temperature is "warm"
    When the caller invokes the MCP tool "get_weather" for city "Paris" once without and once with a valid API key
    Then the response status is 200
    And the MCP tool result without the Target credential matches REST API "bravo" response
    And the MCP tool result is marked as an error
    And the response mentions "REST response does not match the tool output schema"
    And REST API "bravo" received exactly 2 requests

  Scenario: A credentialed tool call under the MCP proxy base path carries the Target credential
    Given the MCP proxy's base URL has the base path "/api/"
    And the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid API key
    Then the response status is 200
    And REST API "bravo" received "GET /api/weather/Paris"
    And REST API "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A credentialed tool call keeps the last segment of a base URL without a trailing slash
    Given the MCP proxy's base URL has the base path "/api/v4"
    And the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid API key
    Then the response status is 200
    And REST API "bravo" received "GET /api/v4/weather/Paris"
    And REST API "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A credentialed tool call that leaves a base URL without a trailing slash is refused before the REST API
    Given the MCP proxy's base URL has the base path "/api/v4"
    And the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller invokes the MCP tool "get_weather" for city "../../../api/weather/Paris" with a valid API key
    Then the response status is 502
    And the response mentions "Target authentication failed"
    And REST API "bravo" was not called

  Scenario: A credentialed tool call whose path leaves the MCP proxy base path is refused before the REST API
    Given the MCP proxy's base URL has the base path "/api/"
    And the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller invokes the MCP tool "get_weather" for city "../../admin" with a valid API key
    Then the response status is 502
    And the response mentions "Target authentication failed"
    And REST API "bravo" was not called

  Scenario: A credentialed tool call with a braced path value is refused as invalid arguments, not as leaving the base path
    Given the MCP proxy's base URL has the base path "/api/"
    And the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller invokes the MCP tool "get_weather" for city "{Paris}" with a valid API key
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32603
    And REST API "bravo" was not called

  Scenario: A credentialed tool call does not follow a redirect from the REST API
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And REST API "bravo" answers every request with a redirect to its path "/elsewhere"
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid API key
    Then the response status is 200
    And the MCP response is a JSON-RPC error with code -32603
    And the response mentions "REST tool redirects are not permitted"
    And REST API "bravo" received exactly 1 requests
    And REST API "bravo" received "GET /weather/Paris"

  Scenario: An MCP proxy tool call carries the Target credential while https Targets only warn
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway only warns on the credential rule "target_https"
    And the gateway keeps its log of warnings
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid API key
    Then the response status is 200
    And REST API "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And the gateway log has a warning containing "it will be withheld once credential_policy.target_https is enforce"

  Scenario: An MCP proxy tool call is refused before the REST API when https Targets are enforced
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway enforces the credential rule "target_https"
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid API key
    Then the response status is 502
    And the response mentions "Target authentication"
    And REST API "bravo" was not called

  Scenario: An MCP proxy tool call goes out without the Target credential when https Targets are enforced and fallback is passthrough
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway's authentication to the managed agent falls back to "passthrough"
    And the gateway enforces the credential rule "target_https"
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid API key
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And REST API "bravo" did not receive header "x-target-api-key"

  Scenario: Editing an MCP proxy Target credential is saved with a warning while https Targets only warn
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway only warns on the credential rule "target_https"
    When the operator saves the surface with its Target authentication formatting the value as "Token {value}"
    Then the admin API response status is 200
    And the admin API response carries a Warning header containing "target.auth sends a credential, so its MCP proxy's base_url must be an https URL; it will be refused once credential_policy.target_https is enforce"

  Scenario: Editing an MCP proxy Target credential is refused when https Targets are enforced
    Given the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway enforces the credential rule "target_https"
    When the operator saves the surface with its Target authentication formatting the value as "Token {value}"
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth sends a credential, so its MCP proxy's base_url must be an https URL"

  Scenario: Editing an MCP proxy Target credential is saved when https Targets are enforced and the MCP proxy's base URL is https
    Given the MCP proxy's base URL is an https URL
    And the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway enforces the credential rule "target_https"
    When the operator saves the surface with its Target authentication formatting the value as "Token {value}"
    Then the admin API response status is 200
    And the admin API response carries no Warning header containing "must be an https URL"
