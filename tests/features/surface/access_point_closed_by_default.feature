Feature: Access Points that are not public refuse failed callers
  A surface created through the admin API has a closed Access Point. Until it
  has source authentication, or the operator marks it public, it is not ready
  and refuses every caller. Once it has source authentication, a caller whose
  credential is missing or invalid is refused before the target. A legacy
  surface, stored without being marked closed or public, refuses such callers
  too, while only a public Access Point hands them to policy.

  Scenario: A not-ready Access Point refuses callers
    Given an A2A surface targeting managed agent "bravo"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 503
    And the response content type is "application/problem+json"
    And the response says only that the Access Point is not available
    And managed agent "bravo" was not called

  Scenario: A not-ready MCP Access Point refuses a caller with a JSON-RPC error
    Given MCP surface "alpha" targets MCP server "bravo"
    And the operator has created the surface for route "/example"
    When the caller asks the MCP surface for available tools without an API key
    Then the response status is 503
    And the MCP response is a JSON-RPC error with code -32603
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: A not-ready Access Point refuses discovery reads
    Given an A2A surface targeting managed agent "bravo"
    And the operator has created the surface for route "/example"
    When the caller reads the surface path "/example/.well-known/agent-card.json"
    Then the response status is 503
    And managed agent "bravo" was not called

  Scenario: Adding source authentication makes a not-ready Access Point ready
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example" without its source authentication
    And the operator has added its source authentication to the surface
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A new public surface admits callers without credentials
    Given an A2A surface targeting managed agent "bravo"
    And the operator has created the surface for route "/example" as a public Access Point
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A closed surface marked public admits callers without credentials
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    And the operator has marked the surface public
    When the caller sends a request to the surface without an API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario Outline: A legacy surface refuses a caller whose API key is missing or invalid
    Given an A2A surface targeting managed agent "bravo"
    And the surface is stored as a legacy surface
    And the surface requires "API Key" source authentication
    When the caller sends a request to the surface <credential condition>
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response content type is "application/problem+json"
    And the response says only that the caller credential is missing or invalid

    Examples:
      | credential condition    |
      | without an API key      |
      | with an invalid API key |

  Scenario: A legacy MCP surface refuses a caller with a JSON-RPC error
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface is stored as a legacy surface
    And the surface requires "API Key" source authentication
    When the caller asks the MCP surface for available tools without an API key
    Then the response status is 401
    And the MCP response is a JSON-RPC error with code -32603
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: The gateway warns at start about a legacy surface that refuses failed callers
    Given an A2A surface targeting managed agent "bravo"
    And the surface is stored as a legacy surface
    And the surface requires "API Key" source authentication
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface with a valid API key
    Then the gateway log has a warning containing "is configured for authenticated callers only"

  Scenario: The gateway does not warn at start about a public surface
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the surface is stored with a public Access Point
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface with a valid API key
    Then the gateway log has no warning containing "is configured for authenticated callers only"

  Scenario: A legacy surface admits a caller with a valid API key
    Given an A2A surface targeting managed agent "bravo"
    And the surface is stored as a legacy surface
    And the surface requires "API Key" source authentication
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A legacy surface without source authentication admits every caller
    Given an A2A surface targeting managed agent "bravo"
    And the surface is stored as a legacy surface
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A stored public surface hands a caller without an API key to policy
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the surface is stored with a public Access Point
    When the caller sends a request to the surface without an API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario Outline: A new surface refuses a caller whose API key is missing or invalid
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface <credential condition>
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response content type is "application/problem+json"
    And the response says only that the caller credential is missing or invalid

    Examples:
      | credential condition    |
      | without an API key      |
      | with an invalid API key |

  Scenario: A new surface admits a caller with a valid API key
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive header "x-api-key"

  Scenario: A new MCP surface refuses a caller with a JSON-RPC error
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    When the caller asks the MCP surface for available tools without an API key
    Then the response status is 401
    And the MCP response is a JSON-RPC error with code -32603
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario Outline: Public discovery reads stay open on a closed Access Point
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    When the caller reads the surface path "<path>"
    Then the response status is 200
    And managed agent "bravo" received the agent card request at path "<agent card path>"

    Examples:
      | path                                 | agent card path              |
      | /example/.well-known/agent-card.json | /.well-known/agent-card.json |
      | /example/.well-known/agent.json      | /.well-known/agent-card.json |
      | /example/agent-card.json             | /agent-card.json             |

  Scenario: A non-discovery method on a discovery path is still gated
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface path "/example/agent.json"
    Then the response status is 401
    And the MCP response is a JSON-RPC error with code -32603
    And MCP server "bravo" was not called

  Scenario: A closed surface whose source authentication is removed goes not ready and refuses callers
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    And the operator has removed source authentication from the surface
    When the caller sends a request to the surface with a valid API key
    Then the response status is 503
    And the response says only that the Access Point is not available
    And managed agent "bravo" was not called

  Scenario: A closed surface whose variant clears source authentication refuses callers of that variant
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    And the operator has added a complete-mode variant "open" without source authentication to the surface
    When the caller sends a request to the surface path "/example$open/foo"
    Then the response status is 503
    And the response says only that the Access Point is not available
    And managed agent "bravo" was not called
