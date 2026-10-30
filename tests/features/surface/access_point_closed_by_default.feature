Feature: New Access Points are closed by default
  A surface created through the admin API has a closed Access Point. It must
  require source authentication unless the operator marks it public, and a
  caller whose credential is missing or invalid is refused before the target.
  A stored surface that was never marked closed or public keeps handing such
  callers to policy.

  Scenario: A new surface without source authentication is refused
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target
    When the operator attempts to create a surface for route "/example" without source authentication
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.caller_authentication is required"
    And the admin API response does not include a surface id

  Scenario: A new public surface is created with a warning
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target
    When the operator creates a public surface for route "/example"
    Then the admin API response status is 201
    And the admin API response warns "This Access Point is public"

  Scenario: A public surface warns again on every save
    Given an A2A surface targeting managed agent "bravo"
    And the operator has created the surface for route "/example" as a public Access Point
    When the operator saves the surface again
    Then the admin API response status is 200
    And the admin API response warns "This Access Point is public"

  Scenario: A new public surface admits callers without credentials
    Given an A2A surface targeting managed agent "bravo"
    And the operator has created the surface for route "/example" as a public Access Point
    When the caller sends a request to the surface path "/example/foo"
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

  Scenario: A closed surface cannot be reopened by an update
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    When the operator removes source authentication from the surface
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.caller_authentication is required"

  Scenario: A closed surface cannot be reopened by a variant
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the operator has created the surface for route "/example"
    When the operator adds a complete-mode variant "open" without source authentication to the surface
    Then the admin API response status is 400
    And the admin API error response mentions "variant 'open': access_point.caller_authentication is required"
