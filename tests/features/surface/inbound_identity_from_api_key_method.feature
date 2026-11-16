Feature: Inbound identity derived from a named API key method
  A surface mixing JWT Bearer and API Key can derive its inbound identity from
  the API key method it names. A caller of any other method is refused, even
  with a valid credential, before policy and before the Target.

  Scenario: A surface naming its API key method serves a caller with a valid API key
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from the API key of its "API Key" source authentication
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received a forwarded request

  Scenario: A surface naming its API key method refuses a caller with a valid token
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from the API key of its "API Key" source authentication
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response says only that the caller credential is missing or invalid
    And the response carries no "www-authenticate" header

  Scenario: An MCP surface naming its API key method refuses a caller with a valid token and no challenge
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from the API key of its "API Key" source authentication
    When the caller asks the MCP surface for available tools with a valid token
    Then the response status is 401
    And the response carries no "www-authenticate" header
    And MCP server "bravo" was not called
    And the MCP response says only that the caller credential is missing or invalid
    And the MCP response id matches the request id

  Scenario: A public Access Point naming its API key method refuses a caller with no credential
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from the API key of its "API Key" source authentication
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example" as a public Access Point
    When the caller sends a request to the surface without an API key
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response says only that the caller credential is missing or invalid
