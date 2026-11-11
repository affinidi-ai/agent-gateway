Feature: Inbound identity derived from a JWT claim
  An Access Point whose inbound identity comes from a JWT claim cannot derive a
  caller identity without a valid JWT, so it refuses the caller before policy.

  Scenario Outline: An Access Point deriving the inbound identity from a JWT claim refuses a caller whose token is missing or invalid
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface <credential condition>
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response content type is "application/problem+json"
    And the response says only that the caller credential is missing or invalid

    Examples:
      | credential condition       |
      | without a token            |
      | with an expired token      |
      | with a tampered token      |
      | with a malformed token     |

  Scenario Outline: An MCP surface deriving the inbound identity from a JWT claim refuses a caller whose token is missing or invalid
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives the inbound identity from a JWT claim
    When the caller asks the MCP surface for available tools <credential condition>
    Then the response status is 401
    And the response carries a non-empty "www-authenticate" header
    And MCP server "bravo" was not called
    And the MCP response says only that the caller credential is missing or invalid
    And the MCP response id matches the request id

    Examples:
      | credential condition       |
      | without a token            |
      | with an expired token      |
      | with a tampered token      |
      | with a malformed token     |

  Scenario: An Access Point deriving the inbound identity from a JWT claim forwards a caller with a valid token
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received a forwarded request

  Scenario: A surface mixing JWT Bearer and API Key serves a caller whose token supplies the inbound identity
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim of its "JWT Bearer" source authentication
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received a forwarded request

  Scenario: A surface mixing JWT Bearer and API Key refuses a caller whose API key is not the source of the inbound identity
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim of its "JWT Bearer" source authentication
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid API key
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response content type is "application/problem+json"
    And the response says only that the caller credential is missing or invalid

  Scenario: A surface mixing JWT Bearer and API Key is refused when its inbound identity names no source authentication method
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim of a source authentication method it does not have
    And the surface accepts JWT audience "bdd-test-audience"
    When the operator tries to create the surface for route "/example"
    Then the admin API response status is 400
    And the admin API error response mentions "inbound_source_method"

  Scenario: A surface mixing JWT Bearer and API Key is refused when its inbound identity names no source authentication method and none is selected
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    When the operator tries to create the surface for route "/example"
    Then the admin API response status is 400
    And the admin API error response mentions "from_jwt_claim identity requires jwt_bearer as the only source authentication method"

