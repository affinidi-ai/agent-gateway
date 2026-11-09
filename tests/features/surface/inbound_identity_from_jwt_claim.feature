Feature: Inbound identity derived from a JWT claim
  An Access Point whose inbound identity comes from a JWT claim cannot derive a
  caller identity without a valid JWT, so it refuses the caller before policy.

  Scenario Outline: An Access Point deriving the inbound identity from a JWT claim refuses a caller whose token is missing or invalid
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives the inbound identity from a JWT claim
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
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
