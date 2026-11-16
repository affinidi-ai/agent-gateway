Feature: HTTP surface source authentication
  Source authentication verifies the caller's credential at the Access Point.
  An Access Point that is not public refuses a caller whose credential is
  missing or invalid with 401 before policy and the Target. Only a public
  Access Point hands such a caller to policy (`input.source_auth.method ==
  "failed"`), which decides whether to allow or deny it.

  # A2A / JWT Bearer

  Scenario Outline: JWT Bearer failures are refused
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface <auth condition>
    Then the response status is 401
    And managed agent "bravo" was not called
    And the VP Audit Log records a blocking "JWT Bearer" source authentication failure for "<failure>"

    Examples:
      | auth condition         | failure               |
      | without a token        | a missing credential  |
      | with an expired token  | an invalid credential |
      | with a malformed token | an invalid credential |
      | with a tampered token  | an invalid credential |

  Scenario: JWT Bearer source authentication forwards authenticated A2A requests
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And the response body matches managed agent "bravo" response

  # A2A / API key and API key provider

  Scenario Outline: API key failures are refused
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "<auth type>" source authentication
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface <credential condition>
    Then the response status is 401
    And managed agent "bravo" was not called
    And the VP Audit Log records a blocking "<auth type>" source authentication failure for "<failure>"

    Examples:
      | auth type        | credential condition    | failure               |
      | API Key          | without an API key      | a missing credential  |
      | API Key          | with an invalid API key | an invalid credential |
      | API Key Provider | without an API key      | a missing credential  |
      | API Key Provider | with an invalid API key | an invalid credential |

  Scenario Outline: API key source authentication forwards authenticated A2A requests
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "<auth type>" source authentication
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive header "x-api-key"
    And the response body matches managed agent "bravo" response

    Examples:
      | auth type        |
      | API Key          |
      | API Key Provider |

  # A2A / several source authentication methods

  Scenario Outline: A surface accepting JWT Bearer and API Key authenticates each caller by the credential it presents
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    When the caller sends a request to the surface <credential condition>
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive header "authorization"
    And managed agent "bravo" did not receive header "x-api-key"

    Examples:
      | credential condition |
      | with a valid token   |
      | with a valid API key |

  Scenario: A request carrying credentials for two source authentication methods is refused
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    When the caller sends a request to the surface with a valid token and a valid API key
    Then the response status is 401
    And managed agent "bravo" was not called

  # MCP / JWT Bearer

  Scenario Outline: JWT Bearer MCP failures are refused with a JSON-RPC error
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the caller asks the MCP surface for available tools <auth condition>
    Then the response status is 401
    And the MCP response is a JSON-RPC error with code -32603
    And MCP server "bravo" was not called

    Examples:
      | auth condition         |
      | without a token        |
      | with an expired token  |
      | with a malformed token |
      | with a tampered token  |

  Scenario: JWT Bearer source authentication forwards authenticated MCP requests
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools with a valid token
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario Outline: JWT Bearer MCP tokens from an untrusted issuer or for another audience are refused
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "mcp-alpha"
    When the caller asks the MCP surface for available tools <auth condition>
    Then the response status is 401
    And MCP server "bravo" was not called

    Examples:
      | auth condition                                |
      | with a token from an untrusted issuer         |
      | with a token outside JWT audience "mcp-alpha" |

  # MCP / API key and API key provider

  Scenario Outline: API key MCP failures are refused with a JSON-RPC error
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "<auth type>" source authentication
    When the caller asks the MCP surface for available tools <credential condition>
    Then the response status is 401
    And the MCP response is a JSON-RPC error with code -32603
    And MCP server "bravo" was not called

    Examples:
      | auth type        | credential condition    |
      | API Key          | without an API key      |
      | API Key          | with an invalid API key |
      | API Key Provider | without an API key      |
      | API Key Provider | with an invalid API key |

  Scenario Outline: API key source authentication forwards authenticated MCP requests
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "<auth type>" source authentication
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools with a valid API key
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive header "x-api-key"
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

    Examples:
      | auth type        |
      | API Key          |
      | API Key Provider |

  # Public Access Points

  Scenario Outline: A public Access Point hands a failed caller to policy, which forwards it with no blocking policy
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "<auth type>" source authentication
    And the surface is stored with a public Access Point
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface <credential condition>
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And the VP Audit Log records a non-blocking "<auth type>" source authentication failure for "<failure>"

    Examples:
      | auth type  | credential condition    | failure               |
      | JWT Bearer | without a token         | a missing credential  |
      | API Key    | with an invalid API key | an invalid credential |

  Scenario Outline: A public Access Point refuses a failed caller when a policy denies unverified callers
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "<auth type>" source authentication
    And the surface is stored with a public Access Point
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface <credential condition>
    Then the response status is 403
    And managed agent "bravo" was not called

    Examples:
      | auth type  | credential condition    |
      | JWT Bearer | with an expired token   |
      | API Key    | without an API key      |

  Scenario: A public MCP Access Point refuses a failed caller when a policy denies unverified callers
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "API Key" source authentication
    And the surface is stored with a public Access Point
    And the surface has a policy denying callers whose source authentication failed
    When the caller asks the MCP surface for available tools with an invalid API key
    Then the response status is 403
    And MCP server "bravo" was not called

  Scenario: A public Access Point does not give a caller whose source authentication failed the Target credential
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the surface is stored with a public Access Point
    When the caller sends a request to the surface without an API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive header "x-target-api-key"

  Scenario: A public Access Point gives a caller it authenticated the Target credential
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the surface is stored with a public Access Point
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"
