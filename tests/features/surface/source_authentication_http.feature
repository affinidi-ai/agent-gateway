Feature: HTTP surface source authentication
  Source authentication verifies the caller's credential at the Access Point,
  but a caller-attributable failure (missing or invalid credential) no longer
  blocks the request on its own. Instead the outcome is handed to the policy
  layer (`input.source_auth.method == "failed"`), which decides whether to allow
  or deny. With no blocking policy configured the request is forwarded with no
  asserted caller identity; an operator opts into blocking by writing a policy.

  # A2A / JWT Bearer

  Scenario Outline: JWT Bearer failures are forwarded when no blocking policy is configured
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the caller sends a request to the surface <auth condition>
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

    Examples:
      | auth condition         |
      | without a token        |
      | with an expired token  |
      | with a malformed token |
      | with a tampered token  |

  Scenario Outline: JWT Bearer failures are blocked when a policy denies unverified callers
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface <auth condition>
    Then the response status is 403
    And managed agent "bravo" was not called

    Examples:
      | auth condition         |
      | without a token        |
      | with an expired token  |
      | with a malformed token |
      | with a tampered token  |

  Scenario: JWT Bearer source authentication forwards authenticated A2A requests
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And the response body matches managed agent "bravo" response

  # A2A / API key and API key provider

  Scenario Outline: API key failures are forwarded when no blocking policy is configured
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "<auth type>" source authentication
    When the caller sends a request to the surface <credential condition>
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

    Examples:
      | auth type        | credential condition    |
      | API Key          | without an API key      |
      | API Key          | with an invalid API key |
      | API Key Provider | without an API key      |
      | API Key Provider | with an invalid API key |

  Scenario Outline: API key failures are blocked when a policy denies unverified callers
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "<auth type>" source authentication
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface <credential condition>
    Then the response status is 403
    And managed agent "bravo" was not called

    Examples:
      | auth type        | credential condition    |
      | API Key          | without an API key      |
      | API Key          | with an invalid API key |
      | API Key Provider | without an API key      |
      | API Key Provider | with an invalid API key |

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

  # MCP / JWT Bearer

  Scenario Outline: JWT Bearer MCP failures are forwarded when no blocking policy is configured
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools <auth condition>
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request

    Examples:
      | auth condition         |
      | without a token        |
      | with an expired token  |
      | with a malformed token |
      | with a tampered token  |

  Scenario Outline: JWT Bearer MCP failures are blocked when a policy denies unverified callers
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface has a policy denying callers whose source authentication failed
    When the caller asks the MCP surface for available tools <auth condition>
    Then the response status is 403
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

  Scenario Outline: JWT Bearer MCP invalid issuer or audience is blocked when a policy denies unverified callers
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "mcp-alpha"
    And the surface has a policy denying callers whose source authentication failed
    When the caller asks the MCP surface for available tools <auth condition>
    Then the response status is 403
    And MCP server "bravo" was not called

    Examples:
      | auth condition                                |
      | with a token from an untrusted issuer         |
      | with a token outside JWT audience "mcp-alpha" |

  # MCP / API key and API key provider

  Scenario Outline: API key MCP failures are forwarded when no blocking policy is configured
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "<auth type>" source authentication
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools <credential condition>
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request

    Examples:
      | auth type        | credential condition    |
      | API Key          | without an API key      |
      | API Key          | with an invalid API key |
      | API Key Provider | without an API key      |
      | API Key Provider | with an invalid API key |

  Scenario Outline: API key MCP failures are blocked when a policy denies unverified callers
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "<auth type>" source authentication
    And the surface has a policy denying callers whose source authentication failed
    When the caller asks the MCP surface for available tools <credential condition>
    Then the response status is 403
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
