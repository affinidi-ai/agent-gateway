Feature: A2A agent card security
  An Access Point that declares the authorization server of its source
  authentication replaces the security a managed agent's card declares with
  that authorization server, in the shape of the card's era, because callers
  authorize with the gateway rather than the managed agent. Its card names the
  Access Point URL as its endpoint, drops the managed agent's signature and must
  be revalidated before reuse. A Transit Point of such an Access Point serves its
  partner's card without any security declaration or signature. An Access Point
  that does not declare serves the card with the managed agent's security and
  signature unchanged.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: A 1.0 card declares the authorization server in the 1.0 shape
    Given managed agent "bravo" publishes a v1.0 agent card with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke agent.read"
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card declares the surface authorization server for scopes "agent.invoke agent.read" in the 1.0 shape

  Scenario: A 0.3 card declares the authorization server in the 0.3 shape
    Given managed agent "bravo" publishes a v0.3 agent card with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card declares the surface authorization server for scopes "agent.invoke" in the 0.3 shape

  Scenario: A card of both eras declares the authorization server in both shapes
    Given managed agent "bravo" publishes an agent card of both eras with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card declares the surface authorization server for scopes "agent.invoke" in both shapes

  Scenario: A JWT Bearer Access Point that requires no scope keeps the security of the managed agent
    Given managed agent "bravo" publishes a v1.0 agent card with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card keeps the security of the managed agent

  Scenario: A JWT Bearer Access Point that publishes no authorization server keeps the security of the managed agent
    Given managed agent "bravo" publishes a v0.3 agent card with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface requires scopes "agent.invoke"
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card keeps the security of the managed agent

  Scenario Outline: An Access Point that authenticates callers with an API key keeps the security of the managed agent
    Given managed agent "bravo" publishes a v1.0 agent card with its own security
    And the surface requires "<auth type>" source authentication
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card keeps the security of the managed agent

    Examples:
      | auth type        |
      | API Key          |
      | API Key Provider |

  Scenario Outline: An Access Point without caller authentication keeps the security of the managed agent
    Given managed agent "bravo" publishes a <era> agent card with its own security
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card keeps the security of the managed agent

    Examples:
      | era  |
      | v1.0 |
      | v0.3 |

  Scenario Outline: A declaring Access Point's card names the Access Point URL as its endpoint
    Given managed agent "bravo" publishes a <era> agent card with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card names the surface Access Point URL as its endpoint

    Examples:
      | era  |
      | v1.0 |
      | v0.3 |

  Scenario Outline: A declaring Access Point drops the managed agent's signature from its card
    Given managed agent "bravo" publishes a signed <era> agent card with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card carries no signature

    Examples:
      | era  |
      | v1.0 |
      | v0.3 |

  Scenario: A declaring Access Point's card must be revalidated before reuse
    Given managed agent "bravo" publishes a v1.0 agent card with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    When the caller fetches the agent card
    Then the response status is 200
    And the response includes header "cache-control" with value "no-cache"
    And the response carries a non-empty "etag" header

  Scenario: An Access Point without caller authentication keeps the managed agent's signature and asks for no revalidation
    Given managed agent "bravo" publishes a signed v1.0 agent card with its own security
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card keeps the signature of managed agent "bravo"
    And the response does not include header "etag"

  Scenario: A Transit Point of a declaring Access Point serves its partner's card without security or signature
    Given the surface has a transit point "t1" to external agent "charlie"
    And external agent "charlie" publishes a signed v1.0 agent card with its own security
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    When managed agent "bravo" fetches the agent card through Transit Point "t1"
    Then the response status is 200
    And the agent card carries no security declaration
    And the agent card carries no signature

  Scenario: A Transit Point of an Access Point without caller authentication serves its partner's card unchanged
    Given the surface has a transit point "t1" to external agent "charlie"
    And external agent "charlie" publishes a signed v1.0 agent card with its own security
    When managed agent "bravo" fetches the agent card through Transit Point "t1"
    Then the response status is 200
    And the agent card keeps the signature of external agent "charlie"
