Feature: A2A agents that compress their replies
  Most HTTP clients accept gzip by default. The gateway asks an agent for an
  uncompressed agent card whatever the caller accepts, so it can rewrite the
  card to point at the gateway, and refuses a card compressed all the same.

  Scenario: An Access Point serves the agent card of an agent that compresses when asked
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" serves a gzip-compressed agent card when asked
    When the caller fetches the agent card with header "accept-encoding" set to "gzip"
    Then the response status is 200
    And the agent card points callers at the gateway, not at the agent
    And managed agent "bravo" received header "accept-encoding" with value "identity"

  Scenario: An Access Point refuses an agent card compressed although none was accepted
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" serves a gzip-compressed agent card even when not asked
    When the caller fetches the agent card with header "accept-encoding" set to "gzip"
    Then the response status is 502
    And the response body is error "agent_card_upstream_compressed"

  Scenario: A Transit Point serves the agent card of an agent that compresses when asked
    Given A2A surface "alpha" is defined for route "/example" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"
    And external agent "charlie" serves a gzip-compressed agent card when asked
    When managed agent "bravo" fetches the agent card of Transit Point "tr1" accepting gzip
    Then the response status is 200
    And the agent card points callers at the gateway, not at the agent
    And external agent "charlie" received header "accept-encoding" with value "identity"

  Scenario: A Transit Point refuses an agent card compressed although none was accepted
    Given A2A surface "alpha" is defined for route "/example" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"
    And external agent "charlie" serves a gzip-compressed agent card even when not asked
    When managed agent "bravo" fetches the agent card of Transit Point "tr1" accepting gzip
    Then the response status is 502
