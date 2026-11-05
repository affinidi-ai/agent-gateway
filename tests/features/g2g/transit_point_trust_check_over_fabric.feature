Feature: Transit Point Trust Check over Fabric
  A Transit Point to a partner gateway can authenticate its callers and run a target-leg
  Trust Check together. The gateway reads the partner's agent card for the Trust Check
  over Fabric, not through the Transit Point, so the Transit Point's caller authentication
  does not stop it.

  Scenario: A Transit Point that authenticates its callers reads its partner's agent card over Fabric
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And Transit Point "tr1" authenticates its callers with API key "tr1-caller-key"
    And surface "charlie" denies a target Trust Check reporting any of error codes "AGENT_CARD_UNAVAILABLE"
    And Transit Point "tr1" has a target-leg Trust Check
    When managed agent "delta" sends an A2A message/send request through Transit Point "tr1" with header "x-api-key" set to "tr1-caller-key"
    Then the response status is 200
    And managed agent "bravo" served its agent card
    And managed agent "bravo" received one forwarded message
