Feature: A2A agents that compress their replies, over Fabric
  A gateway carries a Target's answer to a paired gateway as text, so the Target
  is asked for an uncompressed answer whatever the managed agent accepts.

  Scenario: A Fabric Transit Point carries the reply of an agent that compresses when asked
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" compresses its replies with gzip when asked
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "to-alpha" over Fabric to gateway 2 surface "alpha"
    When managed agent "delta" sends an A2A message/send request through Transit Point "to-alpha" with header "accept-encoding" set to "gzip"
    Then the response status is 200
    And the A2A response result matches managed agent "bravo" response result
    And managed agent "bravo" received header "accept-encoding" with value "identity"

  Scenario: A Fabric Transit Point refuses the reply of an agent that compresses although none was accepted
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" compresses its replies with gzip even when not asked
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "to-alpha" over Fabric to gateway 2 surface "alpha"
    When managed agent "delta" sends an A2A message/send request through Transit Point "to-alpha" with header "accept-encoding" set to "gzip"
    Then the response status is 502
    And the response says "response is compressed"
    And managed agent "bravo" received header "accept-encoding" with value "identity"

  Scenario: An Access Point serves over Fabric the agent card of an agent that compresses when asked
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" serves an agent card
    And managed agent "bravo" compresses its replies with gzip when asked
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller fetches the agent card from gateway 1 surface "charlie" with header "accept-encoding" set to "gzip"
    Then the response status is 200
    And the agent card points callers at gateway 1 surface "charlie"
    And managed agent "bravo" received header "accept-encoding" with value "identity"
