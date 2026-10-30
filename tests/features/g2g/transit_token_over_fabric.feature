Feature: Transit tokens for requests that arrive over Fabric
  A gateway that receives a request from a paired gateway gives its managed agent
  a transit token for that request, as its Access Point does for a direct caller,
  so the agent can call onward through its own Transit Points. The token names the
  peer gateway and counts the Fabric crossings, so a chain of agents calling each
  other across gateways stops at the hop limit.

  Scenario: A managed agent serving a partner request receives a transit token for it
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has A2A Transit Point "to-echo" over Fabric to gateway 3 surface "echo"
    And Transit Point "to-echo" requires a transit token
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And managed agent "bravo" received a transit token for the request gateway 1 sent

  Scenario: A managed agent serving a partner request calls onward through its own Transit Point
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has A2A Transit Point "to-echo" over Fabric to gateway 3 surface "echo"
    And Transit Point "to-echo" requires a transit token
    And the caller has sent a Fabric A2A request through gateway 1 surface "charlie"
    When managed agent "bravo" calls Transit Point "to-echo" with the transit token it received
    Then the response status is 200
    And managed agent "foxtrot" received the trace id managed agent "bravo" received

  Scenario: A Transit Point that requires a transit token refuses a partner's agent without one
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has A2A Transit Point "to-echo" over Fabric to gateway 3 surface "echo"
    And Transit Point "to-echo" requires a transit token
    And the caller has sent a Fabric A2A request through gateway 1 surface "charlie"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "to-echo"
    Then the response status is 401
    And managed agent "foxtrot" did not receive a forwarded message

  Scenario: A token issued for a partner request opens only its own surface's Transit Points
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 2 has an A2A surface "golf" targeting managed agent "hotel"
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has A2A Transit Point "to-echo" over Fabric to gateway 3 surface "echo"
    And surface "golf" has A2A Transit Point "golf-to-echo" over Fabric to gateway 3 surface "echo"
    And Transit Point "to-echo" requires a transit token
    And Transit Point "golf-to-echo" requires a transit token
    And the caller has sent a Fabric A2A request through gateway 1 surface "charlie"
    When managed agent "hotel" calls Transit Point "golf-to-echo" with the transit token managed agent "bravo" received
    Then the response status is 401
    And managed agent "foxtrot" did not receive a forwarded message

  Scenario: Agents passing a request back and forth are stopped at the hop limit
    Given a fabric with 2 gateways
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "charlie" has A2A Transit Point "to-alpha" over Fabric to gateway 2 surface "alpha"
    And surface "alpha" has A2A Transit Point "to-charlie" over Fabric to gateway 1 surface "charlie"
    And Transit Point "to-alpha" requires a transit token
    And Transit Point "to-charlie" requires a transit token
    And the caller has sent a Fabric A2A request through gateway 1 surface "charlie"
    When managed agents "delta" and "bravo" pass the request back and forth through Transit Points "to-alpha" and "to-charlie"
    Then the relay was refused with status 508 after 8 Transit Point calls crossed Fabric
