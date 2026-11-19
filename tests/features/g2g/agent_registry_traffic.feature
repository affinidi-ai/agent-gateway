Feature: Agent traffic over Fabric
  Scenario: A request a surface receives over Fabric counts once in its agent's traffic
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the operator has read the traffic of the agent of surface "alpha"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And the operator sees 1 more request, none failed, in the traffic of the agent of surface "alpha"
