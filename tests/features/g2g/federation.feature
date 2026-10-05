Feature: Fabric routing between gateways
  Scenario: A2A request body reaches the remote managed agent unchanged
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then managed agent "bravo" received the forwarded request with the original body
    And the response status is 200
    And the A2A response result matches managed agent "bravo" response result

  Scenario Outline: An A2A method from either era survives the fabric hop unchanged
    # The gateway forwards the JSON-RPC method as-sent and never translates between
    # protocol eras, so a v1.0 PascalCase name must arrive at the remote managed
    # agent verbatim after the GW1 -> DIDComm -> GW2 hop — including methods that
    # only exist in v1.0, such as ListTasks.
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends Fabric A2A method "<method>" through gateway 1 surface "charlie"
    Then managed agent "bravo" received the forwarded request with the original body
    And the response status is 200

    Examples:
      | method       |
      | message/send |
      | SendMessage  |
      | ListTasks    |

  Scenario: gateway 1 can ping gateway 2
    Given a fabric with 2 gateways
    When gateway 1 pings gateway 2
    Then the ping from gateway 1 to gateway 2 succeeds

  Scenario: gateway 2 can ping gateway 1
    Given a fabric with 2 gateways
    When gateway 2 pings gateway 1
    Then the ping from gateway 2 to gateway 1 succeeds
