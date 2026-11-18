Feature: Live policy input capture of requests received over Fabric
  A request a gateway receives over Fabric is evaluated by its policies like a direct
  one. While an operator of the receiving gateway listens to the policy input of the
  surface it reaches, their Capture view shows those evaluations.

  Scenario: The receiving gateway's Capture view shows its gateway-level policy denying a Fabric caller
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 2 has a Gateway-level policy that rejects all fabric callers
    And policy input capture is turned on on gateway 2
    And the operator listens to the policy input of gateway 2 surface "alpha"
    When the caller asks gateway 1 MCP surface "charlie" for available tools
    Then the response status is 403
    And the Capture view on gateway 2 shows the "gateway" policy of surface "alpha" deciding "deny" on an input showing "tools/list"

  Scenario: The receiving gateway's Capture view masks a credential in the query of a Fabric caller's path
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 2 has a Gateway-level policy that rejects all fabric callers
    And policy input capture is turned on on gateway 2
    And the operator listens to the policy input of gateway 2 surface "alpha"
    When the caller sends a POST request to gateway 1 surface "charlie" path "/messages?token=bdd-fabric-query-secret"
    Then the response status is 403
    And the Capture view on gateway 2 shows the "gateway" policy of surface "alpha" deciding "deny" on an input showing "/messages?token=<redacted>"
    And no captured policy input of surface "alpha" on gateway 2 contains "bdd-fabric-query-secret"
