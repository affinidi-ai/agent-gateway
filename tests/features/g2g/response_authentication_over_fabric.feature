Feature: Response authentication over Fabric
  A gateway receiving a Fabric request applies its own surface's Response authentication to
  its managed agent's response. A response without the registered key is refused with 502
  before anything uses it, the refusal is recorded as a refused Fabric request, and the
  sending gateway's caller gets the 502. A response with the key reaches the caller without it.

  Scenario: A Fabric request is refused when the managed agent's response is not authenticated
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 2 surface "alpha" has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And surface "alpha" authenticates its Target's responses by the API key in secret "bravo-key" holding "bravo-secret" in header "X-Agent-Key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 502
    And the VP Audit Log of gateway 2 records that a Fabric request to surface "alpha" was refused for a Target response that is not authenticated
    And gateway 2 issued no managed agent identity

  Scenario: A Fabric request is served without the key when the managed agent's response carries it
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" authenticates its Target's responses by the API key in secret "bravo-key" holding "bravo-secret" in header "X-Agent-Key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And managed agent "bravo" answers with header "X-Agent-Key" set to "bravo-secret"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And the response to the caller did not carry header "X-Agent-Key"

  Scenario: A managed agent identity is issued for an authenticated response over Fabric
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 2 surface "alpha" has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And surface "alpha" authenticates its Target's responses by the API key in secret "bravo-key" holding "bravo-secret" in header "X-Agent-Key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And managed agent "bravo" answers with header "X-Agent-Key" set to "bravo-secret"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And gateway 2 issued a managed agent identity
