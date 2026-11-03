Feature: Protected agent card fetch over fabric
  A gateway receiving a fabric forward answers the peer's agent card fetch with
  its own Target credential and nothing else from the caller. Any other request
  is forwarded without that credential, and the sending gateway runs its surface
  policy on everything that is not a public discovery read.

  Scenario: gateway 2 fetches the agent card with only the peer's content negotiation headers
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json" with headers
      | cookie           | session=caller   |
      | authorization    | Bearer caller    |
      | x-forwarded-user | caller-forged    |
      | x-target-api-key | caller-forged    |
      | accept-language  | en-GB            |
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" carried header "x-target-api-key" with value "bdd-target-secret"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" carried header "accept-language" with value "en-GB"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "cookie"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "authorization"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "x-forwarded-user"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "x-transit-token"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" had an empty body

  Scenario: gateway 2 refuses the agent card fetch when its target credential cannot be resolved
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback reject
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then the response status is 502
    And the response says "Target authentication failed"
    And managed agent "bravo" was not called

  Scenario: gateway 2 presents its target credential when it reads the agent card for its surface policy
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And surface "alpha" has a request policy that allows all requests
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent.json"
    And the GET request at path "/.well-known/agent.json" to managed agent "bravo" carried header "x-target-api-key" with value "bdd-target-secret"

  Scenario Outline: gateway 2 forwards a read that is not its agent card fetch without its target credential
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "<path>"
    Then managed agent "bravo" received a GET request at path "<forwarded path>"
    And the GET request at path "<forwarded path>" to managed agent "bravo" did not carry header "x-target-api-key"

    Examples:
      | path                              | forwarded path                    |
      | /discovery                        | /discovery                        |
      | /.well-known/ucp                  | /.well-known/ucp                  |
      | /x/%2e%2e/discovery               | /discovery                        |

  Scenario: gateway 2 does not treat a card path whose case differs as its agent card fetch
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/Agent-Card.json"
    Then managed agent "bravo" received a GET request at path "/.well-known/Agent-Card.json"
    And the GET request at path "/.well-known/Agent-Card.json" to managed agent "bravo" did not carry header "x-target-api-key"

  Scenario: gateway 1 runs its surface policy on a POST to a card-like path
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" has a request policy that denies all requests
    When the caller sends a POST request to gateway 1 surface "charlie" path "/rpc/agent-card.json"
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: gateway 1 does not apply its surface policy to a read of the agent card
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" has a request policy that denies all requests
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
