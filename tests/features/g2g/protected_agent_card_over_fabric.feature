Feature: Protected agent card fetch over Fabric
  A gateway receiving a Fabric forward answers the peer's agent card fetch with
  its own Target credential and nothing else from the caller. Any other public
  read is forwarded without that credential; an authenticated caller's request
  still carries it. The sending gateway runs its surface policy on everything
  that is not a public discovery read.

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
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "x-gateway-trace-id"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" had an empty body

  Scenario: gateway 2 refuses the agent card fetch when its Target credential cannot be resolved
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback reject
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then the response status is 502
    And the response says "Upstream error: 502"
    And managed agent "bravo" was not called

  Scenario: gateway 2 refuses a Fabric A2A message when its Target credential cannot be resolved
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback reject
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 502
    And the response says "Target authentication failed"
    And managed agent "bravo" was not called

  Scenario: gateway 2 fetches the configured card location with its Target credential for a caller without an API key
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" requires "API Key" source authentication and forwards failed callers to policy
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request without an API key to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/cards/me"
    And the GET request at path "/cards/me" to managed agent "bravo" carried header "x-target-api-key" with value "bdd-target-secret"
    And the GET request at path "/cards/me" to managed agent "bravo" had an empty body

  Scenario: gateway 2 relays only the headers that describe the card from its configured card location
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And managed agent "bravo" answers with header "set-cookie" set to "session=bravo-target"
    And managed agent "bravo" answers with header "cache-control" set to "max-age=60"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 200
    And the response to the caller did not carry header "set-cookie"
    And the response to the caller carried header "cache-control"

  Scenario: gateway 2 answers a refused card fetch at its configured card location with only the status
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And managed agent "bravo" refuses with status 401 saying "credential rejected for account acct-bravo-7731"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 401
    And the response says "Upstream error: 401"
    And the response does not say "acct-bravo-7731"

  Scenario: gateway 2 gives no transit token on its agent card fetch but gives one on a forwarded call
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has A2A Transit Point "to-echo" over Fabric to gateway 3 surface "echo"
    And Transit Point "to-echo" requires a transit token
    And the caller has sent a Fabric A2A request through gateway 1 surface "charlie"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then the response status is 200
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "x-transit-token"
    And managed agent "bravo" received a transit token for the request gateway 1 sent

  Scenario: gateway 2 presents its Target credential when it reads the agent card for its surface policy
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" publishes an agent card naming DID "did:example:bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has a request policy that allows only requests whose Target agent card names DID "did:example:bravo"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent.json"
    And the GET request at path "/.well-known/agent.json" to managed agent "bravo" carried header "x-target-api-key" with value "bdd-target-secret"

  Scenario: gateway 2 reads the agent card for its surface policy once for two requests
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" publishes an agent card naming DID "did:example:bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has a request policy that allows only requests whose Target agent card names DID "did:example:bravo"
    And the caller has sent a Fabric A2A request through gateway 1 surface "charlie"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent.json"

  Scenario: gateway 2 denies a request when its Target credential for the policy card read cannot be resolved
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" publishes an agent card naming DID "did:example:bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback reject
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" starts with a request policy that allows only requests whose Target agent card names DID "did:example:bravo"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 403
    And managed agent "bravo" did not receive a GET request at path "/.well-known/agent.json"
    And managed agent "bravo" was not called

  Scenario Outline: gateway 2 forwards a read that is not its agent card fetch without its Target credential
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
      | /x/agent-card.json                | /x/agent-card.json                |

  Scenario: gateway 2 does not treat a card path whose case differs as its agent card fetch
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" requires "API Key" source authentication and forwards failed callers to policy
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request without an API key to gateway 1 surface "charlie" path "/.well-known/Agent-Card.json"
    Then managed agent "bravo" received a GET request at path "/.well-known/Agent-Card.json"
    And the GET request at path "/.well-known/Agent-Card.json" to managed agent "bravo" did not carry header "x-target-api-key"

  Scenario: gateway 1 runs its surface policy on a POST to a path that only ends like an agent card
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" has a request policy that denies all requests
    When the caller sends a POST request to gateway 1 surface "charlie" path "/rpc/agent-card.json"
    Then the response status is 403
    And managed agent "bravo" did not receive a POST request at path "/rpc/agent-card.json"

  Scenario: gateway 1 runs its surface policy on a POST to a public discovery path
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" has a request policy that denies all requests
    When the caller sends a POST request to gateway 1 surface "charlie" path "/discovery"
    Then the response status is 403
    And managed agent "bravo" did not receive a POST request at path "/discovery"

  Scenario: gateway 1 answers a POST to its well-known agent card path with its own card GET before policy
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" has a request policy that denies all requests
    When the caller sends a POST request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And managed agent "bravo" did not receive a POST request at path "/.well-known/agent-card.json"

  Scenario Outline: gateway 1 does not apply its surface policy to a public discovery read
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" has a request policy that denies all requests
    When the caller sends a <method> request to gateway 1 surface "charlie" path "<path>"
    Then the response status is 200
    And managed agent "bravo" received a <method> request at path "<path>"

    Examples:
      | method | path             |
      | GET    | /x/agent.json    |
      | HEAD   | /x/agent.json    |
      | GET    | /discovery       |
      | GET    | /.well-known/ucp |
