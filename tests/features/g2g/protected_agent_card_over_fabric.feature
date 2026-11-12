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
      | x-forwarded-user | caller-forged    |
      | x-caller-note    | from-the-caller  |
      | x-target-api-key | caller-forged    |
      | accept-language  | en-GB            |
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" carried header "x-target-api-key" with value "bdd-target-secret"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" carried header "accept-language" with value "en-GB"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" carried header "accept-encoding" with value "identity"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "x-forwarded-user"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "x-caller-note"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" did not carry header "x-gateway-trace-id"
    And the GET request at path "/.well-known/agent-card.json" that gateway 2 sent to managed agent "bravo" carried only headers "accept, accept-encoding, accept-language, x-target-api-key"

  Scenario: gateway 2 refuses the agent card fetch when its Target credential cannot be resolved
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback reject
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then the response status is 502
    And the response detail is "Target authentication failed"
    And managed agent "bravo" was not called
    And the VP Audit Log of gateway 2 records that the Target credential of surface "alpha" was not sent on a Fabric request, which was refused

  Scenario: gateway 2 under fallback passthrough fetches its configured card location without its Target credential
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" publishes an agent card naming DID "did:example:bravo"
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" is configured with missing target authentication secret "bdd-missing-target-auth-secret" for header "x-target-api-key" and fallback passthrough
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    When the caller sends a GET request with an A2A message body to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 200
    And the response says "did:example:bravo"
    And the GET request at path "/cards/me" to managed agent "bravo" did not carry header "x-target-api-key"
    And the GET request at path "/cards/me" to managed agent "bravo" had an empty body
    And the VP Audit Log of gateway 2 records that the Target credential of surface "alpha" was not sent on a Fabric request, which was forwarded without it

  Scenario: gateway 2 fetches the agent card with its credential provider's token
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" publishes an agent card with url "http://bravo.internal/a2a"
    And surface "alpha" authenticates to its managed agent with a client credentials provider
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then the response status is 200
    And the agent card url points to gateway 1 surface "charlie"
    And the GET request at path "/.well-known/agent-card.json" to managed agent "bravo" carried header "authorization" with value "Bearer bdd-target-provider-token"

  Scenario: gateway 2 refuses the agent card fetch when its credential provider refuses a token
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" authenticates to its managed agent with a client credentials provider
    And the credential provider of surface "alpha" is refusing token requests
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then the response status is 502
    And the response detail is "Target authentication failed"
    And the response does not say "bdd-target-client-secret-value"
    And the response does not say "invalid_client"
    And managed agent "bravo" was not called

  Scenario: gateway 2 answers a redirected agent card fetch as the direct path does
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And managed agent "bravo" refuses with status 302 saying "sign in at the identity provider"
    And managed agent "bravo" answers with header "location" set to "https://idp.example/login"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/agent-card.json"
    Then the response status is 502
    And the response detail is "Upstream redirected"
    And the response to the caller did not carry header "location"
    And the response does not say "idp.example"

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
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" is stored with a public Access Point
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request with an A2A message body to gateway 1 surface "charlie" path "/cards/me"
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
    And managed agent "bravo" answers with header "x-target-internal" set to "bravo-only"
    And managed agent "bravo" answers with header "cache-control" set to "max-age=60"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 200
    And the response to the caller did not carry header "x-target-internal"
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

  Scenario: gateway 2 gives no transit token on its agent card fetch at its configured card location but gives one on a forwarded call
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has A2A Transit Point "to-echo" over Fabric to gateway 3 surface "echo"
    And Transit Point "to-echo" requires a transit token
    And the caller has sent a Fabric A2A request through gateway 1 surface "charlie"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 200
    And the GET request at path "/cards/me" to managed agent "bravo" carried header "x-target-api-key" with value "bdd-target-secret"
    And the GET request at path "/cards/me" to managed agent "bravo" did not carry header "x-transit-token"
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

  Scenario: gateway 2 presents its credential provider's token when it reads the agent card for its surface policy
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" publishes an agent card naming DID "did:example:bravo"
    And surface "alpha" authenticates to its managed agent with a client credentials provider
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "alpha" has a request policy that allows only requests whose Target agent card names DID "did:example:bravo"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And the GET request at path "/.well-known/agent.json" to managed agent "bravo" carried header "authorization" with value "Bearer bdd-target-provider-token"

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
    And surface "alpha" has a request policy that allows only requests whose Target agent card names DID "did:example:bravo"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 403
    And managed agent "bravo" did not receive a GET request at path "/.well-known/agent.json"
    And managed agent "bravo" was not called

  Scenario Outline: gateway 2 forwards a read that is not its agent card fetch without its Target credential
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a <method> request to gateway 1 surface "charlie" path "<path>"
    Then the response status is 200
    And managed agent "bravo" received a <method> request at path "<path>"
    And the <method> request at path "<path>" to managed agent "bravo" did not carry header "x-target-api-key"

    Examples:
      | method | path               |
      | GET    | /discovery         |
      | GET    | /.well-known/ucp   |
      | GET    | /x/agent-card.json |
      | HEAD   | /x/agent-card.json |
      | HEAD   | /discovery         |

  Scenario: gateway 2 forwards an authenticated caller's POST to its configured card location with its body and Target credential
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" is stored with a public Access Point
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a POST request to gateway 1 surface "charlie" path "/cards/me" with headers
      | x-api-key | bdd-source-api-key |
    Then the response status is 200
    And managed agent "bravo" received a POST request at path "/cards/me"
    And the POST request at path "/cards/me" to managed agent "bravo" carried header "x-target-api-key" with value "bdd-target-secret"
    And the POST request at path "/cards/me" to managed agent "bravo" carried the caller's A2A message parts

  Scenario: gateway 2 forwards a POST to its configured card location from a caller without an API key without its Target credential
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" is stored with a public Access Point
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a POST request to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 200
    And managed agent "bravo" received a POST request at path "/cards/me"
    And the POST request at path "/cards/me" to managed agent "bravo" did not carry header "x-target-api-key"
    And the POST request at path "/cards/me" to managed agent "bravo" carried the caller's A2A message parts

  Scenario: gateway 2 forwards a HEAD of its configured card location from a caller without an API key without its Target credential
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" is stored with a public Access Point
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a HEAD request to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 200
    And managed agent "bravo" received a HEAD request at path "/cards/me"
    And the HEAD request at path "/cards/me" to managed agent "bravo" did not carry header "x-target-api-key"

  Scenario: gateway 2 refuses the configured card location to a caller without an API key on a closed Access Point
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" fetches its agent card from path "/cards/me"
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/cards/me"
    Then the response status is 401
    And the response says "Caller credential missing or invalid"
    And managed agent "bravo" was not called

  Scenario: gateway 2 does not treat a card path whose case differs as its agent card fetch
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" is stored with a public Access Point
    And surface "alpha" injects target authentication from secret "bdd-target-auth-secret" with value "bdd-target-secret" as header "x-target-api-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a GET request to gateway 1 surface "charlie" path "/.well-known/Agent-Card.json"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/Agent-Card.json"
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
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
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
