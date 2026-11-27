Feature: Transit Point identity from its caller's credential
  A Transit Point can take the managed agent's DID from the API key, a claim of the JWT, or the
  client certificate its caller presented to the Transit Point's own caller authentication. The credential's DID
  replaces any identity the request body asserts, so a caller with a copied identity extension
  gets the DID of its own key, and the same key or claim value gives the same DID on the Access
  Point and on the Transit Point.

  Background:
    Given A2A surface "alpha" is defined for route "/example" with managed agent "bravo" as its target

  Scenario: A Transit Point gives the managed agent the DID of the key it presented
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with key "bravo-key"
    Then the response status is 200
    And external agent "delta" received the request with a VP proving the DID of key "bravo-key"

  Scenario: A Transit Point that takes its identity from the caller's key forwards a task request
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    When managed agent "bravo" sends an A2A tasks/get request through Transit Point "tr1" with key "bravo-key"
    Then the response status is 200
    And external agent "delta" received a forwarded request
    And external agent "delta" received no identity presentation

  Scenario: A Transit Point that takes its identity from the caller's key refuses a JSON-RPC batch
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    When managed agent "bravo" sends an A2A JSON-RPC batch through Transit Point "tr1" with key "bravo-key"
    Then the response status is 400
    And the response is a JSON-RPC error with code -32600
    And external agent "delta" was not called

  Scenario: The Agents API lists each DID a Transit Point took from its callers' keys
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    And API key provider "agents" has issued key "bravo-second-key"
    And managed agent "bravo" has sent a request through Transit Point "tr1" with key "bravo-key"
    And managed agent "bravo" has sent a request through Transit Point "tr1" with key "bravo-second-key"
    When the operator lists the agents
    Then the admin API response status is 200
    And the agents list gives one agent the DIDs of keys "bravo-key" and "bravo-second-key"

  Scenario: A Transit Point policy admits a managed agent whose identity its key verified
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    And Transit Point "tr1" has a policy that admits only a managed agent whose identity verification is "source_auth"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with key "bravo-key"
    Then the response status is 200
    And external agent "delta" received the request with a VP proving the DID of key "bravo-key"

  Scenario: A Transit Point policy refuses a managed agent identity taken from a plain API key
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    And Transit Point "tr1" has a policy that admits only a managed agent whose identity verification is "source_auth"
    And Transit Point "tr1" authenticates its callers with API key "bravo-plain-key"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "X-API-Key" set to "bravo-plain-key"
    Then the response status is 403
    And external agent "delta" was not called

  Scenario: A Transit Point policy refuses a managed agent identity taken from the request
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And transit point "tr1" maps managed-agent header "x-ms-entra-agent-id" to A2A metadata field "entra_agent_id"
    And transit point "tr1" maps managed-agent header "x-ms-client-tenant-id" to A2A metadata field "client_tenant_id"
    And transit point "tr1" derives outbound managed-agent identity from mapped A2A metadata fields "entra_agent_id" and "client_tenant_id"
    And Transit Point "tr1" has a policy that admits only a managed agent whose identity verification is "source_auth"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-ms-entra-agent-id" set to "agent-123" and header "x-ms-client-tenant-id" set to "tenant-456"
    Then the response status is 403
    And external agent "delta" was not called

  Scenario: A caller with a copied identity extension gets the DID of its own key
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    And API key provider "agents" has issued key "rogue-key"
    And managed agent "bravo" has sent a request through Transit Point "tr1" with key "bravo-key"
    And the request carries a copy of managed agent "bravo"'s identity extension
    And the copy also carries an identity binding naming managed agent "bravo"'s DID
    When agent "rogue" sends an A2A message/send request through Transit Point "tr1" with key "rogue-key"
    Then the response status is 200
    And external agent "delta" received the request with a VP proving the DID of key "rogue-key"
    And the DID is not the DID of key "bravo-key"
    And external agent "delta" received no identity binding

  Scenario: A caller without the key gets no identity
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    And managed agent "bravo" has sent a request through Transit Point "tr1" with key "bravo-key"
    And the request carries a copy of managed agent "bravo"'s identity extension
    When agent "rogue" sends an A2A message/send request through Transit Point "tr1" with no key
    Then the response status is 401
    And external agent "delta" was not called

  Scenario: The same API key gives the same DID on the Access Point and the Transit Point
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And surface "alpha" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And surface "alpha"'s inbound identity takes its DID from the caller's API key
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    And a caller has sent a request to the Access Point with key "bravo-key"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with key "bravo-key"
    Then the response status is 200
    And both identity presentations prove the same DID

  Scenario: An MCP caller with a copied identity gets the DID of its own key
    Given Transit Point "tr1" routes to MCP server "delta"
    And MCP server "delta" supports tool invocation
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from its caller's API key
    And API key provider "agents" has issued key "rogue-key"
    And managed agent "bravo" has invoked MCP tool "search" through Transit Point "tr1" with key "bravo-key"
    And the request carries a copy of managed agent "bravo"'s identity extension
    And the copy also carries an identity binding naming managed agent "bravo"'s DID
    When agent "rogue" invokes MCP tool "search" through Transit Point "tr1" with key "rogue-key"
    Then the response status is 200
    And MCP server "delta" received the request with a VP proving the DID of key "rogue-key"
    And the DID is not the DID of key "bravo-key"
    And MCP server "delta" received no identity binding

  Scenario: A Transit Point identity from the caller's API key needs API key caller authentication
    Given a surface draft whose Transit Point "tr1" authenticates its callers with JWT Bearer
    And Transit Point "tr1" in the draft takes the managed agent's identity from its caller's API key
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response names Transit Point "tr1" and its caller authentication

  Scenario: A Transit Point gives one DID per value of the JWT claim
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with JWT Bearer tokens for audience "tr1"
    And Transit Point "tr1" takes the managed agent's identity from the JWT claim "oid"
    And managed agent "bravo" has sent a request through Transit Point "tr1" with a token whose "oid" is "bdd-agent-one"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with a token whose "oid" is "bdd-agent-two"
    Then the response status is 200
    And external agent "delta" received two requests with VPs proving different DIDs

  Scenario: A Transit Point refuses a token without the claim its identity reads
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with JWT Bearer tokens for audience "tr1"
    And Transit Point "tr1" takes the managed agent's identity from the JWT claim "oid"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with a token without "oid"
    Then the response status is 422
    And external agent "delta" was not called

  Scenario: A stored Transit Point identity from a JWT claim without JWT Bearer caller authentication refuses its callers
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And Transit Point "tr1" takes the managed agent's identity from the JWT claim "oid"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with key "bravo-key"
    Then the response status is 500
    And external agent "delta" was not called

  Scenario: A Transit Point identity from a JWT claim needs JWT Bearer caller authentication
    Given a surface draft whose Transit Point "tr1" authenticates its callers with an API key
    And Transit Point "tr1" in the draft takes the managed agent's identity from the JWT claim "oid"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response names Transit Point "tr1" and its caller authentication

  Scenario: A Transit Point gives one DID per client certificate principal
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers by client certificates issued by CA "agents-ca"
    And Transit Point "tr1" takes the managed agent's identity from its caller's client certificate
    And managed agent "bravo" has sent a request through Transit Point "tr1" with a client certificate for "bdd-agent-one"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with a client certificate for "bdd-agent-two"
    Then the response status is 200
    And external agent "delta" received two requests with VPs proving different DIDs

  Scenario: A Transit Point identity from the caller's certificate needs mTLS caller authentication
    Given a surface draft whose Transit Point "tr1" authenticates its callers with an API key
    And Transit Point "tr1" in the draft takes the managed agent's identity from its caller's client certificate
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response names Transit Point "tr1" and its caller authentication

  Scenario: A save warns of a Transit Point JWT claim identity the issuer does not namespace
    Given a surface draft whose Transit Point "tr1" authenticates its callers with JWT Bearer
    And Transit Point "tr1" in the draft takes the managed agent's identity from the JWT claim "oid"
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries a Warning header containing "add 'iss' to namespace_claims"

  Scenario: A save does not warn of a Transit Point JWT claim identity namespaced by the issuer
    Given a surface draft whose Transit Point "tr1" authenticates its callers with JWT Bearer
    And Transit Point "tr1" in the draft takes the managed agent's identity from the JWT claim "oid" namespaced by claim "iss"
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries no Warning header containing "namespace_claims"

  Scenario: A stored Access Point identity from a client certificate it does not name refuses its callers
    Given surface "alpha" authenticates its callers with an API key of API key provider "agents"
    And surface "alpha" was stored with its inbound Identity taking its DID from a client certificate it does not name
    When a caller sends a request to the Access Point with key "bravo-key"
    Then the response status is 500
    And the response mentions "Caller identity could not be resolved"
    And managed agent "bravo" was not called

  Scenario: A Transit Point that inherits a client certificate identity it does not name refuses its callers
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And surface "alpha" was stored with its protected Identity taking its DID from a client certificate it does not name
    And transit point "tr1" presents the surface's managed agent identity on its outbound calls
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 500
    And the response mentions "Caller identity could not be resolved"
    And external agent "delta" was not called

  Scenario: A surface policy reads no identity hash for a static DID
    Given surface "alpha" gives its callers the static DID "did:web:caller.example"
    And surface "alpha" has a policy that admits only caller DID "did:web:caller.example" without an identity hash
    When the caller sends an A2A message/send request to surface "alpha" with header "X-Example" set to "alpha"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A variant's Transit Point gives the managed agent the DID of the key it presented
    Given surface "alpha" has A2A Transit Point "tr1" to external agent "delta"
    And Transit Point "tr1" authenticates its callers with an API key of API key provider "agents"
    And surface "alpha" has variant "beta" whose Transit Point "tr1" takes the managed agent's identity from its caller's API key
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" of variant "beta" with key "bravo-key"
    Then the response status is 200
    And external agent "delta" received the request with a VP proving the DID of key "bravo-key"
