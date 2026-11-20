Feature: Response authentication
  A surface that authenticates its Target's responses by API key accepts a response only when
  it carries a key of the registered secret in the configured header, and removes that header
  before the caller sees the response. A surface that authenticates them by mTLS accepts a
  response only from a server holding the registered certificate, and can present the
  gateway's client certificate to the managed agent. A response that fails is refused with 502
  before anything uses it, and the VP Audit Log records the refusal. Only an http or https
  Target has a managed agent whose responses can be authenticated, and only an https one by
  mTLS.

  Scenario: A response from the registered managed agent is served
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" serves https with certificate "bravo-cert"
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the surface authenticates its Target's responses by the pinned certificate "bravo-cert"
    When the caller sends a request to the surface
    Then the response status is 200
    And the response contains the credential extension

  Scenario: A response from a server without the registered certificate is refused
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" serves https with certificate "impostor-cert"
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the VP Audit Log keeps every audit event
    And the surface authenticates its Target's responses by the pinned certificate "bravo-cert"
    When the caller sends a request to the surface
    Then the response status is 502
    And the response is a JSON-RPC error with code -32603
    And the VP Audit Log records a request refusal for "a Target response that is not authenticated"
    And no managed agent identity is issued

  Scenario: The gateway presents its client certificate to the managed agent
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" serves https with certificate "bravo-cert"
    And the surface authenticates its Target's responses by the pinned certificate "bravo-cert" and presents client certificate "gateway-cert"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received client certificate "gateway-cert"

  Scenario: mTLS on an http Target cannot be saved
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft authenticates its Target's responses by the pinned certificate "bravo-cert"
    And the draft's Target is a plain http URL
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.response_auth.mtls needs an https Target"

  Scenario: A response carrying the registered key is served without the key
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its Target's responses by the API key in secret "bravo-key" holding "bravo-secret" in header "X-Agent-Key"
    And managed agent "bravo" responds with header "X-Agent-Key" set to "bravo-secret"
    When the caller sends a request to the surface
    Then the response status is 200
    And the response does not include header "X-Agent-Key"

  Scenario: A response without the registered key is refused and audited
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its Target's responses by the API key in secret "bravo-key" holding "bravo-secret" in header "X-Agent-Key"
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface
    Then the response status is 502
    And the response is a JSON-RPC error with code -32603
    And the VP Audit Log records a request refusal for "a Target response that is not authenticated"

  Scenario: Response authentication on a Target with no managed agent cannot be saved
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft authenticates its Target's responses by the API key in secret "target-key" in header "X-Agent-Key"
    And the draft's Target is "a2a-proxy://proxy-1"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.response_auth needs an http or https Target"
