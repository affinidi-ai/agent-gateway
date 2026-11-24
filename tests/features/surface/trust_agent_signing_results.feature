Feature: What the gateway signs through a trust agent verifies against the trust agent's key
  When the gateway signs through a trust agent, the trust agent's key signs, and what it
  hands out names the DID of the trust agent context that holds that key as its issuer, not
  the gateway's DID. The gateway publishes that key so verifiers can check its tokens. When
  the trust agent that was chosen cannot be reached, the gateway refuses to sign rather than
  sign with a key of its own.

  Scenario: A token the gateway issues while it signs through a trust agent is signed by the trust agent's key
    Given the operator has connected a trust agent that signs as its context "orders" with key "orders-key"
    And the gateway signs through that trust agent by default
    And the operator has a managed connection for agent "alpha" allowing audience "/reports"
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    When agent "alpha" exchanges the identity assertion for a token scoped to audience "/reports"
    Then the response status is 200
    And the issued token is signed by the trust agent's key
    And the issued token names the trust agent context's DID as its issuer

  Scenario: The gateway publishes the trust agent's key for verifiers of its tokens
    Given the operator has connected a trust agent that signs as its context "orders" with key "orders-key"
    And the gateway signs through that trust agent by default
    When a verifier reads the gateway's published token keys
    Then the published token keys include the trust agent's key

  Scenario: A token is refused rather than signed by the gateway when its trust agent cannot be reached
    Given the operator has connected a trust agent that signs as its context "orders" with key "orders-key"
    And the gateway signs through that trust agent by default
    And the operator has a managed connection for agent "alpha" allowing audience "/reports"
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    And the trust agent can no longer be reached
    When agent "alpha" exchanges the identity assertion for a token scoped to audience "/reports"
    Then the response status is 500
    And no token is issued

  Scenario: The caller's identity presentation on a surface that signs through a trust agent carries a credential its context issued
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface has an explicit inbound identity slot for MCP
    And MCP server "bravo" supports tool invocation
    And the operator has connected a trust agent that signs as its context "orders" with key "orders-key"
    And the surface signs through that trust agent
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload
    Then the response status is 200
    And MCP server "bravo" received a presentation whose credential the trust agent context issued

  Scenario: A surface whose trust agent cannot be reached forwards no request with an identity it did not sign
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface has an explicit inbound identity slot for MCP
    And MCP server "bravo" supports tool invocation
    And the operator has connected a trust agent that signs as its context "orders" with key "orders-key"
    And the surface signs through that trust agent
    And the trust agent can no longer be reached
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload
    Then the response status is 503
    And MCP server "bravo" was not called

  Scenario: The managed agent's identity on a surface that signs through a trust agent carries a credential its context issued
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface has managed identity enabled
    And MCP server "bravo" includes an agent-identity extension in responses
    And the operator has connected a trust agent that signs as its context "orders" with key "orders-key"
    And the surface signs through that trust agent
    When the caller invokes MCP tool "get_news"
    Then the response status is 200
    And the MCP response carries a presentation whose credential the trust agent context issued

  Scenario: The agent card a surface that signs through a trust agent serves carries a credential its context issued
    Given A2A surface "orders" is defined for route "/orders" with managed agent "bravo" as its target
    And the surface has managed identity enabled
    And managed agent "bravo" publishes the agent-identity extension on its agent card
    And the operator has connected a trust agent that signs as its context "orders" with key "orders-key"
    And the surface signs through that trust agent
    When the caller fetches the agent card for surface "orders"
    Then the response status is 200
    And the agent card carries a presentation whose credential the trust agent context issued
