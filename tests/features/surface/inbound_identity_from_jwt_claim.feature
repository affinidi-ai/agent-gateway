Feature: Inbound identity derived from a JWT claim
  An Access Point whose inbound identity comes from a JWT claim refuses a caller
  whose credential is missing or invalid before policy. A caller authenticated
  by another source authentication method is served with no identity.

  Scenario Outline: An Access Point deriving the inbound identity from a JWT claim refuses a caller whose token is missing or invalid
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface <credential condition>
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response content type is "application/problem+json"
    And the response says only that the caller credential is missing or invalid

    Examples:
      | credential condition       |
      | without a token            |
      | with an expired token      |
      | with a tampered token      |
      | with a malformed token     |

  Scenario Outline: An MCP surface deriving the inbound identity from a JWT claim refuses a caller whose token is missing or invalid
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives the inbound identity from a JWT claim
    When the caller asks the MCP surface for available tools <credential condition>
    Then the response status is 401
    And the response carries a non-empty "www-authenticate" header
    And MCP server "bravo" was not called
    And the MCP response says only that the caller credential is missing or invalid
    And the MCP response id matches the request id

    Examples:
      | credential condition       |
      | without a token            |
      | with an expired token      |
      | with a tampered token      |
      | with a malformed token     |

  Scenario: An Access Point deriving the inbound identity from a JWT claim forwards a caller with a valid token
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with a VP proving the Agent DID of the token's subject

  Scenario: A surface deriving the inbound identity from a JWT claim gives a token caller beside an API key method its identity
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with a VP proving the Agent DID of the token's subject

  Scenario: A surface deriving the inbound identity from a JWT claim serves an API key caller with no identity, even one it proves
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid API key and an identity proof of its own
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with no caller identity

  Scenario: A surface deriving the inbound identity from a JWT claim maps no identity proof from a header of an API key caller
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the surface maps caller header "x-caller-presentation" into the identity binding presentation
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid API key and header "x-caller-presentation" set to "caller-made-presentation"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with no caller identity

  Scenario: A surface deriving the inbound identity from a JWT claim gives an API key caller no identity from a presentation it signed
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the surface has managed identity enabled
    And the surface has a request policy that requires a verified caller identity
    And the caller's DID document lists its key for assertions
    When the caller sends a request to the surface with a valid API key and a presentation of a credential it issued itself
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: A surface deriving the inbound identity from a JWT claim refuses an API key caller's body it cannot read
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the surface's A2A validation is "off"
    When the caller sends a request to the surface with a valid API key and an identity proof of its own beside a value nested too deeply to read
    Then the response status is 400
    And managed agent "bravo" was not called

  Scenario: A surface deriving the inbound identity from a JWT claim without a JWT Bearer method is refused at save
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    When the operator attempts to create the surface for route "/example"
    Then the admin API response status is 400
    And the admin API error response mentions "inbound from_jwt_claim identity needs a jwt_bearer source authentication method"

  Scenario: A surface deriving the inbound identity from a JWT claim tells the Target no DID an API key caller asserts
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the surface has a request policy that allows all requests
    When the caller sends a request to the surface with a valid API key and a trust-registry agent DID "did:web:asserted.example"
    Then the response status is 200
    And managed agent "bravo" received header "x-caller-did" with value "anonymous"

  Scenario: An MCP surface deriving the inbound identity from a JWT claim forwards no identity proof of an API key caller
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    When the caller asks the MCP surface for available tools with a valid API key and an identity proof of its own
    Then the response status is 200
    And MCP server "bravo" did not receive MCP _meta key "https://fabric.affinidi.io/extensions/agent-identity-binding/v1"

  Scenario: A surface deriving the inbound identity from a JWT claim refuses an API key caller's body with a duplicate metadata member
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the surface's A2A validation is "off"
    When the caller sends a request to the surface with a valid API key and an identity proof of its own beside a duplicate metadata member
    Then the response status is 400
    And managed agent "bravo" was not called

  Scenario: A surface deriving the inbound identity from a JWT claim shows policy no identity proof or trust-registry claim of an API key caller
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the surface has a request policy that denies a message carrying an identity proof or trust-registry claim
    When the caller sends a request to the surface with a valid API key and an identity proof of its own
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with no caller identity

  Scenario: An MCP surface deriving the inbound identity from a JWT claim shows policy no identity proof or trust-registry claim of an API key caller
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And MCP server "bravo" supports modern tool invocation with "application/json" responses
    And the MCP surface has a request policy that denies a request carrying an identity proof or trust-registry claim
    When the caller invokes MCP tool "echo" using protocol version "2026-07-28" with a valid API key and an identity proof of its own
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request

  Scenario: An MCP surface deriving the inbound identity from a JWT claim shows a tool policy no identity proof or trust-registry claim of an API key caller
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from a JWT claim
    And the surface accepts JWT audience "bdd-test-audience"
    And the MCP surface enforces a wildcard default tool policy that denies a call carrying an identity proof or trust-registry claim
    When the caller invokes MCP tool "get_news" with a valid API key and an identity proof of its own
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
