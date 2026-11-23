Feature: Inbound identity derived from the API key a caller presents
  An Access Point whose inbound identity comes from the API key a caller
  presents identifies each API key caller by its key. A caller authenticated by
  another Caller Context method is served with no identity.

  Scenario: A surface deriving the inbound identity from the API key gives an API key caller beside a JWT method its identity
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from the API key the caller presents
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with a VP proving the caller Agent DID

  Scenario: A surface deriving the inbound identity from the API key serves a token caller with no identity
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from the API key the caller presents
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with no caller identity
