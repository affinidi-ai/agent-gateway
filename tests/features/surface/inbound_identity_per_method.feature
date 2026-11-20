Feature: Caller identity per source authentication method
  Each source authentication method can say how its callers' identity is derived
  from the credential they present, so a surface mixing JWT Bearer and API Key
  serves both, each caller with its own identity. A caller of a method that sets
  no identity, which the surface's inbound identity cannot read, is refused
  before policy and before the Target.

  Scenario: A surface whose methods identify their callers serves a caller with a valid token
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface's "JWT Bearer" source authentication identifies its callers from a JWT claim
    And the surface's "API Key" source authentication identifies its callers by their API key
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received a forwarded request

  Scenario: A surface whose methods identify their callers serves a caller with a valid API key
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface's "JWT Bearer" source authentication identifies its callers from a JWT claim
    And the surface's "API Key" source authentication identifies its callers by their API key
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received a forwarded request

  Scenario: A surface whose methods identify their callers gives a token caller and an API key caller different identities
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface's "JWT Bearer" source authentication identifies its callers from a JWT claim
    And the surface's "API Key" source authentication identifies its callers by their API key
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    And the caller has sent a request to the surface with a valid token
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received two forwarded requests with VPs proving different caller Agent DIDs

  Scenario: A surface identifying callers by their API key refuses a token caller whose method sets no identity
    Given an A2A surface targeting managed agent "bravo"
    And the VP Audit Log keeps every audit event
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from the API key the caller presents
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example"
    When the caller sends a request to the surface with a valid token
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response says only that the caller credential is missing or invalid
    And the response carries no "www-authenticate" header
    And the VP Audit Log records a blocking "JWT Bearer" source authentication failure for "a valid credential of a method the inbound identity does not read"

  Scenario: An MCP surface identifying callers by their API key refuses a token caller with no challenge
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface derives the inbound identity from the API key the caller presents
    When the caller asks the MCP surface for available tools with a valid token
    Then the response status is 401
    And the response carries no "www-authenticate" header
    And MCP server "bravo" was not called
    And the MCP response says only that the caller credential is missing or invalid
    And the MCP response id matches the request id

  Scenario: A public Access Point whose methods identify their callers refuses a caller with no credential
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface's "API Key" source authentication identifies its callers by their API key
    And the surface accepts JWT audience "bdd-test-audience"
    And the operator has created the surface for route "/example" as a public Access Point
    When the caller sends a request to the surface without an API key
    Then the response status is 401
    And managed agent "bravo" was not called
    And the response says only that the caller credential is missing or invalid

  Scenario: A method identity that cannot read the method's credential is refused at save
    Given an A2A surface targeting managed agent "bravo"
    And the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface's "JWT Bearer" source authentication identifies its callers by their API key
    And the surface accepts JWT audience "bdd-test-audience"
    When the operator tries to create the surface for route "/example"
    Then the admin API response status is 400
    And the admin API error response mentions "can only set from_jwt_claim with a non-empty claim as its identity"
