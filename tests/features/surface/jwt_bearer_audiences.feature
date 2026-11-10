Feature: JWT Bearer audiences
  An Access Point JWT Bearer method names the audiences it accepts, so a token
  its identity provider issued for another service is refused. A method stored
  without audiences, from before that rule, keeps accepting such tokens, and
  every save of its surface warns; a save may keep the method but not change
  it. For an identity provider whose tokens carry no audience, the method
  checks the client a token was issued to instead.

  Scenario: A new JWT Bearer method that names no audience is refused
    Given a surface draft for route "/example" whose Access Point checks JWT Bearer tokens naming no audience
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "must name the audiences it accepts"

  Scenario: A token for the audience the method names is accepted
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "api://alpha"
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface with a token for audience "api://alpha"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A token issued for another service is refused when the method names an audience
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "api://alpha"
    When the caller sends a request to the surface with a token for audience "api://other"
    Then the response status is 401
    And managed agent "bravo" was not called

  Scenario: A method stored without audiences still accepts a token issued for another service
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface with a token for audience "api://other"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A save that keeps a method stored without audiences warns about it
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the operator saves the surface with the description "edited"
    Then the admin API response status is 200
    And the admin API response carries a Warning header containing "names no audience"

  Scenario: A new variant keeps the method stored without audiences that it inherits
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the operator saves the surface with a new variant "beta"
    Then the admin API response status is 200
    And the admin API response carries a Warning header containing "names no audience"

  Scenario: A variant saved disabled cannot be enabled with a method that names no audience
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "api://alpha"
    And the operator has saved the surface with a disabled variant "beta" whose JWT Bearer method names no audience
    When the operator enables variant "beta"
    Then the admin API response status is 400
    And the admin API error response mentions "must name the audiences it accepts"

  Scenario: A change to a method stored without audiences is refused unless it names one
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the operator saves the surface reading the caller's JWT Bearer token from header "X-Token"
    Then the admin API response status is 400
    And the admin API error response mentions "must name the audiences it accepts"

  Scenario: A method that checks the client is refused beside a binding that releases callers' own credentials
    Given the appliance holds the secret "provider-id-secret"
    And the appliance holds the secret "provider-password-secret"
    And the operator has created the credential provider "bound" using secrets "provider-id-secret" and "provider-password-secret"
    And a surface draft for route "/example" whose Access Point checks JWT Bearer tokens issued to client "app-alpha"
    And the draft injects a delegated credential from credential provider "bound" as header "X-Bound-Token"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "cannot authenticate the callers of a binding that releases their own delegated credentials"

  Scenario: A method that checks the client accepts a token issued to a listed client
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT Bearer tokens issued to client "app-alpha"
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface with a token issued to client "app-alpha"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A method that checks the client refuses a token issued to another client
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT Bearer tokens issued to client "app-alpha"
    When the caller sends a request to the surface with a token issued to client "app-bravo"
    Then the response status is 401
    And managed agent "bravo" was not called
