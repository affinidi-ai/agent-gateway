Feature: Delegated credential scope on the direct path
  The gateway sends a delegated credential only to URLs under the Target endpoint, as it
  does the Target credential. A request whose path climbs out of the Target base path,
  written plainly, percent-encoded or as an ambiguous segment, is refused before the
  delegated credential is fetched and before anything reaches the Target, and the refusal
  is recorded in the VP Audit Log.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface's Target endpoint has the base path "/base"
    And the surface requires delegated credentials from a client credentials provider

  Scenario: A request under the Target base path carries the delegated credential
    Given the surface requires "JWT Bearer" source authentication
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario Outline: A request whose path leaves the Target base path is refused before the delegated credential is fetched
    Given the VP Audit Log keeps every audit event
    When the caller sends a request to the surface path "<path>" exactly as written
    Then the response status is 400
    And the response mentions "Target authentication failed"
    And the response reason is "target_path_refused"
    And managed agent "bravo" was not called
    And the credential provider received 0 token requests
    And the VP Audit Log records a request refusal for "a path outside the Target base path"

    Examples:
      | path                |
      | /smoke/../admin     |
      | /smoke/%2e%2e/admin |
      | /smoke/..;/admin    |
      | /smoke/..%2Fadmin   |
