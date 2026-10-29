Feature: Callers refused by an A2A Access Point that does not declare an authorization server
  An Access Point declares the authorization server of its source
  authentication only when it authenticates callers with JWT Bearer alone,
  publishes that authorization server, requires scopes and keeps the caller's
  token from its Target. One that does not declare leaves a caller whose source
  authentication failed to policy: a refusing policy answers with a 403 and no
  challenge, and with no refusing policy the request is forwarded. The VP Audit
  Log records such a failure as non-blocking. It publishes no protected
  resource metadata.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: A JWT Bearer Access Point that publishes no authorization server refuses with a plain 403
    Given the surface requires "JWT Bearer" source authentication
    And the surface requires scopes "agent.invoke"
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface without a token
    Then the response status is 403
    And the response does not include header "www-authenticate"
    And managed agent "bravo" was not called

  Scenario: A JWT Bearer Access Point that requires no scope refuses with a plain 403
    Given the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface without a token
    Then the response status is 403
    And the response does not include header "www-authenticate"
    And managed agent "bravo" was not called

  Scenario: A JWT Bearer Access Point that forwards the caller's token refuses with a plain 403
    Given the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    And the surface forwards the caller's token to its Target
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface without a token
    Then the response status is 403
    And the response does not include header "www-authenticate"
    And managed agent "bravo" was not called

  Scenario: A JWT Bearer Access Point that forwards the caller's token has no metadata
    Given the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    And the surface forwards the caller's token to its Target
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 404

  Scenario: A caller without a token is forwarded when no policy refuses it
    Given the surface requires "JWT Bearer" source authentication
    And the surface requires scopes "agent.invoke"
    When the caller sends a request to the surface without a token
    Then the response status is 200
    And the response does not include header "www-authenticate"
    And managed agent "bravo" received the forwarded request

  Scenario: A caller forwarded without a token is recorded as a non-blocking failure
    Given the surface requires "JWT Bearer" source authentication
    And the surface requires scopes "agent.invoke"
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface without a token
    Then the response status is 200
    And the VP Audit Log records a non-blocking "JWT Bearer" source authentication failure for "a missing credential"

  Scenario Outline: An Access Point that authenticates callers with an API key refuses with a plain 403
    Given the surface requires "<auth type>" source authentication
    And the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface <credential condition>
    Then the response status is 403
    And the response does not include header "www-authenticate"
    And managed agent "bravo" was not called

    Examples:
      | auth type        | credential condition    |
      | API Key          | without an API key      |
      | API Key          | with an invalid API key |
      | API Key Provider | without an API key      |
