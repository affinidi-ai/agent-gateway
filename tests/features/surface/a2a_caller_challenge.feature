Feature: Caller challenge and required scopes on an A2A Access Point
  An Access Point that authenticates callers with JWT Bearer, publishes the
  authorization server of its source authentication and requires scopes
  declares that authorization server. It refuses a caller whose source
  authentication failed itself, before reading the request and before rate
  limiting, any policy, payment or the managed agent, with a challenge that
  names its protected resource metadata: 401 for a missing or invalid token and
  403 for a token that lacks a required scope. The challenge is a problem report
  that is not cached, and a token is accepted when the Access Point URL is one
  of its audiences. A surface needs no policy for this refusal, and the VP
  Audit Log records it as a blocking source authentication failure. A caller
  whose token grants every required scope is forwarded without its token.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke agent.read"

  Scenario: A caller that presents no token is challenged to authorize
    When the caller sends a request to the surface without a token
    Then the response status is 401
    And the response challenges the caller to authorize for scopes "agent.invoke agent.read"
    And managed agent "bravo" was not called

  Scenario Outline: A caller that presents an invalid token is challenged with invalid_token
    When the caller sends a request to the surface <token condition>
    Then the response status is 401
    And the response challenges the caller with error "invalid_token" for scopes "agent.invoke agent.read"
    And managed agent "bravo" was not called

    Examples:
      | token condition                                                                          |
      | with an expired token                                                                    |
      | with a malformed token                                                                   |
      | with a tampered token                                                                    |
      | with a token issued for another resource                                                 |
      | with an identity token issued for the surface granting scopes "agent.invoke agent.read" |

  Scenario Outline: A token that lacks a required scope is challenged with insufficient_scope
    When the caller sends a request to the surface with a token issued for the surface granting scopes "<granted>" in its "<claim>" claim
    Then the response status is 403
    And the response challenges the caller with error "insufficient_scope" for scopes "agent.invoke agent.read"
    And managed agent "bravo" was not called

    Examples:
      | granted      | claim |
      | agent.invoke | scope |
      |              | scope |
      | agent.read   | scp   |

  Scenario Outline: A token that grants every required scope is forwarded without the caller's token
    When the caller sends a request to the surface with a token issued for the surface granting scopes "<granted>" in its "<claim>" claim
    Then the response status is 200
    And the response does not include header "www-authenticate"
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive header "authorization"

    Examples:
      | granted                             | claim |
      | agent.read agent.invoke             | scope |
      | agent.invoke agent.read agent.admin | scope |
      | agent.invoke agent.read             | scp   |

  Scenario: A policy admitting every caller does not admit a caller whose token lacks a required scope
    Given the surface has a policy admitting every caller
    When the caller sends a request to the surface with a token issued for the surface granting scopes "agent.invoke" in its "scope" claim
    Then the response status is 403
    And the response challenges the caller with error "insufficient_scope" for scopes "agent.invoke agent.read"
    And managed agent "bravo" was not called

  Scenario: A policy refusing callers whose source authentication failed leaves the same challenge
    Given the surface has a policy denying callers whose source authentication failed
    When the caller sends a request to the surface without a token
    Then the response status is 401
    And the response challenges the caller to authorize for scopes "agent.invoke agent.read"
    And managed agent "bravo" was not called

  Scenario: A token that names the surface resource among other audiences is accepted
    When the caller sends a request to the surface with a token whose audiences are the surface resource and "https://as.example/userinfo" granting scopes "agent.invoke agent.read"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A caller without a token is challenged before a gateway policy that denies every request
    Given the gateway has a gateway-level policy that denies every request
    When the caller sends a request to the surface without a token
    Then the response status is 401
    And the response challenges the caller to authorize for scopes "agent.invoke agent.read"
    And managed agent "bravo" was not called

  Scenario: A caller with a valid token is then refused by that gateway policy
    Given the gateway has a gateway-level policy that denies every request
    When the caller sends a request to the surface with a token issued for the surface granting scopes "agent.invoke agent.read" in its "scope" claim
    Then the response status is 403
    And the response does not include header "www-authenticate"
    And managed agent "bravo" was not called

  Scenario: A caller without a token is challenged before its request body is read
    When the caller sends a request to the surface without a token and with a body that is not JSON
    Then the response status is 401
    And the response challenges the caller to authorize for scopes "agent.invoke agent.read"
    And managed agent "bravo" was not called

  Scenario: Callers without a token are challenged rather than rate limited
    Given the surface admits 1 request per minute
    When 2 callers send requests to the surface sequentially
    Then the response status is 401
    And the response challenges the caller to authorize for scopes "agent.invoke agent.read"
    And managed agent "bravo" was not called

  Scenario: No policy sees a caller whose source authentication failed
    Given the surface has a policy admitting every caller
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface without a token
    Then the response status is 401
    And the VP Audit Log records no policy decision

  Scenario: A challenged caller receives a problem report that is not cached
    When the caller sends a request to the surface without a token
    Then the response status is 401
    And the response includes header "cache-control" with value "no-store"
    And the response includes header "content-type" with value "application/problem+json"

  Scenario Outline: A refused caller is recorded as a blocking source authentication failure
    Given the VP Audit Log keeps every audit event
    When the caller sends a request to the surface <request>
    Then the response status is <status>
    And the VP Audit Log records a blocking "JWT Bearer" source authentication failure for "<failure>"

    Examples:
      | request                                                                                 | status | failure              |
      | without a token                                                                         | 401    | a missing credential |
      | with a token issued for the surface granting scopes "agent.invoke" in its "scope" claim | 403    | a scope shortfall    |
