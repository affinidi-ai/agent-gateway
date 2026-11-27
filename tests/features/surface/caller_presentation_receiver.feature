Feature: Caller presentation receiver
  A caller's presentation names the gateway it is meant for in its proof's domain: an origin
  the Access Point is published under. A presentation that names another receiver, names none,
  or names a label the gateway reserves for its own answers is refused, and the Target is never
  called, so a copy of a presentation cannot be used at another gateway.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the caller's DID document lists its key for assertions

  Scenario: A presentation that names the Access Point origin is accepted
    When the caller sends a request with a presentation of a credential it issued itself
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A presentation that names another gateway is refused
    When the caller sends a request with a presentation that names another gateway
    Then the response status is 422
    And managed agent "bravo" was not called

  Scenario: A presentation that names no receiver is refused
    When the caller sends a request with a presentation that names no receiver
    Then the response status is 422
    And managed agent "bravo" was not called

  Scenario: A presentation that names a reserved label is refused
    When the caller sends a request with a presentation that names a label the gateway reserves for its answers
    Then the response status is 422
    And managed agent "bravo" was not called
