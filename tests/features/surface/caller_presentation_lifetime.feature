Feature: Caller presentation lifetime
  A caller's presentation counts only while its proof is fresh: the proof may expire at most
  5 minutes after the gateway checks it, plus 2 minutes of clock skew, and a proof without an
  expiry may not be created more than 2 minutes ahead of the gateway's clock. A presentation
  that breaks this is rejected like a bad signature, so the request carries no caller identity.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the surface has a request policy that requires a verified caller identity
    And the caller's DID document lists its key for assertions and authentication

  Scenario: A presentation that expires within the 5 minute lifetime gives a verified caller identity
    When the caller sends a request with a presentation of a credential it issued itself that expires in 5 minutes
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A presentation that expires further ahead than the lifetime allows gives no caller identity
    When the caller sends a request with a presentation of a credential it issued itself that expires in 30 minutes
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: A presentation without an expiry created ahead of the gateway's clock gives no caller identity
    When the caller sends a request with a presentation of a credential it issued itself, created 10 minutes ahead and without an expiry
    Then the response status is 403
    And managed agent "bravo" was not called
