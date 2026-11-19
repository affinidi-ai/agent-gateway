Feature: Caller presentation proof purpose
  A caller's presentation counts only when each proof key is listed in its signer's DID
  document under the purpose the proof declares: assertionMethod for a credential, and
  assertionMethod or authentication for the presentation. A presentation that breaks this
  is rejected like a bad signature, so the request carries no caller identity. When the key
  is missing from a DID document the gateway had cached, it fetches the document again, so a
  signer that has since listed the key is accepted.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the surface has a request policy that requires a verified caller identity

  Scenario: A credential signed with a key listed only for authentication gives no caller identity
    Given the caller's DID document lists its key for authentication only
    When the caller sends a request with a presentation of a credential it issued itself
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: A caller that has since listed its key for assertions is accepted despite its cached DID document
    Given the caller's DID document lists its key for authentication only
    And the gateway has accepted a presentation from the caller of a credential from another issuer
    And the caller has since listed its key for assertions in its DID document
    When the caller sends a request with a presentation of a credential it issued itself
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
