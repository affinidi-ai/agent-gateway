Feature: The DID the trust agent contexts the gateway creates sign as
  A context the gateway creates in a trust agent (its issuer context, a surface's, an agent's)
  signs as one DID, chosen for the whole deployment. By default it is the did:key of a key the
  context holds. A deployment can choose a did:webvh instead, which the trust agent creates and
  whose key its operator can rotate without changing the DID. The operator can read which one is
  in use from the trust agent status and the key inventory.

  Scenario: The trust agent status says contexts sign as a did:key by default
    When the operator reads the trust agent status
    Then the trust agent status says new contexts sign as "did_key"

  Scenario: The key inventory says contexts sign as a did:key by default
    When the operator reads the key inventory
    Then the key inventory says new contexts sign as "did_key"

  Scenario: The trust agent status says where a chosen did:webvh is hosted
    Given the deployment has trust agent contexts sign as a did:webvh on the trust agent's webvh server
    When the operator reads the trust agent status
    Then the trust agent status says new contexts sign as "did_webvh" hosted on "vta_server"

  Scenario: The key inventory says contexts sign as a chosen did:webvh
    Given the deployment has trust agent contexts sign as a did:webvh on the trust agent's webvh server
    When the operator reads the key inventory
    Then the key inventory says new contexts sign as "did_webvh"
