Feature: Gateway DID document
  The gateway signs the credentials and presentations it issues with its signing
  key, so its published DID document lists that key under assertionMethod for
  verifiers to accept them.

  Scenario: The gateway DID document authorizes the gateway signing key for assertions
    When the caller fetches the gateway DID document
    Then the response status is 200
    And the DID document lists the gateway signing key under assertionMethod

  Scenario: A new gateway publishes its DID log with the signing key under assertionMethod
    When the caller fetches the gateway DID log
    Then the response status is 200
    And the gateway DID log has 1 version
    And the latest version of the gateway DID log lists the gateway signing key under assertionMethod

  Scenario: A gateway adds the signing key to its published DID document under the same DID
    Given the gateway published its DID document without its signing key under assertionMethod
    When the caller fetches the gateway DID log
    Then the response status is 200
    And the gateway DID log has 2 versions
    And every version of the gateway DID log describes the same did:webvh DID
    And the first version of the gateway DID log does not list the gateway signing key under assertionMethod
    And the latest version of the gateway DID log lists the gateway signing key under assertionMethod
    And the gateway DID log verifies as a did:webvh log
