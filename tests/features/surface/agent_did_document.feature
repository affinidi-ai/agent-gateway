Feature: Agent DID document
  An agent signs the presentations it sends with its signing key, so its published
  DID document lists that key under assertionMethod and authentication. An agent DID
  published before that is repaired when the gateway starts, under the same DID.

  Scenario: An agent DID gets its signing key listed under authentication
    Given an agent DID published with its signing key under assertionMethod only
    When the caller fetches the agent DID log
    Then within ten seconds the agent DID log has 2 versions
    And every version of the agent DID log describes the same agent DID
    And the first version of the agent DID log does not list the agent signing key under authentication
    And the latest version of the agent DID log lists the agent signing key under assertionMethod and authentication
    And the agent DID log verifies as a did:webvh log

  Scenario: An agent DID that never published its signing key gets it published and listed
    Given an agent DID published without its signing key
    When the caller fetches the agent DID log
    Then within ten seconds the agent DID log has 2 versions
    And every version of the agent DID log describes the same agent DID
    And the first version of the agent DID log does not publish the agent signing key
    And the latest version of the agent DID log lists the agent signing key under assertionMethod and authentication
    And the agent DID log verifies as a did:webvh log
