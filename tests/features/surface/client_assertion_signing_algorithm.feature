Feature: Client assertion signing algorithm
  A client credentials provider whose client authenticates with a signed JWT signs its client
  assertion with PS256, RS256 or ES256. The admin API stores a provider that signs with ES256
  when its signing key is an EC key, and refuses one whose key cannot sign with ES256.

  Scenario: A client credentials JWT provider that signs with ES256 and an EC key is stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the EC signing key "bdd-ec-signing-key"
    And the appliance holds the secret "bdd-client-id"
    When the operator creates the client credentials JWT provider "ec-signer" signing with "ES256" using the secret "bdd-ec-signing-key" and the client ID secret "bdd-client-id"
    Then the admin API response status is 201
    And the credential provider "ec-signer" is stored

  Scenario: A client credentials JWT provider that signs with ES256 and an RSA key is refused and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    And the appliance holds the secret "bdd-client-id"
    When the operator creates the client credentials JWT provider "rsa-signer" signing with "ES256" using the secret "bdd-signing-key" and the client ID secret "bdd-client-id"
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_signing_key_secret_ref must reference"
    And no credential provider "rsa-signer" is stored
