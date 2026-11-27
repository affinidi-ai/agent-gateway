Feature: Secrets an API key credential provider uses
  An API key credential provider sends only its API key. A token endpoint and client ID and
  secret that an older gateway stored on one are never read, so the secrets they name are not
  in use: deleting such a secret needs no force, while the provider's API key secret stays in
  use.

  Scenario: A secret named only as a stored API key provider's client secret is deleted
    Given the API key credential provider "vendor-key" is stored with API key secret "vendor-api-key" and client secrets "stale-client-id" and "stale-client-secret"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "stale-client-secret"
    When the operator deletes the secret "stale-client-secret"
    Then the admin API response status is 204
    And no secret "stale-client-secret" is stored

  Scenario: The API key secret of an API key provider is still in use
    Given the API key credential provider "vendor-key" is stored with API key secret "vendor-api-key" and client secrets "stale-client-id" and "stale-client-secret"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "vendor-api-key"
    When the operator deletes the secret "vendor-api-key"
    Then the admin API response status is 409
    And the refusal names credential provider "vendor-key" as a record that uses it
    And the secret "vendor-api-key" is stored
