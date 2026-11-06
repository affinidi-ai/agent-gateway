Feature: Secrets and credential providers that other records use
  The admin API keeps a secret that a surface, a credential provider, an A2A proxy or an STS
  client uses: deleting it is refused with 409, naming the records the operator's access
  token may view and counting the rest, unless the operator deletes it with force. A
  credential provider that a surface uses for Target authentication can neither be deleted
  nor changed to a type that needs a user's consent.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "client-id"
    And the appliance holds the secret "client-secret"
    And the operator has created the credential provider "machine" using secrets "client-id" and "client-secret"
    And the operator has created the surface for route "/orders" authenticating its target with credential provider "machine" and its callers with secret "client-id"

  Scenario: Deleting a secret that a credential provider and a surface use is refused naming both
    When the operator deletes the secret "client-id"
    Then the admin API response status is 409
    And the admin API error response mentions "The secret is in use; remove its references first, or delete it with force=true"
    And the refusal names credential provider "machine" as a record that uses it
    And the refusal names the surface under test as a record that uses it
    And the refusal names 2 referencing records
    And the refusal hides 0 referencing records
    And the secret "client-id" is stored

  Scenario: An access token that cannot view credential providers only counts them
    When an access token that may view secrets and surfaces but not credential providers deletes the secret "client-id"
    Then the admin API response status is 409
    And the refusal names the surface under test as a record that uses it
    And the refusal names 1 referencing record
    And the refusal hides 1 referencing record
    And the secret "client-id" is stored

  Scenario: A secret in use is deleted with force
    When the operator deletes the secret "client-id" with force
    Then the admin API response status is 204
    And no secret "client-id" is stored

  Scenario: A secret that nothing uses is deleted
    Given the appliance holds the secret "unused-key"
    When the operator deletes the secret "unused-key"
    Then the admin API response status is 204
    And no secret "unused-key" is stored

  Scenario: Deleting a credential provider that a surface uses is refused
    When the operator deletes the credential provider "machine"
    Then the admin API response status is 409
    And the admin API error response mentions "provider_in_use"
    And the credential provider "machine" is stored

  Scenario: A credential provider that a surface uses for Target authentication cannot need a user's consent
    When the operator changes the type of credential provider "machine" to "oauth2_authorization_code"
    Then the admin API response status is 409
    And the admin API error response mentions "The credential provider is used for Target authentication, which cannot use a provider that needs a user's consent"
    And the refusal names the surface under test as a record that uses it
    And the refusal hides 0 referencing records

  Scenario: A credential provider that no surface uses for Target authentication can change its type
    Given the operator has created the credential provider "spare" using secrets "client-id" and "client-secret"
    When the operator changes the type of credential provider "spare" to "oauth2_authorization_code"
    Then the admin API response status is 200
