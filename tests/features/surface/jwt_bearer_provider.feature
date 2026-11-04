Feature: JWT Bearer credential providers
  A JWT Bearer credential provider names the subject its grant is issued for. The admin API
  refuses to save one without a subject, every assertion the gateway signs carries that subject
  and an identifier of its own, and a stored provider without a subject is named at startup. The
  gateway writes its startup
  report when it starts, so each report scenario sends one request to be sure it is running.

  Scenario Outline: A JWT Bearer provider without a usable subject is refused and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator creates the JWT Bearer provider "<provider>" using the secret "bdd-signing-key" <subject>
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And no credential provider "<provider>" is stored

    Examples:
      | provider      | subject            |
      | no-subject    | without a subject  |
      | blank-subject | with subject "   " |

  Scenario: A JWT Bearer provider with a subject is stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator creates the JWT Bearer provider "with-subject" using the secret "bdd-signing-key" with subject "svc@example.com"
    Then the admin API response status is 201
    And the credential provider "with-subject" is stored

  Scenario: A JWT Bearer provider validated without a subject is refused before any token request
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator validates a JWT Bearer provider using the secret "bdd-signing-key" without a subject
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"

  Scenario: A JWT Bearer provider validated with a subject is accepted
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator validates a JWT Bearer provider using the secret "bdd-signing-key" with subject "svc@example.com"
    Then the admin API response status is 200

  Scenario: A change to a stored JWT Bearer provider without a subject is refused
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    When the operator changes the credential provider's scope to "bdd-new-scope"
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And the credential provider stores no subject

  Scenario: A change to a stored JWT Bearer provider that names a subject is accepted
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    When the operator changes the credential provider's scope to "bdd-new-scope" and names the subject "svc@example.com"
    Then the admin API response status is 200
    And the credential provider stores the subject "svc@example.com"

  Scenario: Rotating the signing key of a stored JWT Bearer provider without a subject is refused
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    And the appliance holds the signing key "rotated-key"
    When the operator changes the credential provider's signing key to the secret "rotated-key"
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And the credential provider stores no subject

  Scenario: Rotating the signing key of a stored JWT Bearer provider that names a subject is accepted
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    And the appliance holds the signing key "rotated-key"
    When the operator changes the credential provider's signing key to the secret "rotated-key" and names the subject "svc@example.com"
    Then the admin API response status is 200
    And the credential provider stores the subject "svc@example.com"

  Scenario: Clearing the subject of a stored JWT Bearer provider is refused and the subject is kept
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider stores the JWT subject "svc@example.com"
    When the operator clears the credential provider's subject
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And the credential provider stores the subject "svc@example.com"

  Scenario: A stored JWT Bearer provider without a subject still signs its grant without a subject
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And no JWT Bearer assertion the credential provider received carries a subject

  Scenario: Every assertion carries the subject and a jti of its own
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider stores the JWT subject "svc@example.com"
    And the credential provider issues tokens that expire in 1 seconds
    And the caller has sent a request to the surface and received status 200
    And the caller has waited 2 seconds
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 2 token requests
    And every JWT Bearer assertion the credential provider received has subject "svc@example.com"
    And no two JWT Bearer assertions the credential provider received share a jti

  Scenario: The startup report names a stored JWT Bearer provider without a subject
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 200
    And the startup report names the credential_provider "bdd-target-provider" as breaking the rule "jwt_subject" in warn mode

  Scenario: The startup report stays quiet about a JWT Bearer provider with a subject
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider stores the JWT subject "svc@example.com"
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 200
    And the startup report does not name the credential_provider "bdd-target-provider" as breaking the rule "jwt_subject"

  Scenario: The subject rule only warns while another credential rule is enforced
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    And the gateway enforces the credential rule "token_endpoint_https"
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 200
    And the startup report names the credential_provider "bdd-target-provider" as breaking the rule "jwt_subject" in warn mode
