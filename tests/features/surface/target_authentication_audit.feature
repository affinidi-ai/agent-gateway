Feature: Target authentication changes are audited
  Each management change to the credential a surface sends to its Target or a Transit Point
  is recorded in the VP Audit Log with the operator as its actor. The record names the method
  and credential provider before and after, never a secret id, header or value.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target
    And the appliance holds the secret "first-key"
    And the appliance holds the secret "second-key"
    And the VP Audit Log keeps every audit event
    And the operator has created the appliance-wide surface for route "/audited" authenticating its target with secret "first-key"

  Scenario: Replacing the secret a Target authenticates with is recorded with the operator
    When the operator saves the surface authenticating its target with secret "second-key"
    Then the admin API response status is 200
    And the VP Audit Log records that the operator replaced the secret the surface's Target authenticates with
    And no VP Audit Log record names the secret "first-key"
    And no VP Audit Log record names the secret "second-key"
