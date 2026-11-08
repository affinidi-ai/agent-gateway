Feature: Forced secret deletes are audited
  Deleting a secret with force while a surface still uses it is recorded in the VP Audit Log
  with the operator as its actor, naming the secret and the records that used it, never a value.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target
    And the appliance holds the secret "first-key"
    And the VP Audit Log keeps every audit event
    And the operator has created the appliance-wide surface for route "/audited" authenticating its target with secret "first-key"

  Scenario: Force-deleting a secret a surface uses is recorded with the operator
    When the operator deletes the secret "first-key" with force
    Then the admin API response status is 204
    And the VP Audit Log records that the operator force-deleted the secret "first-key" the surface still used
    And no VP Audit Log record carries a secret value
