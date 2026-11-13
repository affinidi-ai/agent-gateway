Feature: Audit events added to stored selections
  A gateway starting as Active adds a new audit event once to a stored
  selection, the VP Audit Log's or an integration event set, that holds the
  event it extends, so an operator who records granted consents also records
  refused ones. An event added once and removed afterwards stays removed.

  Scenario: A stored selection holding consent_granted gets delegation_failed
    Given the VP Audit Log's stored selection holds only audit event "consent_granted"
    When the gateway starts
    Then the VP Audit Log selection includes audit event "delegation_failed"

  Scenario: A stored selection without consent_granted is left alone
    Given the VP Audit Log's stored selection holds only audit event "policy_decision"
    When the gateway starts
    Then the VP Audit Log selection does not include audit event "delegation_failed"

  Scenario: An event added once and removed afterwards stays removed
    Given the VP Audit Log's stored selection holds only audit event "consent_granted"
    And audit event "delegation_failed" was already added to the stored audit selections once
    When the gateway starts
    Then the VP Audit Log selection does not include audit event "delegation_failed"

  Scenario: A stored integration event set holding consent_granted gets delegation_failed
    Given a stored integration event set holds only audit event "consent_granted"
    When the gateway starts
    Then the stored integration event set includes audit event "delegation_failed"

  Scenario: A stored integration event set without consent_granted is left alone
    Given a stored integration event set holds only audit event "policy_decision"
    When the gateway starts
    Then the stored integration event set does not include audit event "delegation_failed"
