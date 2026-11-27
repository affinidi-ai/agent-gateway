Feature: Trust agent changes and refusals leave a security record
  A refused change to a trust agent connection and an operator's revoke of one are each
  recorded in the VP Audit Log with who attempted it. Each record is a link of the security
  record chain: it carries its place in the chain, the hash of the record before it and its
  own hash.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the VP Audit Log keeps every audit event
    And the appliance holds the trust agent connection "shared-agent"

  Scenario: A tenant token refused a revoke of an appliance-wide connection is recorded
    When a token of tenant "tenant-a" revokes the trust agent connection "shared-agent"
    Then the admin API response status is 403
    And the VP Audit Log records that a tenant token was refused revoking the trust agent connection "shared-agent"

  Scenario: An operator's revoke of a connection is recorded with the operator
    When the operator revokes the trust agent connection "shared-agent"
    Then the admin API response status is 200
    And the VP Audit Log records that the operator revoked the trust agent connection "shared-agent"

  Scenario: A revoke after a refused revoke follows it in the security record chain
    Given a token of tenant "tenant-a" has been refused revoking the trust agent connection "shared-agent"
    When the operator revokes the trust agent connection "shared-agent"
    Then the operator's revoke record follows the refusal record in the security record chain
