Feature: Audit log access and evidence
  The gateway protects audit evidence with administrator-only access while
  preserving unredacted identity evidence. Live credential secrets are never
  written to audit logs.

  Scenario: Application log readers cannot read the VP Audit Log
    Given operator "uma" has the "user" role
    When operator "uma" reads the VP Audit Log
    Then the audit read response status is 403

  Scenario: Application log readers cannot read the Credential Delegation Audit Log
    Given operator "uma" has the "user" role
    When operator "uma" reads the Credential Delegation Audit Log
    Then the audit read response status is 403

  Scenario: Administrators can read the VP Audit Log
    Given the VP Audit Log contains a policy decision
    And operator "ada" has the "administrator" role
    When administrator "ada" reads the VP Audit Log
    Then the audit read response status is 200
    And the VP Audit Log includes a policy decision

  Scenario: Administrators can read full Credential Delegation Audit Log evidence
    Given the Credential Delegation Audit Log contains a token injection for caller "alice" with email "alice@example.com" and name "Alice Example"
    And operator "ada" has the "administrator" role
    When administrator "ada" reads the Credential Delegation Audit Log
    Then the audit read response status is 200
    And the Credential Delegation Audit Log includes caller email "alice@example.com"
    And the Credential Delegation Audit Log includes caller name "Alice Example"
    And the Credential Delegation Audit Log does not include OAuth access tokens
    And the Credential Delegation Audit Log does not include OAuth refresh tokens

  Scenario: Credential Delegation Audit Log never stores API-key and target-auth secrets
    Given an API-key delegated credential was injected for caller "alice"
    And operator "ada" has the "administrator" role
    When administrator "ada" reads the Credential Delegation Audit Log
    Then the audit read response status is 200
    And the Credential Delegation Audit Log includes a token injection
    And the Credential Delegation Audit Log has no stored API-key secret values
    And the Credential Delegation Audit Log has no stored target-auth secret values

  Scenario: Permission responses distinguish application logs from audit evidence
    Given operator "uma" has the "user" role
    When operator "uma" asks for their permissions
    Then permission "logs.view" is granted
    And permission "audit.view" is denied
