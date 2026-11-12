Feature: Authorities that Trust Checks and Trust Recorder entries use
  A Trust Check or Trust Recorder entry whose authority DID is an Authority's is linked to that
  Authority. The admin API refuses to delete an Authority while anything names it, answering 409
  with the surfaces and managed connections the operator may view and the Trust Checks and Trust
  Recorder entries in them that name it, and counting the rest. Deleting it with force, which
  needs a view of every record naming it, removes the Authority but keeps the surfaces as they
  are; they cannot be saved again until they name another Authority.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the operator has created the Authority "Acme" with DID "did:web:acme.example"

  Scenario: A saved Trust Check records that its authority is an Authority
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check "acme-check" against DID "did:web:acme.example"
    Then the admin API response status is 201
    And the stored Trust Check "acme-check" of the surface under test takes its authority from the Authorities register

  Scenario: A saved Trust Check against a DID in no register is not linked to an Authority
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check "typed-check" against DID "did:web:typed.example"
    Then the admin API response status is 201
    And the stored Trust Check "typed-check" of the surface under test is not linked to any register

  Scenario: Deleting an Authority that a Trust Check uses is refused naming the surface and the check
    Given the operator has created the surface for route "/orders" with a caller-leg Trust Check "acme-check" against DID "did:web:acme.example"
    When the operator deletes the Authority "Acme"
    Then the admin API response status is 409
    And the admin API error response mentions "The Authority is used by Trust Checks or Trust Recorder entries"
    And the refusal names the surface under test as a record that uses it
    And the refusal names 1 referencing record
    And the refusal hides 0 referencing records
    And the refusal says Trust Check "acme-check" of the surface under test uses the Authority
    And the Authority "Acme" is stored

  Scenario: Deleting an Authority that a Trust Recorder entry uses is refused naming the entry
    Given the operator has created the surface for route "/orders" whose Trust Recorder takes DID "did:web:acme.example" as its authority
    When the operator deletes the Authority "Acme"
    Then the admin API response status is 409
    And the refusal names the surface under test as a record that uses it
    And the refusal says a Trust Recorder entry of the surface under test uses the Authority
    And the Authority "Acme" is stored

  Scenario: Deleting an Authority that a managed connection's Trust Check uses is refused naming the connection
    Given the operator has created the managed connection "cli" with a Trust Check against DID "did:web:acme.example"
    When the operator deletes the Authority "Acme"
    Then the admin API response status is 409
    And the refusal names the managed connection "cli" as a record that uses it
    And the Authority "Acme" is stored

  Scenario: An access token that cannot view surfaces only counts them
    Given the operator has created the surface for route "/orders" with a caller-leg Trust Check "acme-check" against DID "did:web:acme.example"
    When an access token that may delete Authorities but not view surfaces deletes the Authority "Acme"
    Then the admin API response status is 409
    And the refusal names 0 referencing records
    And the refusal hides 1 referencing record
    And the Authority "Acme" is stored

  Scenario: An access token that cannot view a record using the Authority cannot delete it with force
    Given the operator has created the surface for route "/orders" with a caller-leg Trust Check "acme-check" against DID "did:web:acme.example"
    When an access token that may delete Authorities but not view surfaces deletes the Authority "Acme" with force
    Then the admin API response status is 409
    And the admin API error response mentions "entries you cannot view, so it cannot be deleted with force"
    And the Authority "Acme" is stored

  Scenario: An Authority in use is deleted with force and the surface keeps its Trust Check
    Given the operator has created the surface for route "/orders" with a caller-leg Trust Check "acme-check" against DID "did:web:acme.example"
    And the VP Audit Log keeps every audit event
    When the operator deletes the Authority "Acme" with force
    Then the admin API response status is 204
    And no Authority "Acme" is stored
    And the stored Trust Check "acme-check" of the surface under test takes its authority from the Authorities register
    And the VP Audit Log records that the operator force-deleted the Authority with DID "did:web:acme.example" the surface still used

  Scenario: A surface whose Authority was deleted with force is not saved until it names another
    Given the operator has created the surface for route "/orders" with a caller-leg Trust Check "acme-check" against DID "did:web:acme.example"
    And the operator has deleted the Authority "Acme" with force
    When the operator renames the surface under test
    Then the admin API response status is 400
    And the admin API error response mentions "Trust Check 'acme-check' uses Authority did:web:acme.example, which does not exist"

  Scenario: An Authority that nothing uses is deleted
    When the operator deletes the Authority "Acme"
    Then the admin API response status is 204
    And no Authority "Acme" is stored
