Feature: Trust Checks that list several authorities
  A Trust Check query names one authority in `authority_id` or several in `authority_ids`,
  never both. A list holds at most 25 distinct, non-blank authorities. The gateway asks the
  trust registry once per listed authority, waits a built-in 5 seconds for each, and gives
  policy one result per authority. A Trust Check that lists authorities cannot set its own
  timeout.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"

  Scenario: A Trust Check that lists several authorities is saved with its list
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check listing authorities "did:web:authority-a, did:web:authority-b, did:web:authority-c"
    Then the admin API response status is 201
    And the stored Trust Check "authority-recognised" of the surface under test lists authorities "did:web:authority-a, did:web:authority-b, did:web:authority-c"

  Scenario: A Trust Check that names one authority and also lists authorities is refused
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check against DID "did:web:authority-a" that also lists authorities "did:web:authority-b"
    Then the admin API response status is 400

  Scenario: A Trust Check that lists authorities and sets its own timeout is refused
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check listing authorities "did:web:authority-a, did:web:authority-b" and a timeout of 2 seconds
    Then the admin API response status is 400

  Scenario: A Trust Check that lists the same authority twice is refused
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check listing authorities "did:web:authority-a, did:web:authority-a"
    Then the admin API response status is 400
