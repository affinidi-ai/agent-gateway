Feature: Trust Checks that list several authorities
  A Trust Check query names one authority in `authority_id` or several in `authority_ids`,
  never both. A list holds distinct, non-blank authorities, with no limit on how many a list or
  the Trust Checks of one leg name. The gateway asks the
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
    And the admin API error response mentions "query.authority_id and query.authority_ids cannot both be set"

  Scenario: A Trust Check that names one authority and sets sources for listed authorities is refused
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check against DID "did:web:authority-a" that takes listed authority "did:web:authority-a" from the Authorities register
    Then the admin API response status is 400
    And the admin API error response mentions "authority_sources cannot be set without query.authority_ids"

  Scenario: A Trust Check that lists authorities and sets its own timeout is refused
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check listing authorities "did:web:authority-a, did:web:authority-b" and a timeout of 2 seconds
    Then the admin API response status is 400
    And the admin API error response mentions "timeout_secs cannot be set when query.authority_ids is set"

  Scenario: A Trust Check that lists the same authority twice is refused
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check listing authorities "did:web:authority-a, did:web:authority-a"
    Then the admin API response status is 400
    And the admin API error response mentions "query.authority_ids[1] repeats an earlier entry"

  Scenario: A Trust Check that lists more than 25 authorities is saved
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check listing 26 distinct authorities
    Then the admin API response status is 201

  Scenario: Trust Checks of one leg that list more than 25 authorities in total are saved
    When the operator creates the surface for route "/orders" with two caller-leg Trust Checks listing 20 and 6 distinct authorities
    Then the admin API response status is 201

  Scenario: A Trust Check that lists a blank authority is refused
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check listing authorities "did:web:authority-a, "
    Then the admin API response status is 400
    And the admin API error response mentions "query.authority_ids[1] must not be blank"
