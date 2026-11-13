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

  Scenario Outline: A Trust Check whose authorities are not one authority or one valid list is refused
    When the operator creates the surface for route "/orders" with <trust_check>
    Then the admin API response status is 400
    And the admin API error response mentions "<error>"

    Examples:
      | trust_check | error |
      | a caller-leg Trust Check against DID "did:web:authority-a" that also lists authorities "did:web:authority-b" | query.authority_id and query.authority_ids cannot both be set |
      | a caller-leg Trust Check against DID "did:web:authority-a" that takes listed authority "did:web:authority-a" from the Authorities register | authority_sources cannot be set without query.authority_ids |
      | a caller-leg Trust Check listing authorities "did:web:authority-a, did:web:authority-b" that takes its single authority from the Authorities register | authority_source cannot be set when query.authority_ids is set |
      | a caller-leg Trust Check listing authorities "did:web:authority-a, did:web:authority-b" and a timeout of 2 seconds | timeout_secs cannot be set when query.authority_ids is set |
      | a caller-leg Trust Check listing authorities "did:web:authority-a, did:web:authority-a" | query.authority_ids[1] repeats an earlier entry |
      | a caller-leg Trust Check listing authorities "did:web:authority-a, " | query.authority_ids[1] must not be blank |

  Scenario: A Trust Check that lists many authorities is saved
    When the operator creates the surface for route "/orders" with a caller-leg Trust Check listing 26 distinct authorities
    Then the admin API response status is 201

  Scenario: A leg with more than 10 Trust Checks is saved
    When the operator creates the surface for route "/orders" with 11 caller-leg Trust Checks
    Then the admin API response status is 201
