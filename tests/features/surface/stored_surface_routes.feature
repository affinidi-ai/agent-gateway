Feature: Surfaces stored on routes the admin API now refuses
  A surface stored before the admin API checked routes keeps its route. The
  gateway warns about it at startup, an edit that keeps its route is saved, and
  enabling it is refused while no surface prefix serves its route. Of two stored
  surfaces whose routes differ only by a trailing slash, startup keeps the one
  that received the requests. A surface stored as deleted is never served and
  holds no route, and the admin API refuses to save one.

  Scenario: The gateway warns at startup about a stored surface on a route no surface prefix serves
    Given a surface "legacy" is stored active on route "/legacy"
    When the gateway starts
    Then the gateway log warns about the route of surface "legacy"

  Scenario: An edit that keeps the route of a stored surface no surface prefix serves is saved
    Given a surface "legacy" is stored active on route "/legacy"
    When the operator changes the description of surface "legacy"
    Then the admin API response status is 200

  Scenario: Enabling a stored surface on a route no surface prefix serves is refused
    Given a surface "legacy" is stored disabled on route "/legacy"
    When the operator enables surface "legacy"
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.route '/legacy' is not served by any surface prefix"

  Scenario: Startup keeps the stored surface that received the requests of two on one route
    Given a surface "a-first" is stored active on route "/smoke/dup"
    And a surface "b-second" is stored active on route "/smoke/dup/"
    When the gateway starts
    Then surface "b-second" is active
    And surface "a-first" is disabled

  Scenario: A surface stored as deleted is not served after a restart
    Given a surface "gone" is stored deleted on route "/example"
    And the operator can use the admin API and no surface is configured for route "/example"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 404
    And the response says only that no surface is served at "/example/foo"

  Scenario: A surface stored as deleted does not take a live surface's route at startup
    Given a surface "a-gone" is stored deleted on route "/smoke/dup"
    And a surface "b-live" is stored active on route "/smoke/dup"
    When the gateway starts
    Then surface "b-live" is active

  Scenario: The admin API refuses to save a surface as deleted
    Given a surface "live" is stored active on route "/smoke/live"
    When the operator saves surface "live" with status "deleted"
    Then the admin API response status is 400
    And the admin API error response mentions "status 'deleted' cannot be saved"
