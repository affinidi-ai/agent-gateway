Feature: Surface routes callers can reach
  The admin API refuses to save an active surface on a route callers could not
  reach: a route no surface prefix serves, a route a gateway.json route serves,
  a route that is not a plain path, or a route another surface already uses
  once a trailing slash is ignored. A reload refuses a gateway.json in which two
  entries serve the same path, and the gateway keeps routing as before.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target

  Scenario: A surface on a route under a surface prefix is saved
    When the operator creates a valid surface for route "/example/orders"
    Then the admin API response status is 201
    And the admin API response includes a surface id

  Scenario: A surface saved on a route with a trailing slash serves callers on the route without it
    Given A2A surface "alpha" exists for route "/example/orders/" with managed agent "bravo" as its target
    When the caller sends a request to the surface path "/example/orders/foo"
    Then the response status is 200
    And managed agent "bravo" received the forwarded path "/foo"
    And the admin API response stores route "/example/orders"

  Scenario: A surface on a path a redirect added by a reload serves is refused
    Given the operator has added a redirect from "/example/docs" to "https://docs.example" and reloaded the configuration
    When the operator creates a valid surface for route "/example/docs"
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.route '/example/docs' is served by route"
    And the admin API error response mentions "(redirect)"

  Scenario: A reload that puts a redirect on a surface prefix is refused and routing is kept
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the operator has added a redirect from "/example" to "https://docs.example" and reloaded the configuration
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And managed agent "bravo" received the forwarded path "/foo"
    And the admin API response status is 500
    And the admin API error response mentions "use the same path prefix"

  Scenario: A surface on a route no surface prefix serves is refused
    When the operator creates a valid surface for route "/orders"
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.route '/orders' is not served by any surface prefix"
    And the admin API error response mentions "Choose a route under one of: /example"
    And the admin API response does not include a surface id

  Scenario: A surface on a route a gateway.json route serves is refused
    When the operator creates a valid surface for route "/api/orders"
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.route '/api/orders' is served by route 'api' (identity_api)"
    And the admin API response does not include a surface id

  Scenario Outline: A surface on a route that is not a plain path is refused
    When the operator creates a valid surface for route "<route>"
    Then the admin API response status is 400
    And the admin API error response mentions "must be a plain path"
    And the admin API response does not include a surface id

    Examples:
      | route                  |
      | /example$alternate     |
      | /example%24alternate   |
      | /example//orders       |
      | /example/../api/orders |

  Scenario: A surface on another surface's route with a trailing slash is refused
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    When the operator creates a valid surface for route "/example/"
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.route '/example'"
    And the admin API error response mentions "is already in use by surface 'alpha'"

  Scenario: Moving a surface to a route no surface prefix serves is refused
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    When the operator moves the surface to route "/orders"
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.route '/orders' is not served by any surface prefix"
