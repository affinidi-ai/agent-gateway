Feature: A Transit Point's listen_path is held to the routes the gateway serves
  A Transit Point answers at the route the gateway derives, under its surface's
  outbound prefix, and at its own listen_path as well. A listen_path is set
  under one of the gateway's configured surface prefixes, with or without the
  outbound prefix in front, which is what the Surface Builder's Listen Path
  picker offers; the admin API refuses the save that introduces anything else,
  so it stores no Transit Point the dashboard could not have made. It also
  refuses one the outbound listener cannot register, which would panic the
  listener build once the surface is stored, and one on the outbound prefix
  itself, which answers every outbound request no more specific route matches.
  A listen_path outside the outbound prefix is served on the outbound
  listener's own address alone, so where an inbound listener shares that
  hostname, as it does here, the save that introduces one is refused as well;
  a deployment whose outbound listener has a hostname of its own keeps it,
  with a Warning on a path already stored.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"

  Scenario: A listen_path under the surface prefix is saved
    When the operator sets Transit Point "alpha" listen_path to "/outbound/example/partner-alpha"
    Then the admin API response status is 200

  Scenario: A listen_path outside the outbound prefix is refused while an inbound listener shares the outbound hostname
    When the operator sets Transit Point "alpha" listen_path to "/transit/partner-alpha"
    Then the admin API response status is 400
    And the admin API error response mentions "listen_path '/transit/partner-alpha', outside '/outbound'"

  Scenario: The refusal names the route the gateway derives instead
    When the operator sets Transit Point "alpha" listen_path to "/transit/partner-alpha"
    Then the admin API response status is 400
    And the admin API error response mentions "/outbound/example/alpha"

  Scenario: A listen_path under no configured surface prefix is refused
    When the operator sets Transit Point "alpha" listen_path to "/partner-a-webhook"
    Then the admin API response status is 400
    And the admin API error response mentions "under no surface prefix this gateway serves Transit Points on"

  Scenario: A listen_path under an unconfigured prefix beneath the outbound prefix is refused
    When the operator sets Transit Point "alpha" listen_path to "/outbound/other/alpha"
    Then the admin API response status is 400
    And the admin API error response mentions "under no surface prefix this gateway serves Transit Points on"

  Scenario: A listen_path on the outbound prefix itself is refused
    When the operator sets Transit Point "alpha" listen_path to "/outbound"
    Then the admin API response status is 400
    And the admin API error response mentions "is the gateway's own outbound prefix"

  Scenario: A listen_path the outbound listener cannot register is refused
    When the operator sets Transit Point "alpha" listen_path to "partner-a"
    Then the admin API response status is 400
    And the admin API error response mentions "must start with '/'"

  Scenario: A listen_path with a legacy parameter segment is refused
    When the operator sets Transit Point "alpha" listen_path to "/outbound/example/:partner"
    Then the admin API response status is 400
    And the admin API error response mentions "must not contain a segment starting with ':' or '*'"

  Scenario: A listen_path with a legacy wildcard segment is refused
    When the operator sets Transit Point "alpha" listen_path to "/outbound/example/*partner"
    Then the admin API response status is 400
    And the admin API error response mentions "must not contain a segment starting with ':' or '*'"

  Scenario: A listen_path whose only segment is trailing slashes is refused
    When the operator sets Transit Point "alpha" listen_path to "/outbound/example//"
    Then the admin API response status is 400
    And the admin API error response mentions "under no surface prefix this gateway serves Transit Points on"

  Scenario: A listen_path that is another Transit Point's route is refused
    Given Transit Point "charlie" routes to MCP server "delta"
    When the operator sets Transit Point "alpha" listen_path to "/outbound/example/charlie"
    Then the admin API response status is 400
    And the admin API error response mentions "Transit Point 'charlie'"

  Scenario: The surface routing settings name the prefixes a Transit Point may listen under
    When the operator reads the surface routing settings
    Then the admin API response status is 200
    And the surface routing settings offer "/outbound/example" as a Transit Point listen path prefix
