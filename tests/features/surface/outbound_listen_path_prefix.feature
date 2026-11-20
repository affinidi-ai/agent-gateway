Feature: A Transit Point's listen_path is held to the prefixes the gateway serves
  A Transit Point answers at the route the gateway derives, under its outbound
  prefix, and at its own listen_path as well. A listen_path outside that prefix
  answers on the outbound listener alone, so an inbound listener sharing the
  outbound hostname never reaches it. So does a listen_path on the outbound
  prefix itself, which answers every outbound request no more specific route
  matches, and one the outbound listener cannot register at all. The appliance
  says so on the save in a Warning header, and refuses the paths the save
  introduces only while strict_outbound_listen_paths is on: with it off, every
  listen_path saves as it always did.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"

  Scenario: A listen_path under the outbound prefix is saved while the appliance is strict
    Given the appliance serves Transit Points only under its outbound prefixes
    When the operator sets Transit Point "alpha" listen_path to "/outbound/partner/alpha"
    Then the admin API response status is 200

  Scenario: A listen_path outside the outbound prefix is refused while the appliance is strict
    Given the appliance serves Transit Points only under its outbound prefixes
    When the operator sets Transit Point "alpha" listen_path to "/partner-a-webhook"
    Then the admin API response status is 400
    And the admin API error response mentions "outside '/outbound'"

  Scenario: The refusal names the route the gateway derives instead
    Given the appliance serves Transit Points only under its outbound prefixes
    When the operator sets Transit Point "alpha" listen_path to "/partner-a-webhook"
    Then the admin API response status is 400
    And the admin API error response mentions "/outbound/example/alpha"

  Scenario: The listen_path a surface was stored with is saved again while the appliance is strict
    Given the appliance serves Transit Points only under its outbound prefixes
    When the operator sets Transit Point "alpha" listen_path to "/transit/alpha"
    Then the admin API response status is 200

  Scenario: A listen_path on the outbound prefix itself is refused while the appliance is strict
    Given the appliance serves Transit Points only under its outbound prefixes
    When the operator sets Transit Point "alpha" listen_path to "/outbound"
    Then the admin API response status is 400
    And the admin API error response mentions "is the gateway's own outbound prefix"

  Scenario: A listen_path the outbound listener cannot register is refused while the appliance is strict
    Given the appliance serves Transit Points only under its outbound prefixes
    When the operator sets Transit Point "alpha" listen_path to "partner-a"
    Then the admin API response status is 400
    And the admin API error response mentions "must start with '/'"

  Scenario: A listen_path on the outbound prefix itself is saved with a warning while the appliance is not strict
    When the operator sets Transit Point "alpha" listen_path to "/outbound"
    Then the admin API response status is 200
    And the admin API response carries a Warning header containing "is the gateway's own outbound prefix"

  Scenario: A listen_path outside the outbound prefix is saved with a warning while the appliance is not strict
    When the operator sets Transit Point "alpha" listen_path to "/partner-a-webhook"
    Then the admin API response status is 200
    And the admin API response carries a Warning header containing "listen_path '/partner-a-webhook', outside '/outbound'"

  Scenario: The surface routing settings name the prefixes a Transit Point may listen under
    When the operator reads the surface routing settings
    Then the admin API response status is 200
    And the surface routing settings offer "/outbound/example" as a Transit Point listen path prefix
