Feature: A Transit Point's listen_path is held to the prefixes the gateway serves
  A Transit Point answers at the route the gateway derives, under its outbound
  prefix, and at its own listen_path as well. A listen_path outside that prefix
  answers on the outbound listener alone, so an inbound listener sharing the
  outbound hostname never reaches it. The appliance either says so on the save
  or, with strict_outbound_listen_paths on, refuses it.

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

  Scenario: A listen_path outside the outbound prefix is saved while the appliance is not strict
    When the operator sets Transit Point "alpha" listen_path to "/partner-a-webhook"
    Then the admin API response status is 200
