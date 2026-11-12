Feature: Pairing that waits for mediator access

  A mediator that admits only known DIDs refuses each new DID until its
  administrator adds it, so a pairing can stop after a gateway mints its DIDs
  and continue once they are admitted. The scenario mediator admits every DID,
  so each pause continues at once.

  Scenario: Two gateways pair through both pauses for mediator access and ping each other
    Given a fabric with 2 gateways that pause for mediator access when they pair
    When gateway 1 and gateway 2 ping each other
    Then gateway 2 waited for the mediator to admit its DIDs "connection_point, permanent"
    And gateway 1 waited for the mediator to admit its DIDs "temporary, permanent"
    And the ping from gateway 1 to gateway 2 succeeds
    And the ping from gateway 2 to gateway 1 succeeds

  Scenario: Two gateways paired in one call ping each other as before
    Given a fabric with 2 gateways
    When gateway 1 and gateway 2 ping each other
    Then the ping from gateway 1 to gateway 2 succeeds
    And the ping from gateway 2 to gateway 1 succeeds
