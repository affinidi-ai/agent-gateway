Feature: Gateways recover when the mediator loses their accounts

  Scenario: A gateway that only receives is reachable again after the mediator loses every account
    Given a fabric with 2 gateways
    And the mediator has lost every account it held
    When gateway 1 pings gateway 2
    Then the ping from gateway 1 to gateway 2 succeeds
