Feature: Pairing that waits for mediator access

  A mediator that admits only known DIDs refuses each new DID until its
  administrator adds it, so a pairing can stop after a gateway mints its DIDs
  and continue once they are admitted. The scenario mediator admits every DID,
  so each pause continues at once. It has no way to refuse a DID, so the
  refusal (409 mediator_access_refused) is covered by unit tests.

  Scenario: Each gateway pauses for mediator access while they pair
    Given a fabric with 2 gateways that pause for mediator access when they pair
    When the gateways pair
    Then gateway 2 waited for the mediator to admit its DIDs "connection_point, permanent"
    And gateway 1 waited for the mediator to admit its DIDs "temporary, permanent"

  Scenario Outline: Two gateways paired through both pauses can ping in each direction
    Given a fabric with 2 gateways that pause for mediator access when they pair
    When gateway <from> pings gateway <to>
    Then the ping from gateway <from> to gateway <to> succeeds

    Examples:
      | from | to |
      | 1    | 2  |
      | 2    | 1  |

  Scenario Outline: Two gateways paired in one call can ping in each direction as before
    Given a fabric with 2 gateways
    When gateway <from> pings gateway <to>
    Then the ping from gateway <from> to gateway <to> succeeds

    Examples:
      | from | to |
      | 1    | 2  |
      | 2    | 1  |

  Scenario Outline: Gateways restarted while paused still pair and can ping in each direction
    Given a fabric with 2 gateways that pause for mediator access and restart while paused
    When gateway <from> pings gateway <to>
    Then the ping from gateway <from> to gateway <to> succeeds

    Examples:
      | from | to |
      | 1    | 2  |
      | 2    | 1  |
