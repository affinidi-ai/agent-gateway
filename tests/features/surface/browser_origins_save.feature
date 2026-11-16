Feature: Browser origins when saving a surface
  A save that leaves the browser origins out, as a Surface Builder save does,
  keeps them; an empty list clears them. An update is held to the same rules as
  a create.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the operator has created a surface for route "/example" that allows browser origins "https://chat.example.com"

  Scenario: A save that leaves the browser origins out keeps them
    When the operator saves the surface without its browser origins
    Then the admin API response status is 200
    And the stored surface allows browser origins "https://chat.example.com"

  Scenario: A save with new browser origins replaces them
    When the operator saves the surface with browser origins "https://App.Example.com, https://chat.example.com"
    Then the admin API response status is 200
    And the stored surface allows browser origins "https://app.example.com, https://chat.example.com"

  Scenario: An update with a browser origin that is not an exact https origin is refused
    When the operator saves the surface with browser origins "http://chat.example.com"
    Then the admin API response status is 400
    And the admin API error response mentions "browser_origins"
    And the stored surface allows browser origins "https://chat.example.com"

  Scenario: A patch with an empty list clears the browser origins
    When the operator patches the surface's browser origins to an empty list
    Then the stored surface allows no browser origins

  Scenario: A save that changes the browser origins is recorded in the VP Audit Log
    Given the VP Audit Log keeps every audit event
    When the operator saves the surface with browser origins "https://app.example.com"
    Then the admin API response status is 200
    And the VP Audit Log records that the operator changed the surface's browser origins from "https://chat.example.com" to "https://app.example.com"
