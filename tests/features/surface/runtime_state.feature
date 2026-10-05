Feature: Surface runtime updates and removal
  An operator can change an existing surface through the admin API and the gateway
  applies the resulting runtime state without a manual reload.

  Background:
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target

  Scenario: An updated surface routes caller traffic to a different managed agent
    Given managed agent "charlie" is available
    And the operator updates surface "alpha" to target managed agent "charlie"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And managed agent "bravo" was not called
    And managed agent "charlie" received the forwarded request
    And managed agent "charlie" received the forwarded path "/foo"
    And the response body matches managed agent "charlie" response

  Scenario: A disabled surface does not serve caller traffic
    Given the operator has disabled the surface
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 404
    And managed agent "bravo" was not called

  Scenario: A disabled surface remains readable through the admin API
    Given the operator has disabled the surface
    When the operator reads the surface through the admin API
    Then the surface lookup response status is 200
    And the operator can still read the stored surface through the admin API
    And the stored surface keeps the existing surface id
    And the stored surface shows the surface status "disabled"

  Scenario: A deleted surface does not serve caller traffic
    Given the operator has deleted the surface
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 404
    And managed agent "bravo" was not called

  Scenario: A deleted surface is no longer readable through the admin API
    Given the operator has deleted the surface
    When the operator reads the surface through the admin API
    Then the operator can no longer read the surface through the admin API
