Feature: Protected resource metadata of an A2A Access Point
  An Access Point that declares the authorization server of its source
  authentication publishes RFC 9728 protected resource metadata, so a caller
  can find the authorization server from the Access Point URL alone. The
  metadata is not cached and never reaches the managed agent. An Access Point
  that does not declare publishes nothing.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: A declaring Access Point publishes its resource, authorization server and scopes
    Given the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke agent.read"
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 200
    And the response includes header "cache-control" with value "no-store"
    And the protected resource metadata names the surface Access Point URL as its resource
    And the protected resource metadata lists the authorization server of the surface
    And the protected resource metadata lists scopes "agent.invoke agent.read"
    And the protected resource metadata accepts bearer tokens in the Authorization header
    And managed agent "bravo" was not called

  Scenario: An Access Point whose authorization server is not published has no metadata
    Given the surface requires "JWT Bearer" source authentication
    And the surface requires scopes "agent.invoke"
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 404

  Scenario: An Access Point that requires no scope has no metadata
    Given the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 404

  Scenario: An Access Point without caller authentication has no metadata
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 404

  Scenario: A route that is not an Access Point has no metadata
    Given the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    When the caller fetches the protected resource metadata for route "/unknown"
    Then the response status is 404
