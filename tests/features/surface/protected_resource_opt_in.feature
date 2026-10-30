Feature: Authorization server discovery is the one opt-in for declaring an A2A Access Point
  An A2A Access Point declares the authorization server of its source authentication only when it
  publishes authorization server discovery (caller_authentication.protected_resource). The authorization
  server is the issuer of its JWT verification strategy and the scopes are its required scopes, so removing
  the required scopes keeps the gateway refusing failed callers. The resource is stored and checked when
  the surface is saved: it must be served by the Access Point's listener at its route, and the
  settings the gateway cannot honour while it is on are refused.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    And the operator has loaded the surface through the admin API

  Scenario: Saving a surface that publishes authorization server discovery declares its stored resource
    When the operator saves the loaded surface through the admin API
    Then the admin API response status is 200
    And the base route is reported to declare the surface Access Point URL
    And the reported warnings do not include "fail_open_policy"

  Scenario: Removing the required scopes keeps the Access Point refusing a caller without a token
    Given the operator has saved the loaded surface through the admin API without its required scopes
    When the caller sends a request to the surface without a token
    Then the response status is 401
    And the response challenges the caller to authorize without naming a scope
    And managed agent "bravo" was not called

  Scenario: Removing the required scopes keeps the metadata, without scopes
    Given the operator has saved the loaded surface through the admin API without its required scopes
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 200
    And the protected resource metadata lists the authorization server of the surface
    And the protected resource metadata lists no scopes

  Scenario: A resource on an origin the listener does not serve is refused
    When the operator saves the loaded surface through the admin API with its protected resource on origin "https://elsewhere.example"
    Then the admin API response status is 400
    And the admin API error response mentions "must be this endpoint's own public URL"

  Scenario: A resource whose path is not the Access Point route is refused
    When the operator saves the loaded surface through the admin API with its protected resource at path "/other"
    Then the admin API response status is 400
    And the admin API error response mentions "must be this endpoint's own public URL"

  Scenario: An authorization server other than the strategy's issuer is refused
    When the operator saves the loaded surface through the admin API with authorization server "https://other-idp.example/"
    Then the admin API response status is 400
    And the admin API error response mentions "authorization_servers must be exactly"

  Scenario: Forwarding the caller's token is refused while authorization server discovery is published
    When the operator saves the loaded surface through the admin API forwarding the caller's token
    Then the admin API response status is 400
    And the admin API error response mentions "forward_header"

  Scenario: Moving the route without a new resource is refused
    When the operator saves the loaded surface through the admin API with its route changed to "/moved" and its protected resource left out
    Then the admin API response status is 400
    And the admin API error response mentions "send protected_resource with a new resource, or null"
