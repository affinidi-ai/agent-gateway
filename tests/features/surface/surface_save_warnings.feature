Feature: Surface save report
  Saving a surface through the admin API answers with the stored surface, the
  declaration outcome of each of its routes and warnings. A surface that
  authenticates callers but has no policy refusing a caller whose source
  authentication failed is warned that it fails open, unless its Access Point
  publishes the authorization server of its source authentication and so
  refuses such callers itself. The declarations of a stored surface can be read
  again at any time, against the strategies and policies as they are now, but
  not for a surface of another tenant. A client can send a save
  response back unchanged, while any other unknown field is still refused. A
  caller of a surface whose JWT verification strategy was deleted gets a
  generic server error that names no strategy.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication

  Scenario: Saving a surface that admits failed callers warns that it fails open
    Given the operator has loaded the surface through the admin API
    When the operator saves the loaded surface through the admin API
    Then the admin API response status is 200
    And the reported warnings include "fail_open_policy" about "access_point.inbound_policy" for the base route
    And the base route is reported with declaration outcome "strip" for reason "not_declared"

  Scenario: Saving a surface whose policy refuses failed callers gives no fail-open warning
    Given the surface has a policy denying callers whose source authentication failed
    And the operator has loaded the surface through the admin API
    When the operator saves the loaded surface through the admin API
    Then the admin API response status is 200
    And the reported warnings do not include "fail_open_policy"

  Scenario: Saving a surface whose Access Point declares its authorization server gives no fail-open warning
    Given the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    And the operator has loaded the surface through the admin API
    When the operator saves the loaded surface through the admin API
    Then the admin API response status is 200
    And the base route is reported to declare the surface Access Point URL
    And the reported warnings do not include "fail_open_policy"

  Scenario: Saving a surface that publishes its authorization server and accepts another audience is refused
    Given the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    And the operator has loaded the surface through the admin API
    When the operator saves the loaded surface through the admin API with JWT audience "https://other.example/agent"
    Then the admin API response status is 400
    And the admin API error response mentions "requires empty JWT Bearer audiences"

  Scenario: The declarations of a stored surface are reported on request
    When the operator reads the declarations of the surface
    Then the admin API response status is 200
    And the reported warnings include "fail_open_policy" about "access_point.inbound_policy" for the base route
    And the base route is reported with declaration outcome "strip" for reason "not_declared"

  Scenario: The declarations report a deleted JWT verification strategy
    Given the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    And the surface's JWT verification strategy has been deleted
    When the operator reads the declarations of the surface
    Then the admin API response status is 200
    And the base route is reported with declaration outcome "unservable" for reason "strategy_unavailable"

  Scenario: The declarations of another tenant's surface are not found
    Given the surface belongs to tenant "tenant-b"
    And the operator has issued an access token for tenant "tenant-a"
    When the holder of the access token for tenant "tenant-a" reads the declarations of the surface
    Then the admin API response status is 404
    And the admin API response reveals no declarations or warnings

  Scenario: A tenant reads the declarations of its own surface
    Given the surface belongs to tenant "tenant-b"
    And the operator has issued an access token for tenant "tenant-b"
    When the holder of the access token for tenant "tenant-b" reads the declarations of the surface
    Then the admin API response status is 200
    And the reported warnings include "fail_open_policy" about "access_point.inbound_policy" for the base route

  Scenario: A save response sent back unchanged is accepted
    Given the operator has loaded the surface through the admin API
    And the operator has saved the loaded surface through the admin API
    When the operator sends the save response back through the admin API
    Then the admin API response status is 200
    And the reported warnings include "fail_open_policy" about "access_point.inbound_policy" for the base route

  Scenario: An unknown field in a surface save is refused
    Given the operator has loaded the surface through the admin API
    When the operator saves the loaded surface through the admin API with unknown field "colour"
    Then the admin API response status is 422
    And the admin API error response mentions "colour"

  Scenario: A caller of a surface whose JWT verification strategy was deleted gets a generic server error
    Given the surface's JWT verification strategy has been deleted
    When the caller sends a request to the surface with a valid token
    Then the response status is 500
    And the response does not name the surface's JWT verification strategy
    And managed agent "bravo" was not called
