Feature: A2A settings through the admin API
  The admin API stores an A2A surface's A2A settings explicitly: the defaults
  when none are sent. It refuses settings that name no A2A version, and A2A
  settings on a surface that is not A2A or AP2.

  Scenario: An A2A surface created without A2A settings is stored with the defaults
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator creates a valid surface for route "/example"
    Then the admin API response status is 201
    And the created surface accepts A2A versions "0.3, 1.0" with envelope validation

  Scenario: An A2A surface that accepts no A2A version is refused
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator attempts to create an A2A surface for route "/example" that accepts no A2A versions
    Then the admin API response status is 400
    And the admin API error response mentions "accepted_versions must name at least one version"

  Scenario: A2A settings sent on a surface that is not A2A are refused
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator attempts to create an MCP surface for route "/example" that carries A2A settings
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.a2a requires an A2A or AP2 Access Point"
