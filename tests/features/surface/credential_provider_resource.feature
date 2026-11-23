Feature: The resource a credential provider is for
  A credential provider's resource is a canonical https URI, stored exactly as written. A bare
  host with no path, the form MCP servers publish, is accepted and kept without the trailing
  slash the URL parser would add. A resource the parser would rewrite in any other way is
  refused and not stored.

  Scenario: A credential provider for a bare-host resource is stored as written
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "provider-id-secret"
    And the appliance holds the secret "provider-password-secret"
    When the operator creates the credential provider "bare-host" for the resource "https://192.0.2.1" using secrets "provider-id-secret" and "provider-password-secret"
    Then the admin API response status is 201
    And the credential provider "bare-host" is stored for the resource "https://192.0.2.1"

  Scenario: A credential provider whose resource names the default port is refused and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "provider-id-secret"
    And the appliance holds the secret "provider-password-secret"
    When the operator creates the credential provider "default-port" for the resource "https://192.0.2.1:443" using secrets "provider-id-secret" and "provider-password-secret"
    Then the admin API response status is 400
    And the admin API error response mentions "resource must be a canonical HTTPS URI"
    And no credential provider "default-port" is stored
